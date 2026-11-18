import { randomUUID } from "node:crypto";
import { eq, sql } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { db, withOrg } from "@/server/db/client";
import { assets, auditEvents, edgeConnections, findings, memberships, users, verificationRuns } from "@/server/db/schema";
import { createOrg } from "@/server/orgs/orgs";
import { loadPrincipal, type LoadedPrincipal } from "@/server/principal";
import { launchAssessment, runAssessment } from "@/server/assessments/assessments";
import type { CheckAdapter, CheckResult } from "@/server/assessments/checks";
import type { SessionInfo } from "@/server/auth/session";
import { setCloudflareFetch } from "@/server/edge/cloudflare";
import { applyEdgeFixes, connectEdge, disconnectEdge, getEdge, undoEdgeFixes } from "@/server/edge/edge";

// Needs a migrated database (see verification.test.ts). Cloudflare is a fake that keeps the zone's rules.
const run = process.env.DATABASE_URL ? describe : describe.skip;
const ZONE = "b".repeat(32);
const TOKEN = "c".repeat(40);
let rules: { id: string; ref: string }[] | null = null;

async function fakeCf(url: string, init: RequestInit): Promise<Response> {
  const method = init.method ?? "GET";
  const p = url.replace(/^https:\/\/api\.cloudflare\.com\/client\/v4/, "");
  const ok = (result: unknown) => new Response(JSON.stringify({ success: true, errors: [], result }), { status: 200 });
  if (method === "GET" && p === `/zones/${ZONE}`) return ok({ name: "example.com" });
  if (p.endsWith("/entrypoint")) {
    if (method === "GET") return rules ? ok({ id: "rs", rules }) : new Response(JSON.stringify({ success: false }), { status: 404 });
    const body = JSON.parse(String(init.body));
    rules = body.rules.map((r: { ref: string }) => ({ ref: r.ref, id: "mine" }));
    return ok({ id: "rs", rules });
  }
  if (method === "DELETE") { rules = rules!.filter((r) => !p.endsWith(`/${r.id}`)); return ok({ id: "rs", rules }); }
  return new Response("{}", { status: 404 });
}

async function newUser(): Promise<SessionInfo> {
  const email = `t-${randomUUID()}@ruya-tests.invalid`;
  const [u] = await db.insert(users).values({ email, displayName: "Test", idpIssuer: "test", idpSubject: email }).returning();
  return { idHash: "x", userId: u.id, email, displayName: "Test", activeOrgId: null, mfa: true, amr: ["mfa"], authTime: new Date() };
}
const stub = (id: string, result: CheckResult): CheckAdapter => ({ id, checkKey: id.split("@")[0], run: async () => result });
const code = (p: Promise<unknown>) => p.then(() => "ok", (e: { status?: number; code?: string }) => `${e.status} ${e.code}`);

async function fixture() {
  const user = await newUser();
  const org = await createOrg(user, { name: `Edge ${randomUUID().slice(0, 8)}` });
  const admin = (await loadPrincipal(user, org.id))!;
  const host = `edge-${randomUUID().slice(0, 8)}.example.com`;
  const [asset] = await withOrg(org.id, (tx) => tx.insert(assets).values({
    orgId: org.id, host, displayName: "site", environment: "production", createdBy: user.userId, status: "verified",
  }).returning());
  const { assessment } = await launchAssessment(admin, { assetId: asset.id, idempotencyKey: `k-${randomUUID()}`, checkIds: ["http.security_headers@1"] });
  const job = await withOrg(org.id, (tx) => tx.execute<{ payload: { assessmentId: string; token: string } }>(sql`SELECT payload FROM outbox WHERE business_key = ${`assessment:${assessment.id}:1`}`));
  const found = [
    { issueKey: "missing_nosniff", title: "X-Content-Type-Options: nosniff missing", severity: "low" as const, location: `https://${host}/`, evidence: {}, remediation: "Send nosniff." },
    { issueKey: "missing_csp", title: "Content-Security-Policy header missing", severity: "medium" as const, location: `https://${host}/`, evidence: {}, remediation: "Define a CSP." },
  ];
  await runAssessment(org.id, job.rows[0].payload, { adapters: new Map([["http.security_headers@1", stub("http.security_headers@1", { status: "ok", findings: found, evidence: {} })]]), minIntervalMs: 0 });
  return { admin, asset };
}

async function viewer(ctx: LoadedPrincipal) {
  const u = await newUser();
  await withOrg(ctx.org.id, (tx) => tx.insert(memberships).values({ orgId: ctx.org.id, userId: u.userId, role: "viewer", restricted: false }));
  return (await loadPrincipal(u, ctx.org.id))!;
}

run("Cloudflare header fixes (database)", () => {
  beforeAll(() => { process.env.RUYA_SECRETS_KEY ??= "test-secrets-key-0123456789abcdef-0123456789"; setCloudflareFetch(fakeCf); });
  afterAll(() => setCloudflareFetch(null));

  it("connects, applies the chosen headers, re-tests what they fix, and undoes", async () => {
    rules = null;
    const { admin, asset } = await fixture();
    const before = await getEdge(admin, asset.id);
    expect(before.connection).toBeNull();
    expect(before.fixes.find((f) => f.key === "nosniff")!.findings).toHaveLength(1);
    expect(before.fixes.find((f) => f.key === "hsts")!.findings).toHaveLength(0);

    const v = await viewer(admin);
    expect(await code(connectEdge(v, { assetId: asset.id, zoneId: ZONE, token: TOKEN }))).toBe("403 forbidden");
    expect(await connectEdge(admin, { assetId: asset.id, zoneId: ZONE, token: TOKEN })).toMatchObject({ zoneName: "example.com" });
    const [row] = await withOrg(admin.org.id, (tx) => tx.select().from(edgeConnections).where(eq(edgeConnections.assetId, asset.id)));
    expect(row.tokenEnc).not.toContain(TOKEN);

    const r = await applyEdgeFixes(admin, { assetId: asset.id, fixes: ["nosniff"] });
    expect(r).toEqual({ fixes: ["nosniff"], retested: 1 });
    expect(rules).toHaveLength(1);
    const fs = await withOrg(admin.org.id, (tx) => tx.select().from(findings).where(eq(findings.assetId, asset.id)));
    expect(fs.find((f) => f.issueKey === "missing_nosniff")!.status).toBe("fix_pending_verification");
    expect(fs.find((f) => f.issueKey === "missing_csp")!.status).toBe("new"); // CSP is never applied for you
    const runs = await withOrg(admin.org.id, (tx) => tx.select().from(verificationRuns).where(eq(verificationRuns.findingId, fs.find((f) => f.issueKey === "missing_nosniff")!.id)));
    expect(runs).toHaveLength(1);
    expect((await getEdge(admin, asset.id)).connection!.appliedFixes).toEqual(["nosniff"]);

    expect(await undoEdgeFixes(admin, asset.id)).toEqual({ removed: true });
    expect(rules).toHaveLength(0);
    expect(await disconnectEdge(admin, asset.id)).toEqual({ ruleLeft: false });
    expect((await getEdge(admin, asset.id)).connection).toBeNull();

    const log = await withOrg(admin.org.id, (tx) => tx.select({ action: auditEvents.action, details: auditEvents.details }).from(auditEvents).where(eq(auditEvents.orgId, admin.org.id)));
    expect(log.map((x) => x.action)).toEqual(expect.arrayContaining(["edge.connected", "edge.applied", "edge.undone", "edge.disconnected"]));
    expect(JSON.stringify(log)).not.toContain(TOKEN);
  });

  it("needs a fresh MFA sign-in to apply", async () => {
    rules = null;
    const { admin, asset } = await fixture();
    await connectEdge(admin, { assetId: asset.id, zoneId: ZONE, token: TOKEN });
    const stale = { ...admin, principal: { ...admin.principal, authTime: new Date(Date.now() - 60 * 60_000) } };
    expect(await code(applyEdgeFixes(stale, { assetId: asset.id, fixes: ["nosniff"] }))).toBe("401 step_up_required");
    expect(rules).toBeNull();
  });
});
