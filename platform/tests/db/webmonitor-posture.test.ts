import { randomUUID } from "node:crypto";
import { sql } from "drizzle-orm";
import { describe, expect, it } from "vitest";
import { db, withOrg } from "@/server/db/client";
import { assets, users } from "@/server/db/schema";
import { createOrg } from "@/server/orgs/orgs";
import { loadPrincipal, type LoadedPrincipal } from "@/server/principal";
import { launchAssessment, runAssessment } from "@/server/assessments/assessments";
import type { CheckAdapter, CheckResult } from "@/server/assessments/checks";
import type { SessionInfo } from "@/server/auth/session";
import { createApiToken, resolveApiToken } from "@/server/tokens/tokens";
import { hostPosture } from "@/server/webmonitor/posture";
import { audit } from "@/server/audit/audit";

// Needs a migrated database reachable as the runtime role (ruya_app, NOBYPASSRLS). Skipped otherwise.
const run = process.env.DATABASE_URL ? describe : describe.skip;

async function newUser(): Promise<SessionInfo> {
  const email = `t-${randomUUID()}@ruya-tests.invalid`;
  const [u] = await db.insert(users).values({ email, displayName: "Test", idpIssuer: "test", idpSubject: email }).returning();
  return { idHash: "x", userId: u.id, email, displayName: "Test", activeOrgId: null, mfa: true, amr: ["mfa"], authTime: new Date() };
}

async function orgWithAsset() {
  const user = await newUser();
  const org = await createOrg(user, { name: `WMP ${randomUUID().slice(0, 8)}` });
  const ctx = (await loadPrincipal(user, org.id))!;
  const [asset] = await withOrg(org.id, (tx) => tx.insert(assets).values({
    orgId: org.id, host: `wmp-${randomUUID().slice(0, 8)}.example.com`, displayName: "shop", environment: "production", createdBy: user.userId, status: "verified",
  }).returning());
  return { user, org, ctx, asset };
}

const stub = (id: string, result: CheckResult): CheckAdapter => ({ id, checkKey: id.split("@")[0], run: async () => result });
const finding = (issueKey: string, severity: "high" | "medium", host: string) => ({
  issueKey, title: `${issueKey} title`, severity, location: `https://${host}/`, evidence: { secretish: "do-not-leak" }, remediation: "Fix it.",
});

async function scan(ctx: LoadedPrincipal, assetId: string, host: string) {
  const { assessment } = await launchAssessment(ctx, { assetId, idempotencyKey: `k-${randomUUID()}`, checkIds: ["dns.caa@1", "http.security_headers@1"] });
  const job = await withOrg(ctx.org.id, (tx) => tx.execute<{ payload: { assessmentId: string; token: string } }>(
    sql`SELECT payload FROM outbox WHERE business_key = ${`assessment:${assessment.id}:1`}`));
  const adapters = new Map([
    ["dns.caa@1", stub("dns.caa@1", { status: "ok", findings: [], evidence: {} })],
    ["http.security_headers@1", stub("http.security_headers@1", { status: "ok", findings: [finding("hsts_missing", "medium", host), finding("csp_missing", "high", host)], evidence: {} })],
  ]);
  await runAssessment(ctx.org.id, job.rows[0].payload, { adapters, minIntervalMs: 0 });
}

run("WebMonitor posture read model (database)", () => {
  it("returns counts, top titles and last assessment for tracked hosts only, through a read-only token", async () => {
    const { ctx, asset } = await orgWithAsset();
    await scan(ctx, asset.id, asset.host);
    const t = await createApiToken(ctx, { name: "webmonitor", scopes: ["assets:read", "findings:read"], days: 30 });
    const tokenCtx = (await resolveApiToken(t.token))!;

    const r = await hostPosture(tokenCtx, [asset.host, "not-tracked.example.com"]);
    expect(r.org.name).toBe(ctx.org.name);
    expect(r.hosts[1]).toEqual({ host: "not-tracked.example.com", tracked: false });
    const h = r.hosts[0];
    if (!h.tracked) throw new Error("expected tracked host");
    expect(h.asset).toMatchObject({ id: asset.id, name: "shop", status: "verified" });
    expect(h.findings).toMatchObject({ openTotal: 2, open: { high: 1, medium: 1, critical: 0 } });
    expect(h.findings!.top.map((f) => f.severity)).toEqual(["high", "medium"]);
    expect(h.lastAssessment).toMatchObject({ status: "completed" });
    expect(h.link).toContain(`/assets/${asset.id}`);
    // Evidence and remediation never leave through this endpoint.
    expect(JSON.stringify(r)).not.toContain("do-not-leak");
    expect(JSON.stringify(r)).not.toContain("Fix it.");
  });

  it("omits finding counts without findings:read and hides other orgs' assets", async () => {
    const a = await orgWithAsset();
    const b = await orgWithAsset();
    const t = await createApiToken(a.ctx, { name: "assets-only", scopes: ["assets:read"], days: 1 });
    const r = await hostPosture((await resolveApiToken(t.token))!, [a.asset.host, b.asset.host]);
    expect(r.hosts[0]).toMatchObject({ tracked: true, findings: null });
    expect(r.hosts[1]).toEqual({ host: b.asset.host, tracked: false });
  });

  it("lists recent edge changes for the site, newest first, and not another org's", async () => {
    const a = await orgWithAsset();
    const b = await orgWithAsset();
    const actor = { type: "user" as const, id: a.user.userId };
    await withOrg(a.org.id, async (tx) => {
      await audit(tx, { actor, action: "edge.applied", target: { type: "asset", id: a.asset.id }, details: { headers: ["X-Frame-Options: DENY"] } });
      await audit(tx, { actor, action: "edge.apply_failed", target: { type: "asset", id: a.asset.id }, outcome: "error", details: {} });
    });
    await withOrg(a.org.id, (tx) => audit(tx, { actor, action: "edge.undone", target: { type: "asset", id: a.asset.id }, details: {} }));
    await withOrg(b.org.id, (tx) => audit(tx, { actor: { type: "user", id: b.user.userId }, action: "edge.applied", target: { type: "asset", id: b.asset.id }, details: {} }));

    const t = await createApiToken(a.ctx, { name: "webmonitor", scopes: ["assets:read", "findings:read"], days: 1 });
    const r = await hostPosture((await resolveApiToken(t.token))!, [a.asset.host, b.asset.host]);
    const h = r.hosts[0];
    if (!h.tracked) throw new Error("expected tracked host");
    expect(h.changes.map((c) => c.kind)).toEqual(["edge_undone", "edge_applied"]);
    expect(h.changes[0].link).toContain(`/assets/${a.asset.id}`);
    expect(h.changes[1].at).toBeInstanceOf(Date);
    expect(r.hosts[1]).toEqual({ host: b.asset.host, tracked: false });
  });

  it("refuses a token that cannot view assets", async () => {
    const a = await orgWithAsset();
    const t = await createApiToken(a.ctx, { name: "reports", scopes: ["reports:generate"], days: 1 });
    await expect(hostPosture((await resolveApiToken(t.token))!, [a.asset.host])).rejects.toMatchObject({ status: 403 });
  });
});
