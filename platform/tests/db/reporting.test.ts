import { createHash, randomUUID } from "node:crypto";
import { sql } from "drizzle-orm";
import { Pool } from "pg";
import { afterAll, describe, expect, it } from "vitest";
import { db, withOrg } from "@/server/db/client";
import { users } from "@/server/db/schema";
import { createOrg } from "@/server/orgs/orgs";
import { loadPrincipal } from "@/server/principal";
import { createApiToken, resolveApiToken, revokeApiToken } from "@/server/tokens/tokens";
import { requestOrgDeletion, cancelOrgDeletion, setLegalHold } from "@/server/orgs/lifecycle";
import { generateReport, getReport } from "@/server/reports/reports";
import type { SessionInfo } from "@/server/auth/session";

// Needs the runtime role (DATABASE_URL) and, for time-travel checks, the owner role (DATABASE_OWNER_URL).
// Owner-side checks run inside a transaction that is always rolled back, so other orgs' data is never purged.
const run = process.env.DATABASE_URL && process.env.DATABASE_OWNER_URL ? describe : describe.skip;
const owner = process.env.DATABASE_OWNER_URL ? new Pool({ connectionString: process.env.DATABASE_OWNER_URL, max: 2 }) : null;
afterAll(async () => { await owner?.end(); });

async function newUser(): Promise<SessionInfo> {
  const email = `t-${randomUUID()}@ruya-tests.invalid`;
  const [u] = await db.insert(users).values({ email, displayName: "Test", idpIssuer: "test", idpSubject: email }).returning();
  return { idHash: "x", userId: u.id, email, displayName: "Test", activeOrgId: null, mfa: true, amr: ["mfa"], authTime: new Date() };
}
async function newOrg(tag: string) {
  const s = await newUser();
  const org = await createOrg(s, { name: `${tag} ${randomUUID().slice(0, 8)}` });
  return { s, ctx: (await loadPrincipal(s, org.id))! };
}
async function rolledBack<T>(fn: (q: (text: string, values?: unknown[]) => Promise<{ rows: Record<string, unknown>[] }>) => Promise<T>): Promise<T> {
  const c = await owner!.connect();
  try {
    await c.query("BEGIN");
    return await fn((text, values) => c.query(text, values));
  } finally {
    await c.query("ROLLBACK");
    c.release();
  }
}

run("reporting and hardening (database)", () => {
  it("purges an old audit prefix behind an anchor, keeps the chain verifiable and skips legal holds", async () => {
    const a = await newOrg("Ret");
    const h = await newOrg("Hold");
    await setLegalHold(h.ctx, true, "litigation test");
    await setLegalHold(a.ctx, true, "temporary");
    await setLegalHold(a.ctx, false, "released"); // a now has 3 events; the newest is always kept
    await rolledBack(async (q) => {
      const before = Number((await q("SELECT count(*) AS n FROM audit_events WHERE org_id = $1", [h.ctx.org.id])).rows[0].n);
      const out = (await q("SELECT * FROM retention_purge_at(now() + interval '4 years')")).rows;
      const mine = out.find((r) => r.purged_org === a.ctx.org.id);
      expect(Number(mine?.n_audit_events)).toBeGreaterThan(0);
      expect(out.some((r) => r.purged_org === h.ctx.org.id)).toBe(false);
      expect(Number((await q("SELECT count(*) AS n FROM audit_events WHERE org_id = $1", [h.ctx.org.id])).rows[0].n)).toBe(before);

      expect(Number((await q("SELECT count(*) AS n FROM audit_events WHERE org_id = $1", [a.ctx.org.id])).rows[0].n)).toBe(1);
      expect((await q("SELECT count(*) AS n FROM audit_chain_anchors WHERE org_id = $1", [a.ctx.org.id])).rows[0].n).toBe("1");
      await q("SELECT set_config('app.org_id', $1, true)", [a.ctx.org.id]);
      expect((await q("SELECT * FROM verify_audit_chain()")).rows[0]).toMatchObject({ checked: "1", first_broken_seq: null });
    });
  });

  it("does not let the runtime role time-travel retention, edit reports or delete audit events", async () => {
    const { ctx } = await newOrg("Imm");
    await expect(db.execute(sql`SELECT * FROM retention_purge_at(now() + interval '4 years')`)).rejects.toThrow();
    const r = await generateReport(ctx, { format: "csv" });
    const got = await getReport(ctx, r.id);
    expect(createHash("sha256").update(got.content).digest("hex")).toBe(r.sha256);
    await expect(withOrg(ctx.org.id, (tx) => tx.execute(sql`UPDATE reports SET sha256 = repeat('0', 64)`))).rejects.toThrow();
    await expect(withOrg(ctx.org.id, (tx) => tx.execute(sql`DELETE FROM reports`))).rejects.toThrow();
    await expect(withOrg(ctx.org.id, (tx) => tx.execute(sql`DELETE FROM audit_events`))).rejects.toThrow();
  });

  it("resolves API tokens only while unrevoked and unexpired, narrowed to their scopes", async () => {
    const { ctx } = await newOrg("Tok");
    const t = await createApiToken(ctx, { name: "ci", scopes: ["findings:read"], days: 30 });
    const p = await resolveApiToken(t.token);
    expect(p?.principal.tokenScopes).toEqual(["findings:read"]);
    expect(p?.principal.authTime.getTime()).toBe(0);
    expect(await resolveApiToken(t.token, {}, new Date(t.expiresAt.getTime() + 1000))).toBeNull();
    expect(await resolveApiToken("rs_" + "x".repeat(40))).toBeNull();
    expect(await resolveApiToken("not-a-token")).toBeNull();
    await expect(createApiToken(p!, { name: "escalate", scopes: ["findings:read"], days: 1 })).rejects.toMatchObject({ status: 403, code: "insufficient_scope" });
    await revokeApiToken(ctx, t.id);
    expect(await resolveApiToken(t.token)).toBeNull();
    await expect(revokeApiToken(ctx, "not-a-uuid")).rejects.toMatchObject({ status: 404 });
  });

  it("blocks deletion under legal hold, blocks a hold while deletion is pending, and finalizes after the grace period", async () => {
    const { ctx } = await newOrg("Del");
    await setLegalHold(ctx, true, "hold first");
    await expect(requestOrgDeletion(ctx, { confirmSlug: ctx.org.slug, reason: "closing" })).rejects.toMatchObject({ code: "legal_hold" });
    await setLegalHold(ctx, false, "released");
    await expect(requestOrgDeletion(ctx, { confirmSlug: "wrong", reason: "closing" })).rejects.toMatchObject({ code: "validation_failed" });
    await requestOrgDeletion(ctx, { confirmSlug: ctx.org.slug, reason: "closing" });
    await expect(setLegalHold(ctx, true, "too late")).rejects.toMatchObject({ code: "deletion_pending" });

    // Within the grace period nothing is finalized.
    const now = await db.execute<{ org_id: string }>(sql`SELECT org_id FROM finalize_org_deletions()`);
    expect(now.rows.map((r) => r.org_id)).not.toContain(ctx.org.id);

    await rolledBack(async (q) => {
      await q("UPDATE orgs SET deletion_requested_at = now() - interval '31 days' WHERE id = $1", [ctx.org.id]);
      const done = (await q("SELECT org_id FROM finalize_org_deletions()")).rows.map((r) => r.org_id);
      expect(done).toContain(ctx.org.id);
      expect((await q("SELECT org_id FROM user_orgs($1)", [ctx.principal.userId])).rows).toEqual([]);
    });

    await cancelOrgDeletion(ctx, "changed our mind");
    const after = await db.execute<{ org_id: string }>(sql`SELECT org_id FROM user_orgs(${ctx.principal.userId})`);
    expect(after.rows.map((r) => r.org_id)).toContain(ctx.org.id);
  });
});

describe("detailed reports (database)", () => {
  it("a technical report lists assets and findings, and keeps a snapshot of what it contained", async () => {
    if (!process.env.DATABASE_URL) return;
    const { randomUUID } = await import("node:crypto");
    const { db, withOrg } = await import("@/server/db/client");
    const { users, assets: assetsT, reports: reportsT } = await import("@/server/db/schema");
    const { createOrg } = await import("@/server/orgs/orgs");
    const { loadPrincipal } = await import("@/server/principal");
    const { generateReport, getReportInfo } = await import("@/server/reports/reports");
    const { launchAssessment, runAssessment } = await import("@/server/assessments/assessments");
    const { sql, eq } = await import("drizzle-orm");
    const email = `rep-${randomUUID()}@ruya-tests.invalid`;
    const [u] = await db.insert(users).values({ email, displayName: "R", idpIssuer: "test", idpSubject: email }).returning();
    const s = { idHash: "x", userId: u.id, email, displayName: "R", activeOrgId: null, mfa: true, amr: ["mfa"], authTime: new Date() };
    const org = await createOrg(s, { name: `Rep ${randomUUID().slice(0, 6)}` });
    const ctx = (await loadPrincipal(s, org.id))!;
    const [a] = await withOrg(org.id, (tx) => tx.insert(assetsT).values({ orgId: org.id, host: `rep-${randomUUID().slice(0, 6)}.example.com`, displayName: "Shop", environment: "production", createdBy: u.id, status: "verified" }).returning());
    const { assessment } = await launchAssessment(ctx, { assetId: a.id, idempotencyKey: `k-${randomUUID()}`, checkIds: ["http.security_headers@1"] });
    const job = await withOrg(org.id, (tx) => tx.execute<{ payload: { assessmentId: string; token: string } }>(sql`SELECT payload FROM outbox WHERE business_key = ${`assessment:${assessment.id}:1`}`));
    const found = [{ issueKey: "csp", title: "Missing Content-Security-Policy", severity: "high" as const, location: `https://${a.host}/`, evidence: {}, remediation: "Add a CSP header." },
      { issueKey: "ref", title: "Referrer-Policy missing", severity: "low" as const, location: `https://${a.host}/`, evidence: {}, remediation: "Add Referrer-Policy." }];
    await runAssessment(org.id, job.rows[0].payload, { adapters: new Map([["http.security_headers@1", { id: "http.security_headers@1", checkKey: "http.security_headers", run: async () => ({ status: "ok" as const, findings: found, evidence: {} }) }]]), minIntervalMs: 0 });

    const csv = await generateReport(ctx, { format: "csv", options: { preset: "technical", title: "Acme monthly" } });
    const row = (await withOrg(org.id, (tx) => tx.select().from(reportsT).where(eq(reportsT.id, csv.id))))[0];
    const text = Buffer.from(row.content).toString("utf8");
    expect(text).toContain('"asset"');
    expect(text).toContain("Missing Content-Security-Policy");
    expect(text).toContain("fix: Add a CSP header.");
    const info = await getReportInfo(ctx, csv.id);
    expect(info.params).toMatchObject({ title: "Acme monthly", preset: "technical", snapshot: { openTotal: 2, findingsTotal: 2 } });

    const exec = await generateReport(ctx, { format: "csv", options: { preset: "custom", sections: ["findings"], minSeverity: "high", includeFixes: false } });
    const execText = Buffer.from((await withOrg(org.id, (tx) => tx.select().from(reportsT).where(eq(reportsT.id, exec.id))))[0].content).toString("utf8");
    expect(execText).toContain("Missing Content-Security-Policy");
    expect(execText).not.toContain('"finding","Referrer-Policy missing"');
    expect(execText).not.toContain("fix: Add a CSP header.");

    const pdf = await generateReport(ctx, { format: "pdf", options: { preset: "client" } });
    const pdfRow = (await withOrg(org.id, (tx) => tx.select().from(reportsT).where(eq(reportsT.id, pdf.id))))[0];
    expect(Buffer.from(pdfRow.content).toString("latin1").startsWith("%PDF")).toBe(true);
  });
});
