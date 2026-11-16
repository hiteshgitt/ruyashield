import { randomUUID } from "node:crypto";
import { and, eq, sql } from "drizzle-orm";
import { describe, expect, it } from "vitest";
import { db, withOrg } from "@/server/db/client";
import { assets, findings, fixproofRecords, outbox, users, verificationRuns } from "@/server/db/schema";
import { createOrg } from "@/server/orgs/orgs";
import { loadPrincipal, type LoadedPrincipal } from "@/server/principal";
import { launchAssessment, runAssessment } from "@/server/assessments/assessments";
import type { CheckAdapter, CheckResult } from "@/server/assessments/checks";
import type { SessionInfo } from "@/server/auth/session";
import { transition } from "@/server/findings/findings";
import {
  exportFixProof, getFixProof, listVerifications, requestVerification, runVerification, sweepVerifications, verifyFixProof, RUN_LEASE_MS,
} from "@/server/verification/verification";

// Needs a migrated database reachable as the runtime role (ruya_app, NOBYPASSRLS). Skipped otherwise.
// The background worker must be stopped while this runs, or it will race for the queued jobs.
const run = process.env.DATABASE_URL ? describe : describe.skip;

async function newUser(): Promise<SessionInfo> {
  const email = `t-${randomUUID()}@ruya-tests.invalid`;
  const [u] = await db.insert(users).values({ email, displayName: "Test", idpIssuer: "test", idpSubject: email }).returning();
  return { idHash: "x", userId: u.id, email, displayName: "Test", activeOrgId: null, mfa: true, amr: ["mfa"], authTime: new Date() };
}

const stub = (id: string, result: CheckResult): CheckAdapter => ({ id, checkKey: id.split("@")[0], run: async () => result });
const ok = (found: Extract<CheckResult, { status: "ok" }>["findings"] = [], evidence: Record<string, unknown> = {}): CheckResult => ({ status: "ok", findings: found, evidence });
const err: CheckResult = { status: "error", reason: "connect_failed", evidence: {} };
const hsts = (host: string) => ({
  issueKey: "hsts_missing", title: "HSTS header missing", severity: "medium" as const, location: `https://${host}/`, evidence: { missing: ["strict-transport-security"] }, remediation: "Send Strict-Transport-Security.",
});
const headers = (r: CheckResult) => ({ adapters: new Map([["http.security_headers@1", stub("http.security_headers@1", r)]]), minIntervalMs: 0 });

/** An org with one verified asset and one HSTS finding marked "fix applied". */
async function fixture() {
  const user = await newUser();
  const org = await createOrg(user, { name: `Verif ${randomUUID().slice(0, 8)}` });
  const ctx = (await loadPrincipal(user, org.id))!;
  const [asset] = await withOrg(org.id, (tx) => tx.insert(assets).values({
    orgId: org.id, host: `verif-${randomUUID().slice(0, 8)}.example.com`, displayName: "app", environment: "production",
    createdBy: user.userId, status: "verified",
  }).returning());
  await scan(ctx, asset.id, ok([hsts(asset.host)]));
  const [f] = await withOrg(org.id, (tx) => tx.select().from(findings).where(eq(findings.assetId, asset.id)));
  for (const k of ["triage", "confirm", "start_remediation", "mark_fix_applied"]) await transition(ctx, f.id, k);
  return { user, org, ctx, asset, finding: f };
}

async function scan(ctx: LoadedPrincipal, assetId: string, r: CheckResult) {
  const { assessment } = await launchAssessment(ctx, { assetId, idempotencyKey: `k-${randomUUID()}`, checkIds: ["dns.caa@1", "http.security_headers@1"] });
  const job = await withOrg(ctx.org.id, (tx) => tx.execute<{ payload: { assessmentId: string; token: string } }>(
    sql`SELECT payload FROM outbox WHERE business_key = ${`assessment:${assessment.id}:1`}`));
  const adapters = new Map([["dns.caa@1", stub("dns.caa@1", ok())], ["http.security_headers@1", stub("http.security_headers@1", r)]]);
  await runAssessment(ctx.org.id, job.rows[0].payload, { adapters, minIntervalMs: 0 });
}

const request = (ctx: LoadedPrincipal, findingId: string, key = `v-${randomUUID()}`) => requestVerification(ctx, findingId, { idempotencyKey: key });
const statusOf = async (orgId: string, id: string) => (await withOrg(orgId, (tx) => tx.select().from(findings).where(eq(findings.id, id))))[0].status;
const runRow = async (orgId: string, id: string) => (await withOrg(orgId, (tx) => tx.select().from(verificationRuns).where(eq(verificationRuns.id, id))))[0];
const proofs = (orgId: string, findingId: string) => withOrg(orgId, (tx) => tx.select().from(fixproofRecords).where(eq(fixproofRecords.findingId, findingId)).orderBy(fixproofRecords.version));
const audits = async (orgId: string, action: string) => (await withOrg(orgId, (tx) => tx.execute<{ outcome: string; reason: string | null }>(
  sql`SELECT outcome, reason FROM audit_events WHERE action = ${action}`))).rows;

run("verification and FixProof (database)", () => {
  it("resolves the finding only after a passing re-test, with a tamper-evident FixProof", async () => {
    const { ctx, finding, asset } = await fixture();
    const { run: r, replayed } = await request(ctx, finding.id);
    expect(replayed).toBe(false);
    expect(await runVerification(ctx.org.id, { runId: r.id }, headers(ok([], { finalUrl: `https://${asset.host}/` })))).toBe("completed:verified");

    expect(await statusOf(ctx.org.id, finding.id)).toBe("resolved_verified");
    const row = await runRow(ctx.org.id, r.id);
    expect(row).toMatchObject({ status: "completed", outcome: "verified" });
    expect(row.results).toEqual([expect.objectContaining({ checkId: "http.security_headers@1", status: "passed", evidenceSha256: expect.any(String) })]);
    const [fp] = await proofs(ctx.org.id, finding.id);
    expect(fp).toMatchObject({ status: "verified", version: 1, supersededAt: null });
    expect(verifyFixProof(fp, undefined).ok).toBe(true);
    expect((fp.content as { aiInvolvement: string }).aiInvolvement).toBe("none");

    const view = await getFixProof(ctx, fp.id);
    expect(view.integrity.ok).toBe(true);
    const json = await exportFixProof(ctx, fp.id, "json");
    const doc = JSON.parse(String(json.body));
    expect(doc).toMatchObject({ format: "ruyashield.fixproof/1", sha256: fp.sha256 });
    const pdf = await exportFixProof(ctx, fp.id, "pdf");
    expect(pdf.contentType).toBe("application/pdf");
    await expect(exportFixProof(ctx, fp.id, "html")).rejects.toMatchObject({ code: "invalid_format" });
  });

  it("reopens and notifies on a failed re-test", async () => {
    const { ctx, finding, asset } = await fixture();
    const { run: r } = await request(ctx, finding.id);
    expect(await runVerification(ctx.org.id, { runId: r.id }, headers(ok([hsts(asset.host)])))).toBe("completed:failed");
    expect(await statusOf(ctx.org.id, finding.id)).toBe("reopened");
    const n = await withOrg(ctx.org.id, (tx) => tx.select().from(outbox).where(and(eq(outbox.topic, "finding.notify"), sql`${outbox.payload}->>'kind' = 'verification_failed'`)));
    expect(n).toHaveLength(1);
    expect((await proofs(ctx.org.id, finding.id))[0].status).toBe("failed");
  });

  it("never treats an error or a different location as a pass", async () => {
    const a = await fixture();
    const r1 = (await request(a.ctx, a.finding.id)).run;
    expect(await runVerification(a.ctx.org.id, { runId: r1.id }, headers(err))).toBe("completed:unverified");
    expect(await statusOf(a.ctx.org.id, a.finding.id)).toBe("fix_pending_verification");

    // The site redirected elsewhere: the original location was not checked.
    const r2 = (await request(a.ctx, a.finding.id)).run;
    expect(await runVerification(a.ctx.org.id, { runId: r2.id }, headers(ok([], { finalUrl: `https://${a.asset.host}/login` })))).toBe("completed:unverified");
    expect((await runRow(a.ctx.org.id, r2.id)).results).toEqual([expect.objectContaining({ status: "inconclusive" })]);
    expect(await statusOf(a.ctx.org.id, a.finding.id)).toBe("fix_pending_verification");
    expect(await audits(a.ctx.org.id, "verification.inconclusive")).toHaveLength(2);

    // The newer record supersedes the older one; only one is active.
    const ps = await proofs(a.ctx.org.id, a.finding.id);
    expect(ps.map((p) => [p.version, p.supersededReason])).toEqual([[1, "newer_verification"], [2, null]]);
    expect(ps[1].prevSha256).toBe(ps[0].sha256);
    expect(verifyFixProof(ps[1], ps[0]).chain).toBe(true);
  });

  it("is idempotent per key and refuses duplicates, wrong states and kill switches", async () => {
    const { ctx, finding, asset } = await fixture();
    const key = `v-${randomUUID()}`;
    const first = await request(ctx, finding.id, key);
    const again = await request(ctx, finding.id, key);
    expect(again).toMatchObject({ replayed: true, run: { id: first.run.id } });
    await expect(request(ctx, finding.id)).rejects.toMatchObject({ status: 409, code: "verification_active" });
    expect(await withOrg(ctx.org.id, (tx) => tx.select().from(outbox).where(eq(outbox.topic, "verification.run")))).toHaveLength(1);

    // Kill switch engaged after the request: the run sends nothing and concludes nothing.
    await withOrg(ctx.org.id, (tx) => tx.update(assets).set({ killScanning: true }).where(eq(assets.id, asset.id)));
    let called = 0;
    const spy = { adapters: new Map([["http.security_headers@1", { ...stub("http.security_headers@1", ok()), run: async () => { called++; return ok(); } }]]), minIntervalMs: 0 };
    expect(await runVerification(ctx.org.id, { runId: first.run.id }, spy)).toBe("not_run:kill_switch_engaged");
    expect(called).toBe(0);
    expect(await runRow(ctx.org.id, first.run.id)).toMatchObject({ status: "not_run", outcome: null, fixproofId: null });
    expect(await statusOf(ctx.org.id, finding.id)).toBe("fix_pending_verification");
    await expect(request(ctx, finding.id)).rejects.toMatchObject({ status: 423, code: "kill_switch_engaged" });
    // A finished run is not run twice.
    expect(await runVerification(ctx.org.id, { runId: first.run.id }, spy)).toBe("not_queued:not_run");

    const other = await fixture();
    await withOrg(other.ctx.org.id, (tx) => tx.update(findings).set({ status: "triaged" }).where(eq(findings.id, other.finding.id)));
    await expect(request(other.ctx, other.finding.id)).rejects.toMatchObject({ status: 422, code: "verification_not_allowed" });
    expect(await audits(other.ctx.org.id, "verification.rejected")).toEqual([{ outcome: "denied", reason: "verification_not_allowed" }]);
  });

  it("isolates tenants", async () => {
    const a = await fixture();
    const b = await fixture();
    await expect(request(b.ctx, a.finding.id)).rejects.toMatchObject({ status: 404 });
    const { run: r } = await request(a.ctx, a.finding.id);
    await runVerification(a.ctx.org.id, { runId: r.id }, headers(ok([], { finalUrl: `https://${a.asset.host}/` })));
    const [fp] = await proofs(a.ctx.org.id, a.finding.id);
    await expect(getFixProof(b.ctx, fp.id)).rejects.toMatchObject({ status: 404 });
    await expect(exportFixProof(b.ctx, fp.id, "json")).rejects.toMatchObject({ status: 404 });
    expect(await withOrg(b.ctx.org.id, (tx) => tx.select().from(fixproofRecords).where(eq(fixproofRecords.id, fp.id)))).toHaveLength(0);
    // The worker cannot run another org's job by naming it under its own org.
    expect(await runVerification(b.ctx.org.id, { runId: r.id }, headers(ok()))).toBe("missing");
  });

  it("rejects edits and deletes of FixProof records, and refuses to export a tampered one", async () => {
    const { ctx, finding, asset } = await fixture();
    const { run: r } = await request(ctx, finding.id);
    await runVerification(ctx.org.id, { runId: r.id }, headers(ok([], { finalUrl: `https://${asset.host}/` })));
    const [fp] = await proofs(ctx.org.id, finding.id);
    await expect(withOrg(ctx.org.id, (tx) => tx.update(fixproofRecords).set({ status: "failed" }).where(eq(fixproofRecords.id, fp.id)))).rejects.toThrow();
    await expect(withOrg(ctx.org.id, (tx) => tx.delete(fixproofRecords).where(eq(fixproofRecords.id, fp.id)))).rejects.toThrow();

    // Simulate tampering below the app (trigger disabled by the owner role) and check it is caught.
    const owner = process.env.DATABASE_OWNER_URL;
    if (!owner) return;
    const pg = await import("pg");
    const c = new pg.default.Client({ connectionString: owner });
    await c.connect();
    try {
      await c.query("ALTER TABLE fixproof_records DISABLE TRIGGER fixproof_records_no_change");
      await c.query(`UPDATE fixproof_records SET content = jsonb_set(content, '{finding,severity}', '"low"') WHERE id = $1`, [fp.id]);
    } finally {
      await c.query("ALTER TABLE fixproof_records ENABLE TRIGGER fixproof_records_no_change");
      await c.end();
    }
    expect((await getFixProof(ctx, fp.id)).integrity).toMatchObject({ ok: false, hash: false });
    await expect(exportFixProof(ctx, fp.id, "json")).rejects.toMatchObject({ status: 409, code: "fixproof_integrity_failed" });
  });

  it("supersedes the active FixProof when the issue is detected again", async () => {
    const { ctx, finding, asset } = await fixture();
    const { run: r } = await request(ctx, finding.id);
    await runVerification(ctx.org.id, { runId: r.id }, headers(ok([], { finalUrl: `https://${asset.host}/` })));
    await scan(ctx, asset.id, ok([hsts(asset.host)]));
    expect(await statusOf(ctx.org.id, finding.id)).toBe("reopened");
    const [fp] = await proofs(ctx.org.id, finding.id);
    expect(fp.supersededReason).toBe("regression");
    const list = await listVerifications(ctx, finding.id);
    expect(list.active).toBeNull();
  });

  it("closes runs whose worker died as not_run", async () => {
    const { ctx, finding } = await fixture();
    const { run: r } = await request(ctx, finding.id);
    await withOrg(ctx.org.id, (tx) => tx.update(verificationRuns).set({ status: "running", startedAt: new Date(Date.now() - RUN_LEASE_MS - 60_000) }).where(eq(verificationRuns.id, r.id)));
    expect(await sweepVerifications()).toBeGreaterThanOrEqual(1);
    expect(await runRow(ctx.org.id, r.id)).toMatchObject({ status: "not_run", reason: "runner_lost", outcome: null });
    expect(await statusOf(ctx.org.id, finding.id)).toBe("fix_pending_verification");
    // A new re-test can then be requested.
    expect((await request(ctx, finding.id)).replayed).toBe(false);
  });
});
