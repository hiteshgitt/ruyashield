import { randomUUID } from "node:crypto";
import { and, eq, sql } from "drizzle-orm";
import { describe, expect, it } from "vitest";
import { db, withOrg } from "@/server/db/client";
import { assessments, assets, checkRuns, findingOccurrences, findings, outbox, usageRecords, users } from "@/server/db/schema";
import { createOrg } from "@/server/orgs/orgs";
import { loadPrincipal, type LoadedPrincipal } from "@/server/principal";
import {
  cancelAssessment, getAssessment, isCleanResult, launchAssessment, listAssessments, runAssessment, sweepAssessments,
} from "@/server/assessments/assessments";
import type { CheckAdapter, CheckResult } from "@/server/assessments/checks";
import type { SessionInfo } from "@/server/auth/session";

// Needs a migrated database reachable as the runtime role (ruya_app, NOBYPASSRLS). Skipped otherwise.
// The background worker must be stopped while this runs, or it will race for the queued jobs.
const run = process.env.DATABASE_URL ? describe : describe.skip;

async function newUser(): Promise<SessionInfo> {
  const email = `t-${randomUUID()}@ruya-tests.invalid`;
  const [u] = await db.insert(users).values({ email, displayName: "Test", idpIssuer: "test", idpSubject: email }).returning();
  return { idHash: "x", userId: u.id, email, displayName: "Test", activeOrgId: null, mfa: true, amr: ["mfa"], authTime: new Date() };
}

async function fixture(opts: { verified?: boolean } = {}) {
  const user = await newUser();
  const org = await createOrg(user, { name: `Scan ${randomUUID().slice(0, 8)}` });
  const ctx = (await loadPrincipal(user, org.id))!;
  const asset = await newAsset(ctx, opts.verified ?? true);
  return { user, org, ctx, asset };
}

async function newAsset(ctx: LoadedPrincipal, verified: boolean) {
  const [a] = await withOrg(ctx.org.id, (tx) => tx.insert(assets).values({
    orgId: ctx.org.id, host: `scan-${randomUUID().slice(0, 8)}.example.com`, displayName: "app", environment: "production",
    createdBy: ctx.principal.userId, ...(verified ? { status: "verified" as const } : {}),
  }).returning());
  return a;
}

const CHECKS = ["dns.caa@1", "http.security_headers@1"];
const launch = (ctx: LoadedPrincipal, assetId: string, extra: Record<string, unknown> = {}) =>
  launchAssessment(ctx, { assetId, idempotencyKey: `k-${randomUUID()}`, checkIds: CHECKS, ...extra });

async function jobPayload(orgId: string, id: string, attempt = 1) {
  const r = await withOrg(orgId, (tx) => tx.select({ payload: outbox.payload }).from(outbox).where(eq(outbox.businessKey, `assessment:${id}:${attempt}`)));
  return r[0]?.payload as { assessmentId: string; token?: string } | undefined;
}

const stub = (id: string, result: CheckResult | (() => Promise<CheckResult>)): CheckAdapter => ({
  id, checkKey: id.split("@")[0], run: async () => (typeof result === "function" ? result() : result),
});
const ok = (findings: Extract<CheckResult, { status: "ok" }>["findings"] = []): CheckResult => ({ status: "ok", findings, evidence: {} });
const err: CheckResult = { status: "error", reason: "connect_failed", evidence: {} };
const deps = (map: Record<string, CheckResult>) => ({ adapters: new Map(Object.entries(map).map(([k, v]) => [k, stub(k, v)])), minIntervalMs: 0 });

async function auditRows(orgId: string, action: string, targetId: string) {
  const r = await withOrg(orgId, (tx) => tx.execute<{ outcome: string; reason: string | null }>(
    sql`SELECT outcome, reason FROM audit_events WHERE action = ${action} AND target_id = ${targetId}`));
  return r.rows;
}

const status = async (orgId: string, id: string) =>
  (await withOrg(orgId, (tx) => tx.select().from(assessments).where(eq(assessments.id, id))))[0];

run("assessments (database)", () => {
  it("launches once per idempotency key and records usage", async () => {
    const { ctx, asset } = await fixture();
    const key = `k-${randomUUID()}`;
    const first = await launchAssessment(ctx, { assetId: asset.id, idempotencyKey: key, checkIds: CHECKS });
    expect(first.replayed).toBe(false);
    expect(first.assessment.status).toBe("queued");
    const again = await launchAssessment(ctx, { assetId: asset.id, idempotencyKey: key, checkIds: CHECKS });
    expect(again).toMatchObject({ replayed: true, assessment: { id: first.assessment.id } });

    const other = await newAsset(ctx, true);
    await expect(launchAssessment(ctx, { assetId: other.id, idempotencyKey: key, checkIds: CHECKS })).rejects.toMatchObject({ status: 409, code: "idempotency_conflict" });

    const usage = await withOrg(ctx.org.id, (tx) => tx.select().from(usageRecords).where(eq(usageRecords.sourceId, first.assessment.id)));
    expect(usage).toHaveLength(1);
    const runs = await withOrg(ctx.org.id, (tx) => tx.select().from(checkRuns).where(eq(checkRuns.assessmentId, first.assessment.id)));
    expect(runs.map((r) => r.checkId).sort()).toEqual(CHECKS);
    expect(runs.every((r) => r.status === "pending")).toBe(true);
    expect((await jobPayload(ctx.org.id, first.assessment.id))?.token).toEqual(expect.any(String));
  });

  it("refuses unverified assets, kill switches and a second active run", async () => {
    const { ctx, asset } = await fixture();
    const unverified = await newAsset(ctx, false);
    await expect(launch(ctx, unverified.id)).rejects.toMatchObject({ status: 403, code: "authorization_required" });

    const killed = { ...ctx, org: { ...ctx.org, killScanning: true } };
    await expect(launch(killed, asset.id)).rejects.toMatchObject({ status: 423, code: "kill_switch_engaged" });
    const denied = await withOrg(ctx.org.id, (tx) => tx.execute<{ outcome: string }>(
      sql`SELECT outcome FROM audit_events WHERE action = 'authz.denied' AND reason = 'kill_switch_engaged'`));
    expect(denied.rows.length).toBeGreaterThan(0);

    await expect(launch(ctx, asset.id, { checkIds: ["x.exploit_payloads@1"] })).rejects.toMatchObject({ code: "check_prohibited" });
    await launch(ctx, asset.id);
    await expect(launch(ctx, asset.id)).rejects.toMatchObject({ status: 409, code: "assessment_active" });
  });

  it("completes only when every check succeeds, and stores findings with occurrences", async () => {
    const { ctx, asset } = await fixture();
    const { assessment } = await launch(ctx, asset.id);
    const finding = { issueKey: "hsts_missing", title: "HSTS header missing", severity: "medium" as const, location: `https://${asset.host}/`, evidence: { header: null }, remediation: "Send Strict-Transport-Security." };
    const out = await runAssessment(ctx.org.id, (await jobPayload(ctx.org.id, assessment.id))!, deps({ "dns.caa@1": ok(), "http.security_headers@1": ok([finding]) }));
    expect(out).toBe("completed");

    const x = await status(ctx.org.id, assessment.id);
    expect(x.coverage).toMatchObject({ complete: true, ok: 2 });
    const f = await withOrg(ctx.org.id, (tx) => tx.select().from(findings).where(eq(findings.assetId, asset.id)));
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ issueKey: "hsts_missing", status: "new", lastAssessmentId: assessment.id });
    const occ = await withOrg(ctx.org.id, (tx) => tx.select().from(findingOccurrences).where(eq(findingOccurrences.findingId, f[0].id)));
    expect(occ).toHaveLength(1);
    expect(isCleanResult(x, 1)).toBe(false);
    expect(await auditRows(ctx.org.id, "assessment.finished", assessment.id)).toEqual([{ outcome: "success", reason: null }]);

    // A second run that sees the same issue updates the finding instead of duplicating it.
    const second = await launch(ctx, asset.id);
    await runAssessment(ctx.org.id, (await jobPayload(ctx.org.id, second.assessment.id))!, deps({ "dns.caa@1": ok(), "http.security_headers@1": ok([finding]) }));
    const f2 = await withOrg(ctx.org.id, (tx) => tx.select().from(findings).where(eq(findings.assetId, asset.id)));
    expect(f2).toHaveLength(1);
    expect(f2[0].lastAssessmentId).toBe(second.assessment.id);
  });

  it("never reports partial or failed runs as clean", async () => {
    const { ctx, asset } = await fixture();
    const a = await launch(ctx, asset.id);
    expect(await runAssessment(ctx.org.id, (await jobPayload(ctx.org.id, a.assessment.id))!, deps({ "dns.caa@1": ok(), "http.security_headers@1": err }))).toBe("completed_with_errors");
    const partial = await status(ctx.org.id, a.assessment.id);
    expect(partial).toMatchObject({ reason: "some_checks_failed", coverage: { complete: false, ok: 1 } });
    expect(isCleanResult(partial, 0)).toBe(false);

    const b = await launch(ctx, asset.id);
    expect(await runAssessment(ctx.org.id, (await jobPayload(ctx.org.id, b.assessment.id))!, deps({ "dns.caa@1": err, "http.security_headers@1": err }))).toBe("failed");
    const failed = await status(ctx.org.id, b.assessment.id);
    expect(failed).toMatchObject({ reason: "no_check_succeeded", coverage: { complete: false, ok: 0 } });
    expect(isCleanResult(failed, 0)).toBe(false);

    // A check with no adapter is an error, not a skip.
    const c = await launch(ctx, asset.id);
    expect(await runAssessment(ctx.org.id, (await jobPayload(ctx.org.id, c.assessment.id))!, deps({ "dns.caa@1": ok() }))).toBe("completed_with_errors");
  });

  it("refuses to run a job with a missing or forged token", async () => {
    const { ctx, asset } = await fixture();
    const a = await launch(ctx, asset.id);
    const ran: string[] = [];
    const spy = { adapters: new Map(CHECKS.map((k) => [k, stub(k, async () => { ran.push(k); return ok(); })])), minIntervalMs: 0 };
    expect(await runAssessment(ctx.org.id, { assessmentId: a.assessment.id }, spy)).toBe("job_token_malformed");
    expect(await status(ctx.org.id, a.assessment.id)).toMatchObject({ status: "failed", reason: "job_token_malformed" });

    const b = await launch(ctx, asset.id);
    const real = (await jobPayload(ctx.org.id, b.assessment.id))!;
    const forged = `${real.token!.split(".")[0]}.AAAA`;
    expect(await runAssessment(ctx.org.id, { assessmentId: b.assessment.id, token: forged }, spy)).toBe("job_token_bad_signature");

    // A token for one assessment cannot run another.
    const c = await launch(ctx, asset.id);
    expect(await runAssessment(ctx.org.id, { assessmentId: c.assessment.id, token: real.token }, spy)).toBe("job_token_mismatch");
    expect(ran).toEqual([]);
    expect(await auditRows(ctx.org.id, "assessment.failed", c.assessment.id)).toEqual([{ outcome: "error", reason: "job_token_mismatch" }]);
  });

  it("stops before the next check when the kill switch is engaged mid-run", async () => {
    const { ctx, asset } = await fixture();
    const { assessment } = await launch(ctx, asset.id);
    const ran: string[] = [];
    const adapters = new Map<string, CheckAdapter>([
      ["dns.caa@1", stub("dns.caa@1", async () => {
        ran.push("dns.caa@1");
        await withOrg(ctx.org.id, (tx) => tx.update(assets).set({ killScanning: true }).where(eq(assets.id, asset.id)));
        return ok();
      })],
      ["http.security_headers@1", stub("http.security_headers@1", async () => { ran.push("http"); return ok(); })],
    ]);
    expect(await runAssessment(ctx.org.id, (await jobPayload(ctx.org.id, assessment.id))!, { adapters, minIntervalMs: 0 })).toBe("cancelled");
    expect(ran).toEqual(["dns.caa@1"]);
    const runs = await withOrg(ctx.org.id, (tx) => tx.select().from(checkRuns).where(and(eq(checkRuns.assessmentId, assessment.id), eq(checkRuns.checkId, "http.security_headers@1"))));
    expect(runs[0]).toMatchObject({ status: "skipped", reason: "kill_switch_engaged" });
    expect((await status(ctx.org.id, assessment.id)).coverage).toMatchObject({ complete: false });
  });

  it("cancels queued runs directly and refuses to cancel finished ones", async () => {
    const { ctx, asset } = await fixture();
    const { assessment } = await launch(ctx, asset.id);
    const c = await cancelAssessment(ctx, assessment.id);
    expect(c).toMatchObject({ status: "cancelled", reason: "cancelled_by_user" });
    await expect(cancelAssessment(ctx, assessment.id)).rejects.toMatchObject({ status: 409, code: "not_cancellable" });
    // The queued job is then refused by the runner.
    expect(await runAssessment(ctx.org.id, (await jobPayload(ctx.org.id, assessment.id))!, deps({}))).toBe("not_queued:cancelled");
  });

  it("re-queues a run whose worker died with a freshly signed token, then times it out after 3 attempts", async () => {
    const { ctx, asset } = await fixture();
    const { assessment } = await launch(ctx, asset.id);
    const expire = () => withOrg(ctx.org.id, (tx) => tx.update(assessments)
      .set({ status: "running", leaseUntil: new Date(Date.now() - 1000), attempts: sql`${assessments.attempts} + 1` }).where(eq(assessments.id, assessment.id)));
    // The worker scrubs the original job's token once it has handled the message.
    await withOrg(ctx.org.id, (tx) => tx.update(outbox).set({ payload: { assessmentId: assessment.id, delivered: "lease_lost" } }).where(eq(outbox.businessKey, `assessment:${assessment.id}:1`)));

    await expire();
    await sweepAssessments();
    expect(await status(ctx.org.id, assessment.id)).toMatchObject({ status: "queued", reason: "worker_lease_expired" });
    const retry = await jobPayload(ctx.org.id, assessment.id, 2);
    expect(retry?.token).toEqual(expect.any(String));
    expect(await runAssessment(ctx.org.id, retry!, deps({ "dns.caa@1": ok(), "http.security_headers@1": ok() }))).toBe("completed");

    const second = await launch(ctx, asset.id);
    for (let i = 0; i < 3; i++) {
      await withOrg(ctx.org.id, (tx) => tx.update(assessments).set({ status: "running", leaseUntil: new Date(Date.now() - 1000), attempts: i + 1 }).where(eq(assessments.id, second.assessment.id)));
      await sweepAssessments();
    }
    expect(await status(ctx.org.id, second.assessment.id)).toMatchObject({ status: "timed_out", reason: "worker_lease_expired" });
    const runs = await withOrg(ctx.org.id, (tx) => tx.select().from(checkRuns).where(eq(checkRuns.assessmentId, second.assessment.id)));
    expect(runs.every((r) => r.status === "skipped")).toBe(true);
  });

  it("sweeps queued runs of a killed org and runs whose window ended", async () => {
    const { ctx, asset } = await fixture();
    const { assessment } = await launch(ctx, asset.id);
    await withOrg(ctx.org.id, (tx) => tx.update(assets).set({ killScanning: true }).where(eq(assets.id, asset.id)));
    await sweepAssessments();
    expect(await status(ctx.org.id, assessment.id)).toMatchObject({ status: "cancelled", reason: "kill_switch_engaged" });
    expect((await auditRows(ctx.org.id, "assessment.swept", assessment.id)).map((r) => r.reason)).toEqual(["kill_switch_engaged"]);
  });

  it("never shows one organization's assessments to another", async () => {
    const a = await fixture(), b = await fixture();
    const { assessment } = await launch(a.ctx, a.asset.id);
    expect((await listAssessments(a.ctx)).map((r) => r.assessment.id)).toContain(assessment.id);
    expect((await listAssessments(b.ctx)).map((r) => r.assessment.id)).not.toContain(assessment.id);
    await expect(getAssessment(b.ctx, assessment.id)).rejects.toMatchObject({ status: 404 });
    await expect(cancelAssessment(b.ctx, assessment.id)).rejects.toMatchObject({ status: 404 });
    // Even the runner cannot load it under the wrong tenant.
    const p = (await jobPayload(a.ctx.org.id, assessment.id))!;
    expect(await runAssessment(b.ctx.org.id, p, deps({}))).toBe("missing");
    const seen = await withOrg(b.ctx.org.id, (tx) => tx.select({ id: findings.id }).from(findings).where(eq(findings.assetId, a.asset.id)));
    expect(seen).toEqual([]);
  });
});
