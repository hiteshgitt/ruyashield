import { randomUUID } from "node:crypto";
import { and, eq, sql } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { db, withOrg } from "@/server/db/client";
import { assets, consents, findings, orgs, outbox, referralEvents, users, verificationRuns, webmonitorReferrals } from "@/server/db/schema";
import { createOrg } from "@/server/orgs/orgs";
import { loadPrincipal, type LoadedPrincipal } from "@/server/principal";
import { launchAssessment, runAssessment } from "@/server/assessments/assessments";
import type { CheckAdapter, CheckResult } from "@/server/assessments/checks";
import type { SessionInfo } from "@/server/auth/session";
import { transition } from "@/server/findings/findings";
import { requestVerification, runVerification, scheduleRegressions } from "@/server/verification/verification";
import { setWebMonitorAdapter, signHandoff, type ResultSummary } from "@/server/webmonitor/adapter";
import {
  CONSENT_TEXT_VERSION, decideReferral, deleteReferral, getReferralByToken, publishReferralResult, receiveHandoff, referralFunnel,
} from "@/server/webmonitor/referrals";

// Needs a migrated database reachable as the runtime role (ruya_app, NOBYPASSRLS). Skipped otherwise.
// The background worker must be stopped while this runs, or it will race for the queued jobs.
const run = process.env.DATABASE_URL ? describe : describe.skip;
const SECRET = "test-handoff-secret-0123456789abcdef";

async function newUser(): Promise<SessionInfo> {
  const email = `t-${randomUUID()}@ruya-tests.invalid`;
  const [u] = await db.insert(users).values({ email, displayName: "Test", idpIssuer: "test", idpSubject: email }).returning();
  return { idHash: "x", userId: u.id, email, displayName: "Test", activeOrgId: null, mfa: true, amr: ["mfa"], authTime: new Date() };
}

const stub = (id: string, result: CheckResult): CheckAdapter => ({ id, checkKey: id.split("@")[0], run: async () => result });
const ok = (found: Extract<CheckResult, { status: "ok" }>["findings"] = [], evidence: Record<string, unknown> = {}): CheckResult => ({ status: "ok", findings: found, evidence });
const hsts = (host: string) => ({
  issueKey: "hsts_missing", title: "HSTS header missing", severity: "medium" as const, location: `https://${host}/`, evidence: { missing: ["strict-transport-security"] }, remediation: "Send Strict-Transport-Security.",
});

async function orgWithAsset() {
  const user = await newUser();
  const org = await createOrg(user, { name: `WM ${randomUUID().slice(0, 8)}` });
  const ctx = (await loadPrincipal(user, org.id))!;
  const [asset] = await withOrg(org.id, (tx) => tx.insert(assets).values({
    orgId: org.id, host: `wm-${randomUUID().slice(0, 8)}.example.com`, displayName: "app", environment: "production", createdBy: user.userId, status: "verified",
  }).returning());
  return { user, org, ctx, asset };
}

async function scan(ctx: LoadedPrincipal, assetId: string, r: CheckResult, referralId?: string) {
  const { assessment } = await launchAssessment(ctx, { assetId, idempotencyKey: `k-${randomUUID()}`, checkIds: ["dns.caa@1", "http.security_headers@1"], referralId });
  const job = await withOrg(ctx.org.id, (tx) => tx.execute<{ payload: { assessmentId: string; token: string } }>(
    sql`SELECT payload FROM outbox WHERE business_key = ${`assessment:${assessment.id}:1`}`));
  const adapters = new Map([["dns.caa@1", stub("dns.caa@1", ok())], ["http.security_headers@1", stub("http.security_headers@1", r)]]);
  await runAssessment(ctx.org.id, job.rows[0].payload, { adapters, minIntervalMs: 0 });
  return assessment;
}

function handoff(host: string, extra: Record<string, unknown> = {}, now = new Date()) {
  const body = JSON.stringify({
    nonce: `nonce-${randomUUID()}`, externalRef: `wm-${randomUUID().slice(0, 8)}`, signalType: "tls.expiry", host,
    observedAt: now.toISOString(), summary: "Certificate expires soon", ...extra,
  });
  const timestamp = String(Math.floor(now.getTime() / 1000));
  return { body, h: { timestamp, signature: signHandoff(timestamp, body, SECRET) } };
}

async function received(host: string, extra: Record<string, unknown> = {}) {
  const { body, h } = handoff(host, extra);
  const r = await receiveHandoff(h, body);
  expect(r.status).toBe(202);
  const b = r.body as { referralId: string; link: string };
  return { id: b.referralId, token: b.link.split("/referrals/")[1] };
}

const consent = (ctx: LoadedPrincipal, token: string, shareStatus = true) =>
  decideReferral(ctx, token, { decision: "consent", textVersion: CONSENT_TEXT_VERSION, acceptCharges: true, shareStatus });
const referral = async (orgId: string, id: string) => (await withOrg(orgId, (tx) => tx.select().from(webmonitorReferrals).where(eq(webmonitorReferrals.id, id))))[0];

let published: ResultSummary[] = [];
const prevSecret = process.env.WEBMONITOR_HANDOFF_SECRET;

run("WebMonitor referrals and regression schedule (database)", () => {
  beforeAll(() => {
    process.env.WEBMONITOR_HANDOFF_SECRET = SECRET;
  });
  afterAll(() => {
    process.env.WEBMONITOR_HANDOFF_SECRET = prevSecret;
    setWebMonitorAdapter(null);
  });

  it("stores a signed handoff as pending consent and starts nothing (TC-WMON-001, TC-WMON-003)", async () => {
    const { ctx, asset } = await orgWithAsset();
    const { body, h } = handoff(asset.host, { password: "hunter2", html: "<script>x</script>" });
    const r = await receiveHandoff(h, body);
    expect(r.status).toBe(202);
    const { referralId, link } = r.body as { referralId: string; link: string };
    const token = link.split("/referrals/")[1];

    const view = await getReferralByToken(ctx, token);
    expect(view).toMatchObject({ id: referralId, status: "pending_consent", host: asset.host, assetId: asset.id, assetVerified: true, summary: "Certificate expires soon" });
    // Unknown fields are dropped and nothing is queued for any org.
    expect(JSON.stringify(view)).not.toContain("hunter2");
    expect(await withOrg(ctx.org.id, (tx) => tx.select().from(outbox).where(eq(outbox.topic, "assessment.run")))).toHaveLength(0);
  });

  it("rejects bad signatures, stale timestamps and replays (TC-WMON-002)", async () => {
    const host = `wm-${randomUUID().slice(0, 8)}.example.com`;
    const { body, h } = handoff(host);
    expect(await receiveHandoff({ ...h, signature: signHandoff(h.timestamp, body, "y".repeat(40)) }, body)).toMatchObject({ status: 401, body: { error: { code: "bad_signature" } } });
    const stale = handoff(host, {}, new Date(Date.now() - 10 * 60_000));
    expect(await receiveHandoff(stale.h, stale.body)).toMatchObject({ status: 401, body: { error: { code: "stale_timestamp" } } });

    const first = await receiveHandoff(h, body);
    expect(first.status).toBe(202);
    // Identical retry is a no-op; the same nonce with a different payload is refused.
    expect(await receiveHandoff(h, body)).toMatchObject({ status: 200, body: { status: "duplicate", referralId: (first.body as { referralId: string }).referralId } });
    const tampered = JSON.stringify({ ...JSON.parse(body), summary: "changed" });
    expect(await receiveHandoff({ timestamp: h.timestamp, signature: signHandoff(h.timestamp, tampered, SECRET) }, tampered)).toMatchObject({ status: 409, body: { error: { code: "nonce_reused" } } });
    expect(await receiveHandoff(h, "{not json")).toMatchObject({ status: 401 });

    delete process.env.WEBMONITOR_HANDOFF_SECRET;
    expect(await receiveHandoff(h, body)).toMatchObject({ status: 503, body: { error: { code: "handoffs_disabled" } } });
    process.env.WEBMONITOR_HANDOFF_SECRET = SECRET;
  });

  it("records consent against the text version, once; decline and delete are honoured (TC-WMON-004)", async () => {
    const { ctx, asset } = await orgWithAsset();
    const a = await received(asset.host);
    await expect(decideReferral(ctx, a.token, { decision: "consent", textVersion: CONSENT_TEXT_VERSION, acceptCharges: false })).rejects.toMatchObject({ code: "charges_consent_required" });
    await expect(decideReferral(ctx, a.token, { decision: "consent", textVersion: "old", acceptCharges: true })).rejects.toMatchObject({ status: 409, code: "consent_text_changed" });
    expect(await consent(ctx, a.token)).toMatchObject({ referralId: a.id, status: "consented", assetId: asset.id });
    await expect(consent(ctx, a.token)).rejects.toMatchObject({ status: 410, code: "referral_unavailable" });
    const subjects = (await withOrg(ctx.org.id, (tx) => tx.select().from(consents).where(eq(consents.referralId, a.id)))).map((c) => [c.subject, c.textVersion]);
    expect(subjects.sort()).toEqual([["referral_assessment", CONSENT_TEXT_VERSION], ["referral_charges", CONSENT_TEXT_VERSION], ["referral_share_status", CONSENT_TEXT_VERSION]]);
    expect((await getReferralByToken(ctx, a.token)).summary).toBe("");

    const b = await received(asset.host);
    expect(await decideReferral(ctx, b.token, { decision: "decline", textVersion: CONSENT_TEXT_VERSION })).toMatchObject({ status: "declined" });
    const c = await received(asset.host);
    expect(await decideReferral(ctx, c.token, { decision: "delete", textVersion: CONSENT_TEXT_VERSION })).toMatchObject({ status: "deleted" });

    await deleteReferral(ctx, a.id);
    expect(await referral(ctx.org.id, a.id)).toMatchObject({ status: "deleted", summary: "", shareStatus: false });
    // Withdrawn consent: a queued link-back sends nothing.
    expect(await publishReferralResult(ctx.org.id, { referralId: a.id })).toBe("not_shared");
  });

  it("only launches under a consented referral for the same host (TC-WMON-005)", async () => {
    const { ctx, asset } = await orgWithAsset();
    // Unclaimed referrals are invisible to every org (RLS); a declined one is visible but not usable.
    const pending = await received(asset.host);
    await expect(scan(ctx, asset.id, ok(), pending.id)).rejects.toMatchObject({ code: "referral_invalid" });
    const declined = await received(asset.host);
    await decideReferral(ctx, declined.token, { decision: "decline", textVersion: CONSENT_TEXT_VERSION });
    await expect(scan(ctx, asset.id, ok(), declined.id)).rejects.toMatchObject({ code: "referral_not_consented" });
    const other = await received(`other-${randomUUID().slice(0, 8)}.example.com`);
    await consent(ctx, other.token);
    await expect(scan(ctx, asset.id, ok(), other.id)).rejects.toMatchObject({ code: "referral_host_mismatch" });
    expect(await withOrg(ctx.org.id, (tx) => tx.select().from(outbox).where(eq(outbox.topic, "assessment.run")))).toHaveLength(0);
  });

  it("links back only statuses and counts, and records every attempt (TC-WMON-006)", async () => {
    published = [];
    setWebMonitorAdapter({ verifyHandoff: () => ({ ok: true }), publishResult: async (s) => { published.push(s); return { sent: true }; } });
    try {
      const { ctx, asset } = await orgWithAsset();
      const r = await received(asset.host);
      await consent(ctx, r.token);
      const assessment = await scan(ctx, asset.id, ok([hsts(asset.host)]), r.id);
      expect((await referral(ctx.org.id, r.id)).assessmentId).toBe(assessment.id);
      const queued = await withOrg(ctx.org.id, (tx) => tx.select().from(outbox).where(eq(outbox.topic, "webmonitor.publish")));
      expect(queued).toHaveLength(1);

      expect(await publishReferralResult(ctx.org.id, queued[0].payload as { referralId: string })).toBe("published");
      expect(published).toHaveLength(1);
      expect(Object.keys(published[0]).sort()).toEqual(["assessmentStatus", "externalRef", "fixproofStatus", "link", "severityCounts"]);
      expect(published[0].severityCounts).toMatchObject({ medium: 1 });
      const sent = JSON.stringify(published[0]);
      for (const leak of [asset.host, "HSTS", "strict-transport-security", ctx.principal.userId]) expect(sent).not.toContain(leak);

      // With the provisional adapter nothing leaves; the attempt is still recorded as not sent.
      setWebMonitorAdapter(null);
      expect(await publishReferralResult(ctx.org.id, { referralId: r.id })).toBe("not_sent:no_contract");
      const ev = await withOrg(ctx.org.id, (tx) => tx.select().from(referralEvents).where(eq(referralEvents.referralId, r.id)));
      expect(ev.map((e) => [e.kind, e.reason]).sort()).toEqual([["result_not_sent", "no_contract"], ["result_published", null]]);
    } finally {
      setWebMonitorAdapter(null);
    }
  });

  it("reports the funnel as counts only (TC-WMON-007)", async () => {
    const since = new Date(Date.now() - 60 * 60_000);
    const f = await referralFunnel(since);
    expect(Object.keys(f).sort()).toEqual(["assessed", "consented", "converted", "received", "verified"]);
    expect(Object.values(f).every((n) => Number.isInteger(n) && n >= 0)).toBe(true);
    expect(f.received).toBeGreaterThanOrEqual(f.consented);
    expect(f.consented).toBeGreaterThanOrEqual(1);
    expect(f.assessed).toBeGreaterThanOrEqual(1);
  });

  it("schedules regression re-tests and reports lapsed authorization as not run (TC-FIXP-015)", async () => {
    const { ctx, asset } = await orgWithAsset();
    await scan(ctx, asset.id, ok([hsts(asset.host)]));
    const [f] = await withOrg(ctx.org.id, (tx) => tx.select().from(findings).where(eq(findings.assetId, asset.id)));
    for (const k of ["triage", "confirm", "start_remediation", "mark_fix_applied"]) await transition(ctx, f.id, k);
    const { run: v } = await requestVerification(ctx, f.id, { idempotencyKey: `v-${randomUUID()}` });
    const headers = (r: CheckResult) => ({ adapters: new Map([["http.security_headers@1", stub("http.security_headers@1", r)]]), minIntervalMs: 0 });
    expect(await runVerification(ctx.org.id, { runId: v.id }, headers(ok([], { finalUrl: `https://${asset.host}/` })))).toBe("completed:verified");

    const runsFor = () => withOrg(ctx.org.id, (tx) => tx.select().from(verificationRuns)
      .where(and(eq(verificationRuns.findingId, f.id), eq(verificationRuns.trigger, "scheduled_regression"))));
    // No schedule set: nothing is due.
    await scheduleRegressions(new Date(Date.now() + 3 * 86_400_000));
    expect(await runsFor()).toHaveLength(0);

    await withOrg(ctx.org.id, (tx) => tx.update(orgs).set({ regressionIntervalDays: 1 }).where(eq(orgs.id, ctx.org.id)));
    // Not yet due inside the interval.
    await scheduleRegressions(new Date(Date.now() + 3_600_000));
    expect(await runsFor()).toHaveLength(0);

    const later = new Date(Date.now() + 2 * 86_400_000);
    await scheduleRegressions(later);
    const [queued] = await runsFor();
    expect(queued).toMatchObject({ status: "queued" });
    // Same day again: the idempotency key keeps it to one run.
    await scheduleRegressions(later);
    expect(await runsFor()).toHaveLength(1);
    // A regression found by the re-test reopens the finding.
    expect(await runVerification(ctx.org.id, { runId: queued.id }, headers(ok([hsts(asset.host)])))).toBe("completed:failed");
    expect((await withOrg(ctx.org.id, (tx) => tx.select().from(findings).where(eq(findings.id, f.id))))[0].status).toBe("reopened");
  });

  it("never runs a regression re-test once authorization has lapsed (TC-FIXP-015)", async () => {
    const { ctx, asset } = await orgWithAsset();
    await scan(ctx, asset.id, ok([hsts(asset.host)]));
    const [f] = await withOrg(ctx.org.id, (tx) => tx.select().from(findings).where(eq(findings.assetId, asset.id)));
    for (const k of ["triage", "confirm", "start_remediation", "mark_fix_applied"]) await transition(ctx, f.id, k);
    const { run: v } = await requestVerification(ctx, f.id, { idempotencyKey: `v-${randomUUID()}` });
    await runVerification(ctx.org.id, { runId: v.id }, { adapters: new Map([["http.security_headers@1", stub("http.security_headers@1", ok([], { finalUrl: `https://${asset.host}/` }))]]), minIntervalMs: 0 });

    await withOrg(ctx.org.id, async (tx) => {
      await tx.update(orgs).set({ regressionIntervalDays: 1 }).where(eq(orgs.id, ctx.org.id));
      await tx.update(assets).set({ status: "lapsed" }).where(eq(assets.id, asset.id));
    });
    await scheduleRegressions(new Date(Date.now() + 2 * 86_400_000));
    const runs = await withOrg(ctx.org.id, (tx) => tx.select().from(verificationRuns).where(and(eq(verificationRuns.findingId, f.id), eq(verificationRuns.trigger, "scheduled_regression"))));
    expect(runs).toEqual([expect.objectContaining({ status: "not_run", reason: "authorization_lapsed", outcome: null })]);
    // Not a pass and not a failure: the finding keeps its state and the owner is told.
    expect((await withOrg(ctx.org.id, (tx) => tx.select().from(findings).where(eq(findings.id, f.id))))[0].status).toBe("resolved_verified");
    const n = await withOrg(ctx.org.id, (tx) => tx.select().from(outbox).where(and(eq(outbox.topic, "finding.notify"), sql`${outbox.payload}->>'kind' = 'regression_not_run'`)));
    expect(n).toHaveLength(1);
    expect(await withOrg(ctx.org.id, (tx) => tx.select().from(outbox).where(and(eq(outbox.topic, "verification.run"), sql`${outbox.payload}->>'runId' = ${runs[0].id}`)))).toHaveLength(0);
  });
});
