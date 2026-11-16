import { randomUUID } from "node:crypto";
import { eq, sql } from "drizzle-orm";
import { describe, expect, it } from "vitest";
import { db, withOrg } from "@/server/db/client";
import {
  assets, clientGroups, evidenceItems, findingOccurrences, findings, memberClientGroups, memberships, riskAcceptances, users,
} from "@/server/db/schema";
import { createOrg } from "@/server/orgs/orgs";
import { loadPrincipal, type LoadedPrincipal } from "@/server/principal";
import { launchAssessment, runAssessment } from "@/server/assessments/assessments";
import type { CheckAdapter, CheckResult } from "@/server/assessments/checks";
import type { SessionInfo } from "@/server/auth/session";
import type { Role } from "@/server/policy/matrix";
import { sha256 } from "@/server/findings/evidence";
import {
  addComment, assign, getEvidence, getFinding, getRawEvidence, listFindings, scheduleRiskExpiries, transition,
} from "@/server/findings/findings";

// Needs a migrated database reachable as the runtime role (ruya_app, NOBYPASSRLS). Skipped otherwise.
// The background worker must be stopped while this runs, or it will race for the queued jobs.
const run = process.env.DATABASE_URL ? describe : describe.skip;

async function newUser(): Promise<SessionInfo> {
  const email = `t-${randomUUID()}@ruya-tests.invalid`;
  const [u] = await db.insert(users).values({ email, displayName: "Test", idpIssuer: "test", idpSubject: email }).returning();
  return { idHash: "x", userId: u.id, email, displayName: "Test", activeOrgId: null, mfa: true, amr: ["mfa"], authTime: new Date() };
}

async function fixture() {
  const user = await newUser();
  const org = await createOrg(user, { name: `Find ${randomUUID().slice(0, 8)}` });
  const ctx = (await loadPrincipal(user, org.id))!;
  const [asset] = await withOrg(org.id, (tx) => tx.insert(assets).values({
    orgId: org.id, host: `find-${randomUUID().slice(0, 8)}.example.com`, displayName: "app", environment: "production",
    createdBy: user.userId, status: "verified",
  }).returning());
  return { user, org, ctx, asset };
}

/** Adds a member with the given role; restricted members see only the listed client groups. */
async function member(ctx: LoadedPrincipal, role: Exclude<Role, "service">, groups: string[] = []) {
  const u = await newUser();
  await withOrg(ctx.org.id, async (tx) => {
    await tx.insert(memberships).values({ orgId: ctx.org.id, userId: u.userId, role, restricted: groups.length > 0 });
    for (const g of groups) await tx.insert(memberClientGroups).values({ orgId: ctx.org.id, userId: u.userId, clientGroupId: g });
  });
  return { user: u, ctx: (await loadPrincipal(u, ctx.org.id))! };
}

const stub = (id: string, result: CheckResult): CheckAdapter => ({ id, checkKey: id.split("@")[0], run: async () => result });
const ok = (found: Extract<CheckResult, { status: "ok" }>["findings"] = []): CheckResult => ({ status: "ok", findings: found, evidence: {} });
const err: CheckResult = { status: "error", reason: "connect_failed", evidence: {} };

/** Runs one assessment where the headers check returns `headers`. */
async function scan(ctx: LoadedPrincipal, assetId: string, headers: CheckResult) {
  const { assessment } = await launchAssessment(ctx, { assetId, idempotencyKey: `k-${randomUUID()}`, checkIds: ["dns.caa@1", "http.security_headers@1"] });
  const job = await withOrg(ctx.org.id, (tx) => tx.execute<{ payload: { assessmentId: string; token: string } }>(
    sql`SELECT payload FROM outbox WHERE business_key = ${`assessment:${assessment.id}:1`}`));
  const adapters = new Map([["dns.caa@1", stub("dns.caa@1", ok())], ["http.security_headers@1", stub("http.security_headers@1", headers)]]);
  await runAssessment(ctx.org.id, job.rows[0].payload, { adapters, minIntervalMs: 0 });
  return assessment.id;
}

const hsts = (host: string, evidence: Record<string, unknown> = { missing: ["strict-transport-security"] }) => ({
  issueKey: "hsts_missing", title: "HSTS header missing", severity: "medium" as const, location: `https://${host}/`, evidence, remediation: "Send Strict-Transport-Security.",
});

const findingOf = async (orgId: string, assetId: string) =>
  (await withOrg(orgId, (tx) => tx.select().from(findings).where(eq(findings.assetId, assetId))));

const JUST = "Header is set by the CDN edge, verified manually.";
const inDays = (d: number) => new Date(Date.now() + d * 86_400_000).toISOString();

run("findings (database)", () => {
  it("deduplicates across runs into one finding with an occurrence per run", async () => {
    const { ctx, asset } = await fixture();
    for (let i = 0; i < 3; i++) await scan(ctx, asset.id, ok([hsts(asset.host, { missing: ["strict-transport-security"], daysRemaining: i })]));
    const fs = await findingOf(ctx.org.id, asset.id);
    expect(fs).toHaveLength(1);
    const occ = await withOrg(ctx.org.id, (tx) => tx.select().from(findingOccurrences).where(eq(findingOccurrences.findingId, fs[0].id)));
    expect(occ).toHaveLength(3);
    expect(occ.every((o) => o.evidenceId)).toBe(true);
    const page = await listFindings(ctx, { assetId: asset.id, status: "open" });
    expect(page.items.map((x: { id: string }) => x.id)).toEqual([fs[0].id]);
    expect(page.bySeverity).toEqual({ info: 0, low: 0, medium: 1, high: 0, critical: 0 });
    // Severity counts ignore the severity filter (the strip shows every severity) but keep the others.
    const high = await listFindings(ctx, { assetId: asset.id, status: "open", severity: "high" });
    expect(high.items).toEqual([]);
    expect(high.bySeverity.medium).toBe(1);
    expect((await listFindings(ctx, { assetId: asset.id, status: "false_positive" })).bySeverity.medium).toBe(0);
  });

  it("a failed check never counts as a miss; two clean runs make a new finding stale; it returns when seen again", async () => {
    const { ctx, asset } = await fixture();
    await scan(ctx, asset.id, ok([hsts(asset.host)]));
    await scan(ctx, asset.id, err);
    await scan(ctx, asset.id, err);
    expect((await findingOf(ctx.org.id, asset.id))[0]).toMatchObject({ status: "new", missedRuns: 0 });
    await scan(ctx, asset.id, ok());
    expect((await findingOf(ctx.org.id, asset.id))[0].status).toBe("new");
    await scan(ctx, asset.id, ok());
    expect((await findingOf(ctx.org.id, asset.id))[0].status).toBe("stale");
    await scan(ctx, asset.id, ok([hsts(asset.host)]));
    expect((await findingOf(ctx.org.id, asset.id))[0]).toMatchObject({ status: "new", missedRuns: 0 });
  });

  it("people cannot resolve a finding; marking a fix leaves it pending verification", async () => {
    const { ctx, asset } = await fixture();
    await scan(ctx, asset.id, ok([hsts(asset.host)]));
    const [f] = await findingOf(ctx.org.id, asset.id);
    await expect(transition(ctx, f.id, "resolve")).rejects.toMatchObject({ status: 422, code: "transition_not_allowed" });
    await expect(transition(ctx, f.id, "confirm")).rejects.toMatchObject({ status: 422, code: "transition_not_allowed" });
    for (const k of ["triage", "confirm", "start_remediation", "mark_fix_applied"]) await transition(ctx, f.id, k);
    const d = await getFinding(ctx, f.id);
    expect(d.finding.status).toBe("fix_pending_verification");
    expect(d.history.map((h: { toStatus: string }) => h.toStatus)).toEqual(expect.arrayContaining(["new", "triaged", "confirmed", "in_remediation", "fix_pending_verification"]));
    // Seeing it again before any verification reopens it.
    await scan(ctx, asset.id, ok([hsts(asset.host)]));
    expect((await findingOf(ctx.org.id, asset.id))[0].status).toBe("reopened");
  });

  it("false positives need a justification and the right role, and different evidence sends them back to triage", async () => {
    const { ctx, asset } = await fixture();
    await scan(ctx, asset.id, ok([hsts(asset.host)]));
    const [f] = await findingOf(ctx.org.id, asset.id);
    const dev = await member(ctx, "developer");
    await expect(transition(dev.ctx, f.id, "false_positive", { justification: JUST })).rejects.toMatchObject({ status: 403 });
    await expect(transition(ctx, f.id, "false_positive", { justification: "too short" })).rejects.toMatchObject({ status: 422 });
    await transition(ctx, f.id, "false_positive", { justification: JUST });

    await scan(ctx, asset.id, ok([hsts(asset.host, { missing: ["strict-transport-security"], daysRemaining: 1 })]));
    expect((await findingOf(ctx.org.id, asset.id))[0].status).toBe("false_positive"); // volatile field only
    await scan(ctx, asset.id, ok([hsts(asset.host, { missing: ["strict-transport-security"], maxAge: 0 })]));
    expect((await findingOf(ctx.org.id, asset.id))[0].status).toBe("triaged");
  });

  it("risk acceptance is limited to leads, expires within 365 days, and lapses back to triage", async () => {
    const { ctx, asset } = await fixture();
    await scan(ctx, asset.id, ok([hsts(asset.host)]));
    const [f] = await findingOf(ctx.org.id, asset.id);
    await transition(ctx, f.id, "triage");
    const analyst = await member(ctx, "analyst");
    const body = { justification: JUST, controls: "WAF rule 1042 strips downgrade attempts.", expiresAt: inDays(30) };
    await expect(transition(analyst.ctx, f.id, "accept_risk", body)).rejects.toMatchObject({ status: 403 });
    await expect(transition(ctx, f.id, "accept_risk", { ...body, expiresAt: inDays(366) })).rejects.toMatchObject({ status: 422, code: "invalid_expiry" });
    await expect(transition(ctx, f.id, "accept_risk", { ...body, controls: "" })).rejects.toMatchObject({ status: 422 });
    await transition(ctx, f.id, "accept_risk", body);
    expect((await findingOf(ctx.org.id, asset.id))[0].status).toBe("accepted_risk");

    await withOrg(ctx.org.id, (tx) => tx.update(riskAcceptances)
      .set({ createdAt: sql`now() - interval '2 days'`, expiresAt: sql`now() - interval '1 minute'` })
      .where(eq(riskAcceptances.findingId, f.id)));
    expect(await scheduleRiskExpiries()).toBeGreaterThanOrEqual(1);
    expect((await findingOf(ctx.org.id, asset.id))[0].status).toBe("triaged");
    const ra = await withOrg(ctx.org.id, (tx) => tx.select().from(riskAcceptances).where(eq(riskAcceptances.findingId, f.id)));
    expect(ra[0].expiredAt).not.toBeNull();
  });

  it("assigns only to people who can see the asset, and resolves mentions only inside the org", async () => {
    const { ctx, asset } = await fixture();
    const [g1] = await withOrg(ctx.org.id, (tx) => tx.insert(clientGroups).values({ orgId: ctx.org.id, name: "A" }).returning());
    const [g2] = await withOrg(ctx.org.id, (tx) => tx.insert(clientGroups).values({ orgId: ctx.org.id, name: "B" }).returning());
    await withOrg(ctx.org.id, (tx) => tx.update(assets).set({ clientGroupId: g1.id }).where(eq(assets.id, asset.id)));
    await scan(ctx, asset.id, ok([hsts(asset.host)]));
    const [f] = await findingOf(ctx.org.id, asset.id);

    const outsider = await member(ctx, "developer", [g2.id]);
    const insider = await member(ctx, "developer", [g1.id]);
    await expect(assign(ctx, f.id, { assigneeId: outsider.user.userId })).rejects.toMatchObject({ status: 422, code: "assignee_not_eligible" });
    await expect(getFinding(outsider.ctx, f.id)).rejects.toMatchObject({ status: 404 });
    expect(await assign(ctx, f.id, { assigneeId: insider.user.userId, dueAt: inDays(7) })).toMatchObject({ ownerId: insider.user.userId });

    const stranger = await fixture();
    const c = await addComment(ctx, f.id, `@${insider.user.email} please look; cc @${stranger.user.email} and @${outsider.user.email}`);
    expect(c.mentions).toEqual([insider.user.userId]);
  });

  it("serves evidence redacted and hash-checked, withholds tampered items, and audits raw downloads", async () => {
    const { ctx, asset } = await fixture();
    await scan(ctx, asset.id, ok([hsts(asset.host, { missing: ["strict-transport-security"], contact: "ops@example.com", cookie: "sid=secret" })]));
    const [f] = await findingOf(ctx.org.id, asset.id);
    const ev = await getEvidence(ctx, f.latestEvidenceId!);
    expect(ev.integrity).toBe("verified");
    expect(ev.body).not.toContain("sid=secret");
    expect(ev.body).not.toContain("ops@example.com");

    // Stored evidence is append-only.
    await expect(withOrg(ctx.org.id, (tx) => tx.update(evidenceItems).set({ body: "x" }).where(eq(evidenceItems.id, ev.id)))).rejects.toThrow();

    const raw = await getRawEvidence(ctx, ev.id);
    expect(raw.sha256).toBe(sha256(raw.body));
    const viewer = await member(ctx, "viewer");
    await expect(getRawEvidence(viewer.ctx, ev.id)).rejects.toMatchObject({ status: 403 });
    const audited = await withOrg(ctx.org.id, (tx) => tx.execute(sql`SELECT 1 FROM audit_events WHERE action = 'evidence.downloaded' AND target_id = ${ev.id}`));
    expect(audited.rows).toHaveLength(1);

    // An item whose hash does not match its body (simulating storage corruption) is never shown.
    const later = await scan(ctx, asset.id, ok());
    const [bad] = await withOrg(ctx.org.id, (tx) => tx.insert(evidenceItems).values({
      orgId: ctx.org.id, sha256: sha256("original"), contentType: "text/plain", sizeBytes: 8, body: "modified",
    }).returning());
    await withOrg(ctx.org.id, (tx) => tx.insert(findingOccurrences).values({ orgId: ctx.org.id, findingId: f.id, assessmentId: later, evidenceId: bad.id }));
    expect(await getEvidence(ctx, bad.id)).toMatchObject({ integrity: "failed", body: null });
    await expect(getRawEvidence(ctx, bad.id)).rejects.toMatchObject({ status: 409, code: "evidence_integrity_failed" });
    const failed = await withOrg(ctx.org.id, (tx) => tx.execute<{ outcome: string }>(sql`SELECT outcome FROM audit_events WHERE action = 'evidence.integrity_failed' AND target_id = ${bad.id}`));
    expect(failed.rows.length).toBeGreaterThanOrEqual(2);
  });

  it("isolates findings, evidence, comments and risk acceptances between orgs", async () => {
    const a = await fixture(), b = await fixture();
    await scan(a.ctx, a.asset.id, ok([hsts(a.asset.host)]));
    const [f] = await findingOf(a.org.id, a.asset.id);
    await addComment(a.ctx, f.id, "note");
    await expect(getFinding(b.ctx, f.id)).rejects.toMatchObject({ status: 404 });
    await expect(getEvidence(b.ctx, f.latestEvidenceId!)).rejects.toMatchObject({ status: 404 });
    for (const t of ["findings", "evidence_items", "finding_comments", "finding_status_history", "risk_acceptances"]) {
      const r = await withOrg(b.org.id, (tx) => tx.execute(sql`SELECT count(*)::int AS n FROM ${sql.identifier(t)} WHERE org_id = ${a.org.id}`));
      expect((r.rows[0] as { n: number }).n, t).toBe(0);
    }
    await expect(withOrg(b.org.id, (tx) => tx.insert(evidenceItems).values({
      orgId: a.org.id, sha256: sha256("x"), contentType: "text/plain", sizeBytes: 1, body: "x",
    }))).rejects.toThrow();
  });
});
