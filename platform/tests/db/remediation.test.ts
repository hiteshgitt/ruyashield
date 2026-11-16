import { randomUUID } from "node:crypto";
import { eq } from "drizzle-orm";
import { describe, expect, it } from "vitest";
import { db, withOrg } from "@/server/db/client";
import { approvals, assets, findings, fixproofRecords, memberships, remediationPlans, users } from "@/server/db/schema";
import { createOrg } from "@/server/orgs/orgs";
import { loadPrincipal, type LoadedPrincipal } from "@/server/principal";
import { launchAssessment, runAssessment } from "@/server/assessments/assessments";
import type { CheckAdapter, CheckResult } from "@/server/assessments/checks";
import type { SessionInfo } from "@/server/auth/session";
import { transition } from "@/server/findings/findings";
import { createPlan, editPlan, submitPlan } from "@/server/remediation/plans";
import { decideApproval, markApplied, requestApproval } from "@/server/remediation/approvals";
import { requestVerification, runVerification } from "@/server/verification/verification";
import { sql } from "drizzle-orm";

// Needs a migrated database (see verification.test.ts). The worker must be stopped while this runs.
const run = process.env.DATABASE_URL ? describe : describe.skip;

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
const headers = (r: CheckResult) => ({ adapters: new Map([["http.security_headers@1", stub("http.security_headers@1", r)]]), minIntervalMs: 0 });
const code = (p: Promise<unknown>) => p.then(() => "ok", (e: { status?: number; code?: string }) => `${e.status} ${e.code}`);

async function member(ctx: LoadedPrincipal, role: "security_lead" | "viewer") {
  const u = await newUser();
  await withOrg(ctx.org.id, (tx) => tx.insert(memberships).values({ orgId: ctx.org.id, userId: u.userId, role, restricted: false }));
  return (await loadPrincipal(u, ctx.org.id))!;
}

/** An org admin, a security lead and one confirmed HSTS finding. */
async function fixture() {
  const user = await newUser();
  const org = await createOrg(user, { name: `Remed ${randomUUID().slice(0, 8)}` });
  const admin = (await loadPrincipal(user, org.id))!;
  const lead = await member(admin, "security_lead");
  const [asset] = await withOrg(org.id, (tx) => tx.insert(assets).values({
    orgId: org.id, host: `remed-${randomUUID().slice(0, 8)}.example.com`, displayName: "app", environment: "production", createdBy: user.userId, status: "verified",
  }).returning());
  const { assessment } = await launchAssessment(admin, { assetId: asset.id, idempotencyKey: `k-${randomUUID()}`, checkIds: ["http.security_headers@1"] });
  const job = await withOrg(org.id, (tx) => tx.execute<{ payload: { assessmentId: string; token: string } }>(sql`SELECT payload FROM outbox WHERE business_key = ${`assessment:${assessment.id}:1`}`));
  await runAssessment(org.id, job.rows[0].payload, headers(ok([hsts(asset.host)])));
  const [f] = await withOrg(org.id, (tx) => tx.select().from(findings).where(eq(findings.assetId, asset.id)));
  for (const k of ["triage", "confirm"]) await transition(admin, f.id, k);
  return { admin, lead, asset, finding: f };
}

/** Admin writes and submits a guided plan, then asks for approval. */
async function proposed(admin: LoadedPrincipal, findingId: string) {
  const { plan } = await createPlan(admin, findingId, { idempotencyKey: `p-${randomUUID()}`, type: "guided", title: "Enable HSTS", description: "Add Strict-Transport-Security at the load balancer." });
  await submitPlan(admin, plan.id);
  const { approval } = await requestApproval(admin, plan.id, { idempotencyKey: `a-${randomUUID()}` });
  return { plan, approval };
}
const planRow = async (orgId: string, id: string) => (await withOrg(orgId, (tx) => tx.select().from(remediationPlans).where(eq(remediationPlans.id, id))))[0];
const statusOf = async (orgId: string, id: string) => (await withOrg(orgId, (tx) => tx.select().from(findings).where(eq(findings.id, id))))[0].status;

run("remediation and approvals (database)", () => {
  it("completes a guided plan only after a passing re-test, and records it in FixProof", async () => {
    const { admin, lead, asset, finding } = await fixture();
    const { plan, approval } = await proposed(admin, finding.id);
    expect(approval).toMatchObject({ policy: "two_person", state: "pending", subjectSha256: plan.contentSha256 });

    // The requester cannot decide their own request; the security lead can.
    expect(await code(decideApproval(admin, approval.id, { decision: "approve", subjectSha256: plan.contentSha256 }))).toBe("403 self_approval");
    await decideApproval(lead, approval.id, { decision: "approve", subjectSha256: plan.contentSha256 });
    expect((await planRow(admin.org.id, plan.id)).state).toBe("approved");

    await markApplied(admin, plan.id, { note: "Header added on the LB." });
    expect((await planRow(admin.org.id, plan.id)).state).toBe("verifying");
    expect(await statusOf(admin.org.id, finding.id)).toBe("fix_pending_verification");

    const { run: r } = await requestVerification(admin, finding.id, { idempotencyKey: `v-${randomUUID()}` });
    expect(await runVerification(admin.org.id, { runId: r.id }, headers(ok([], { finalUrl: `https://${asset.host}/` })))).toBe("completed:verified");
    expect((await planRow(admin.org.id, plan.id)).state).toBe("completed");
    expect(await statusOf(admin.org.id, finding.id)).toBe("resolved_verified");
    const [fp] = await withOrg(admin.org.id, (tx) => tx.select().from(fixproofRecords).where(eq(fixproofRecords.findingId, finding.id)));
    const content = fp.content as { remediation: { recorded: { planId: string; approval: { approverId: string; selfApproved: boolean } }[] }; aiInvolvement: string };
    expect(content.remediation.recorded).toEqual([expect.objectContaining({ planId: plan.id, approval: expect.objectContaining({ approverId: lead.principal.userId, selfApproved: false }) })]);
    expect(content.aiInvolvement).toBe("none");
  });

  it("marks the plan failed, never completed, when the re-test does not pass", async () => {
    const { admin, lead, asset, finding } = await fixture();
    const { plan, approval } = await proposed(admin, finding.id);
    await decideApproval(lead, approval.id, { decision: "approve", subjectSha256: plan.contentSha256 });
    await markApplied(admin, plan.id, { note: "Header added on the LB." });
    const { run: r } = await requestVerification(admin, finding.id, { idempotencyKey: `v-${randomUUID()}` });
    expect(await runVerification(admin.org.id, { runId: r.id }, headers(ok([hsts(asset.host)])))).toBe("completed:failed");
    expect((await planRow(admin.org.id, plan.id)).state).toBe("remediation_failed");
    expect(await statusOf(admin.org.id, finding.id)).toBe("reopened");
  });

  it("binds an approval to the exact plan content", async () => {
    const { admin, lead, finding } = await fixture();
    const { plan, approval } = await proposed(admin, finding.id);
    expect(await code(decideApproval(lead, approval.id, { decision: "approve", subjectSha256: "0".repeat(64) }))).toBe("409 stale_review");
    // Applying needs an approval first; viewers cannot plan at all.
    expect(await code(markApplied(admin, plan.id, { note: "too early" }))).toBe("409 plan_state");
    const viewer = await member(admin, "viewer");
    expect(await code(createPlan(viewer, finding.id, { idempotencyKey: `p-${randomUUID()}`, type: "guided", title: "x plan", description: "y" }))).toBe("403 forbidden");
    // Editing an approved plan voids the approval: it goes back to proposed and cannot be applied.
    await decideApproval(lead, approval.id, { decision: "approve", subjectSha256: plan.contentSha256 });
    const approved = await planRow(admin.org.id, plan.id);
    await editPlan(admin, plan.id, { version: approved.version, title: "Something else" });
    expect((await planRow(admin.org.id, plan.id)).state).toBe("proposed");
    const [ap] = await withOrg(admin.org.id, (tx) => tx.select().from(approvals).where(eq(approvals.id, approval.id)));
    expect(ap).toMatchObject({ state: "invalidated", endReason: "plan_changed" });
    expect(await code(markApplied(admin, plan.id, { note: "applied anyway" }))).toBe("409 plan_state");
    // A rejection needs a reason.
    const fresh = await planRow(admin.org.id, plan.id);
    const { approval: again } = await requestApproval(admin, plan.id, { idempotencyKey: `a-${randomUUID()}` });
    expect(await code(decideApproval(lead, again.id, { decision: "reject", subjectSha256: fresh.contentSha256 }))).toBe("422 reason_required");
  });
});
