import { randomUUID } from "node:crypto";
import { and, desc, eq, gt, inArray, ne, sql } from "drizzle-orm";
import { z } from "zod";
import { db, withOrg, isUuid, type Tx } from "../db/client";
import {
  approvals, assets, codeChanges, findings, memberships, remediationPlans, repositoryIntegrations, sandboxRuns,
  type ApprovalPolicy, type FindingStatus,
} from "../db/schema";
import { audit, type Actor } from "../audit/audit";
import { AppError, isAppError, notFound } from "../errors";
import { authorize, decide } from "../policy/policy";
import type { Role } from "../policy/matrix";
import { enqueue } from "../outbox/outbox";
import { notify, recordTransition } from "../findings/record";
import { systemTransitionAllowed } from "../findings/lifecycle";
import { integrationRef, loadPlan, rejected, res, setPlanState, userActor, type Ctx, type PlanRow } from "./plans";
import { BRANCH_PREFIX, changeUrl, deleteBranch, observeChange, openChange, resolveCommit } from "./repo";

// Approvals and approved changes (RS-REMED-004..006). An approval is bound to the exact plan content (its SHA-256):
// any edit invalidates it. Approving a patch plan only opens a ruyashield/… branch; nothing is ever merged by
// RuyaShield. A merge or a customer-applied fix only moves the finding to "fix pending verification": the fix is
// confirmed solely by a later verification run, never by the approval or the merge.

export const APPROVAL_TTL_MS = 7 * 24 * 60 * 60_000;
const APPROVER_ROLES = ["org_admin", "security_lead", "approver"] as const satisfies readonly Role[];
const CHANGES: Actor = { type: "service", id: "remediation-changes" };

type ApprovalRow = typeof approvals.$inferSelect;
type ChangeRow = typeof codeChanges.$inferSelect;

export const branchFor = (plan: Pick<PlanRow, "id" | "version">) => `${BRANCH_PREFIX}${plan.id}-v${plan.version}`;

/** Members who could decide (role-wise); MFA and step-up are checked when they actually decide. */
async function eligibleApprovers(tx: Tx, orgId: string, exclude?: string): Promise<string[]> {
  const rows = await tx.select({ userId: memberships.userId }).from(memberships)
    .where(and(eq(memberships.orgId, orgId), inArray(memberships.role, [...APPROVER_ROLES]), exclude ? ne(memberships.userId, exclude) : undefined))
    .limit(20);
  return rows.map((r) => r.userId);
}

/** Moves the finding along the remediation path where its lifecycle allows it; otherwise leaves it alone. */
async function findingToPendingVerification(tx: Tx, orgId: string, findingId: string, actor: Actor, details: Record<string, unknown>) {
  const f = (await tx.select().from(findings).where(eq(findings.id, findingId)).for("update"))[0];
  if (!f) return;
  let status: FindingStatus = f.status;
  if (systemTransitionAllowed(status, "in_remediation", "remediation_proposed")) {
    await recordTransition(tx, { orgId, findingId, from: status, to: "in_remediation", actor, reason: "remediation_proposed", details });
    status = "in_remediation";
  }
  if (systemTransitionAllowed(status, "fix_pending_verification", "remediation_applied")) {
    await recordTransition(tx, { orgId, findingId, from: status, to: "fix_pending_verification", actor, reason: "remediation_applied", details });
  }
}

// ---------- request ----------

const requestInput = z.object({
  idempotencyKey: z.string().min(8).max(100),
  note: z.string().trim().max(2000).optional(),
  untestedOverride: z.boolean().default(false),
});

export async function requestApproval(c: Ctx, planId: string, input: unknown) {
  const parsed = requestInput.safeParse(input ?? {});
  if (!parsed.success) throw new AppError(422, "invalid_request", parsed.error.issues.map((i) => i.message).join("; "));
  const d = parsed.data;
  const actor = userActor(c.principal);
  try {
    return await withOrg(c.org.id, async (tx) => {
      const { plan, f, a } = await loadPlan(tx, c, planId, true);
      await authorize(c.principal, "remediation.request_approval", res(f, a), c.org);
      const prior = (await tx.select().from(approvals).where(eq(approvals.idempotencyKey, d.idempotencyKey)))[0];
      if (prior) {
        if (prior.subjectId !== plan.id) throw new AppError(409, "idempotency_conflict", "This request key was already used for another plan.");
        return { approval: prior, replayed: true };
      }
      if (!["proposed", "test_passed"].includes(plan.state)) throw new AppError(409, "plan_state", `A plan that is ${plan.state.replace(/_/g, " ")} cannot be sent for approval.`);

      let sandboxRunId: string | null = null;
      if (plan.type === "patch") {
        const run = (await tx.select().from(sandboxRuns).where(and(eq(sandboxRuns.planId, plan.id), eq(sandboxRuns.contentSha256, plan.contentSha256)))
          .orderBy(desc(sandboxRuns.createdAt)).limit(1))[0];
        const passed = run?.status === "completed" && run.result === "test_passed";
        if (passed) sandboxRunId = run.id;
        else if (!d.untestedOverride) throw new AppError(422, "sandbox_not_passed", "This patch has not passed a sandbox test. Test it, or request approval as untested with a reason.");
        else if (!d.note || d.note.length < 10) throw new AppError(422, "override_reason_required", "Explain (10+ characters) why this patch should be approved without a passing test.");
      }

      const policy: ApprovalPolicy = c.org.approverMustDiffer === false ? "single_approver" : "two_person";
      const approvers = await eligibleApprovers(tx, c.org.id, policy === "two_person" ? c.principal.userId : undefined);
      if (!approvers.length) throw new AppError(409, "no_eligible_approver", "Nobody else in this organization can approve. Add an approver, or ask an admin to change the approval policy.");

      const id = randomUUID();
      const approval = (await tx.insert(approvals).values({
        id, orgId: c.org.id, subjectType: "remediation_plan", subjectId: plan.id, subjectSha256: plan.contentSha256, policy,
        untestedOverride: plan.type === "patch" && !sandboxRunId, sandboxRunId, requesterId: c.principal.userId, requestNote: d.note ?? null,
        expiresAt: new Date(Date.now() + APPROVAL_TTL_MS), idempotencyKey: d.idempotencyKey,
      }).returning())[0];
      await setPlanState(tx, plan, "awaiting_approval", actor, "approval_requested", { approvalId: id, policy, untestedOverride: approval.untestedOverride });
      await audit(tx, {
        actor, action: "approval.requested", target: { type: "approval", id }, requestId: c.principal.requestId,
        details: { planId: plan.id, findingId: f.id, subjectSha256: plan.contentSha256, policy, sandboxRunId, untestedOverride: approval.untestedOverride },
      });
      for (const u of approvers) if (u !== c.principal.userId) await notify(tx, { orgId: c.org.id, userId: u, findingId: f.id, kind: "approval_requested" });
      return { approval, replayed: false };
    });
  } catch (e) {
    await rejected(c, e, "approval.request_rejected", { type: "remediation_plan", id: planId }, ["plan_state", "sandbox_not_passed", "override_reason_required", "no_eligible_approver"]);
    throw e;
  }
}

// ---------- decide ----------

const decideInput = z.object({
  decision: z.enum(["approve", "reject"]),
  reason: z.string().trim().max(2000).optional(),
  /** The plan content the approver reviewed; a mismatch means they looked at an older version. */
  subjectSha256: z.string().regex(/^[0-9a-f]{64}$/),
});

async function loadApproval(tx: Tx, c: Ctx, approvalId: string, lock = false) {
  if (!isUuid(approvalId)) throw notFound();
  const q = tx.select().from(approvals).where(eq(approvals.id, approvalId));
  const ap = (lock ? await q.for("update") : await q)[0];
  if (!ap) throw notFound();
  const { plan, f, a } = await loadPlan(tx, c, ap.subjectId, lock);
  return { ap, plan, f, a };
}

/** Org admins may never approve their own request (A*); others only when the policy allows a single approver. */
const decider = (c: Ctx, ap: ApprovalRow) => (ap.policy === "two_person" || c.principal.role === "org_admin" ? ap.requesterId : undefined);

export async function decideApproval(c: Ctx, approvalId: string, input: unknown, session: { ref?: string | null } = {}) {
  const parsed = decideInput.safeParse(input ?? {});
  if (!parsed.success) throw new AppError(422, "invalid_request", parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; "));
  const d = parsed.data;
  const actor = userActor(c.principal);
  const now = new Date();
  try {
    const out = await withOrg(c.org.id, async (tx) => {
      const { ap, plan, f, a } = await loadApproval(tx, c, approvalId, true);
      await authorize(c.principal, "approval.decide", res(f, a, decider(c, ap)), c.org);
      if (ap.state !== "pending") throw new AppError(409, "approval_closed", `This approval is already ${ap.state}.`);
      if (ap.expiresAt <= now) return { stale: "expired" as const, ap, plan };
      if (plan.contentSha256 !== ap.subjectSha256 || plan.state !== "awaiting_approval") return { stale: "plan_changed" as const, ap, plan };
      if (d.subjectSha256 !== ap.subjectSha256) throw new AppError(409, "stale_review", "The plan changed since you opened it. Reload and review it again.");

      if (d.decision === "reject") {
        if (!d.reason || d.reason.length < 5) throw new AppError(422, "reason_required", "Say why (5+ characters) the plan is rejected.");
        const done = (await tx.update(approvals).set({
          state: "rejected", approverId: c.principal.userId, decisionReason: d.reason, authTime: c.principal.authTime, sessionRef: session.ref ?? null, decidedAt: now,
        }).where(eq(approvals.id, ap.id)).returning())[0];
        await setPlanState(tx, plan, "rejected", actor, "approval_rejected", { approvalId: ap.id });
        await audit(tx, { actor, action: "approval.rejected", target: { type: "approval", id: ap.id }, requestId: c.principal.requestId, reason: d.reason, details: { planId: plan.id, subjectSha256: ap.subjectSha256 } });
        await notify(tx, { orgId: c.org.id, userId: ap.requesterId, findingId: f.id, kind: "approval_decided" });
        return { approval: done, change: null };
      }

      const selfApproved = ap.requesterId === c.principal.userId;
      const done = (await tx.update(approvals).set({
        state: "approved", approverId: c.principal.userId, selfApproved, decisionReason: d.reason ?? null,
        authTime: c.principal.authTime, sessionRef: session.ref ?? null, decidedAt: now,
      }).where(eq(approvals.id, ap.id)).returning())[0];
      const approvedPlan = await setPlanState(tx, plan, "approved", actor, "approval_granted", { approvalId: ap.id, selfApproved });
      await audit(tx, {
        actor, action: "approval.approved", target: { type: "approval", id: ap.id }, requestId: c.principal.requestId, reason: d.reason ?? null,
        details: { planId: plan.id, findingId: f.id, subjectSha256: ap.subjectSha256, policy: ap.policy, selfApproved, untestedOverride: ap.untestedOverride, authTime: c.principal.authTime.toISOString() },
      });
      let change: ChangeRow | null = null;
      if (approvedPlan.type === "patch" && approvedPlan.integrationId && approvedPlan.diffSha256 && approvedPlan.baseCommit) {
        change = (await tx.insert(codeChanges).values({
          orgId: c.org.id, planId: plan.id, approvalId: ap.id, integrationId: approvedPlan.integrationId, diffSha256: approvedPlan.diffSha256,
          baseCommit: approvedPlan.baseCommit, branch: branchFor(approvedPlan),
        }).returning())[0];
        await enqueue(tx, { orgId: c.org.id, topic: "remediation.open_pr", businessKey: `open_pr:${change.id}:1`, payload: { changeId: change.id } });
        await audit(tx, { actor, action: "remediation.change_requested", target: { type: "code_change", id: change.id }, details: { planId: plan.id, approvalId: ap.id, branch: change.branch, diffSha256: change.diffSha256 } });
      }
      await notify(tx, { orgId: c.org.id, userId: ap.requesterId, findingId: f.id, kind: "approval_decided" });
      return { approval: done, change };
    });
    if ("stale" in out && out.stale && out.ap) {
      // Committed on its own, so the approval cannot be decided later against content nobody reviewed.
      await withOrg(c.org.id, async (tx) => {
        const ap = (await tx.select().from(approvals).where(and(eq(approvals.id, out.ap.id), eq(approvals.state, "pending"))).for("update"))[0];
        if (!ap) return;
        await tx.update(approvals).set({ state: out.stale === "expired" ? "expired" : "invalidated", endReason: out.stale }).where(eq(approvals.id, ap.id));
        await audit(tx, { actor, action: out.stale === "expired" ? "approval.expired" : "approval.invalidated", target: { type: "approval", id: ap.id }, reason: out.stale, details: { planId: ap.subjectId } });
        const plan = (await tx.select().from(remediationPlans).where(eq(remediationPlans.id, ap.subjectId)).for("update"))[0];
        if (plan?.state === "awaiting_approval") await setPlanState(tx, plan, "proposed", actor, `approval_${out.stale}`, { approvalId: ap.id });
      });
      throw new AppError(409, out.stale === "expired" ? "approval_expired" : "plan_changed",
        out.stale === "expired" ? "This approval request expired. Ask for a new one." : "The plan changed after approval was requested; this request is no longer valid.");
    }
    return out;
  } catch (e) {
    await rejected(c, e, "approval.decision_rejected", { type: "approval", id: approvalId }, ["approval_closed", "approval_expired", "plan_changed", "stale_review", "reason_required"]);
    throw e;
  }
}

// ---------- revoke / withdraw ----------

const revokeInput = z.object({ reason: z.string().trim().min(5).max(2000) });

/**
 * Withdraws a pending request (the requester, or anyone who may decide) or revokes an approval that has not been
 * used yet (deciders only). A change already opened cannot be revoked here; close the branch instead.
 */
export async function revokeApproval(c: Ctx, approvalId: string, input: unknown) {
  const parsed = revokeInput.safeParse(input ?? {});
  if (!parsed.success) throw new AppError(422, "reason_required", "Say why (5+ characters).");
  const actor = userActor(c.principal);
  return withOrg(c.org.id, async (tx) => {
    const { ap, plan, f, a } = await loadApproval(tx, c, approvalId, true);
    const isRequester = ap.requesterId === c.principal.userId;
    if (ap.state === "pending" && isRequester) {
      await authorize(c.principal, "remediation.request_approval", res(f, a), c.org);
    } else {
      await authorize(c.principal, "approval.decide", res(f, a), c.org);
    }
    if (ap.state !== "pending" && ap.state !== "approved") throw new AppError(409, "approval_closed", `This approval is already ${ap.state}.`);
    const now = new Date();
    const done = ap.state === "pending"
      ? (await tx.update(approvals).set({ state: "invalidated", endReason: "withdrawn" }).where(eq(approvals.id, ap.id)).returning())[0]
      : (await tx.update(approvals).set({ state: "revoked", revokedBy: c.principal.userId, revokedAt: now, endReason: parsed.data.reason }).where(eq(approvals.id, ap.id)).returning())[0];
    if (plan.state === "awaiting_approval" || plan.state === "approved") {
      await setPlanState(tx, plan, "proposed", actor, ap.state === "pending" ? "approval_withdrawn" : "approval_revoked", { approvalId: ap.id });
    }
    await audit(tx, {
      actor, action: ap.state === "pending" ? "approval.withdrawn" : "approval.revoked", target: { type: "approval", id: ap.id },
      reason: parsed.data.reason, requestId: c.principal.requestId, details: { planId: plan.id },
    });
    if (!isRequester) await notify(tx, { orgId: c.org.id, userId: ap.requesterId, findingId: f.id, kind: "approval_decided" });
    return { approval: done };
  });
}

// ---------- open the approved change (worker) ----------

/** Worker: re-checks the approval and opens a ruyashield/… branch with the approved patch. Never merges. */
export async function runOpenChange(orgId: string, payload: { changeId?: unknown }): Promise<string> {
  const id = typeof payload.changeId === "string" ? payload.changeId : "";
  if (!isUuid(id)) return "invalid_payload";

  const pre = await withOrg(orgId, async (tx) => {
    const ch = (await tx.select().from(codeChanges).where(eq(codeChanges.id, id)))[0];
    if (!ch) return { skip: "missing" };
    if (ch.state !== "pending") return { skip: `not_pending:${ch.state}` };
    const ap = (await tx.select().from(approvals).where(eq(approvals.id, ch.approvalId)))[0];
    const plan = (await tx.select().from(remediationPlans).where(eq(remediationPlans.id, ch.planId)))[0];
    const i = (await tx.select().from(repositoryIntegrations).where(eq(repositoryIntegrations.id, ch.integrationId)))[0];
    const why = !ap || ap.state !== "approved" || ap.expiresAt <= new Date() ? "approval_not_valid"
      : !plan || plan.state !== "approved" || plan.contentSha256 !== ap.subjectSha256 || plan.diffSha256 !== ch.diffSha256 || !plan.diff ? "plan_changed"
      : !i || i.status !== "active" ? "integration_unavailable" : null;
    if (why) {
      await tx.update(codeChanges).set({ state: "failed", error: why }).where(eq(codeChanges.id, id));
      await audit(tx, { actor: CHANGES, action: "remediation.change_failed", target: { type: "code_change", id }, outcome: "denied", reason: why, details: { planId: ch.planId } });
      return { skip: `failed:${why}` };
    }
    return { ch, plan: plan!, i: i!, ap: ap! };
  });
  if ("skip" in pre) return pre.skip ?? "skipped";
  const { ch, plan, i, ap } = pre;
  const ref = integrationRef(i);

  let opened: { headSha: string; url: string };
  try {
    opened = await openChange(ref, {
      base: ch.baseCommit, diff: plan.diff!, branch: ch.branch,
      message: `RuyaShield remediation: ${plan.title}\n\nPlan ${plan.id} v${plan.version}, approval ${ap.id}.\nThis change was not merged by RuyaShield; review and merge it yourself.\n`,
    });
  } catch (e) {
    // At-least-once delivery: a previous attempt may have created the branch before crashing. The branch name
    // carries the plan id and version and only this service creates ruyashield/… branches, so adopt it.
    const existing = await resolveCommit(ref, ch.branch).catch(() => null);
    if (!existing) {
      const error = isAppError(e) ? e.code : "open_failed";
      await withOrg(orgId, async (tx) => {
        await tx.update(codeChanges).set({ state: "failed", error }).where(and(eq(codeChanges.id, id), eq(codeChanges.state, "pending")));
        await audit(tx, { actor: CHANGES, action: "remediation.change_failed", target: { type: "code_change", id }, outcome: "error", reason: error, details: { planId: plan.id } });
      });
      return `failed:${error}`;
    }
    opened = { headSha: existing, url: changeUrl(ref, ch.branch) };
  }

  const result = await withOrg(orgId, async (tx) => {
    const cur = (await tx.select().from(codeChanges).where(and(eq(codeChanges.id, id), eq(codeChanges.state, "pending"))).for("update"))[0];
    if (!cur) return "lease_lost";
    const a = (await tx.select().from(approvals).where(eq(approvals.id, ap.id)).for("update"))[0];
    const p = (await tx.select().from(remediationPlans).where(eq(remediationPlans.id, plan.id)).for("update"))[0];
    if (!a || a.state !== "approved" || !p || p.state !== "approved" || p.contentSha256 !== a.subjectSha256) {
      await tx.update(codeChanges).set({ state: "failed", error: "approval_ended", headSha: opened.headSha }).where(eq(codeChanges.id, id));
      await audit(tx, { actor: CHANGES, action: "remediation.change_failed", target: { type: "code_change", id }, outcome: "denied", reason: "approval_ended", details: { planId: plan.id, branch: ch.branch } });
      return "revoked";
    }
    await tx.update(approvals).set({ state: "consumed", consumedAt: new Date() }).where(eq(approvals.id, a.id));
    await tx.update(codeChanges).set({ state: "open", headSha: opened.headSha, prUrl: opened.url, observedAt: new Date() }).where(eq(codeChanges.id, id));
    await setPlanState(tx, p, "change_submitted", CHANGES, "change_opened", { codeChangeId: id, branch: ch.branch, headSha: opened.headSha });
    await audit(tx, { actor: CHANGES, action: "remediation.change_opened", target: { type: "code_change", id }, details: { planId: plan.id, approvalId: a.id, branch: ch.branch, headSha: opened.headSha, url: opened.url, merged: false } });
    return "opened";
  });
  if (result === "revoked") {
    // The approval ended while the branch was being created: take the branch back down.
    await deleteBranch(ref, ch.branch, opened.headSha).catch(() => undefined);
  }
  return result;
}

// ---------- guided plans: the customer applied it ----------

const appliedInput = z.object({ note: z.string().trim().min(5).max(2000) });

export async function markApplied(c: Ctx, planId: string, input: unknown) {
  const parsed = appliedInput.safeParse(input ?? {});
  if (!parsed.success) throw new AppError(422, "note_required", "Describe (5+ characters) what was changed and where.");
  const actor = userActor(c.principal);
  return withOrg(c.org.id, async (tx) => {
    const { plan, f, a } = await loadPlan(tx, c, planId, true);
    await authorize(c.principal, "remediation.mark_applied", res(f, a), c.org);
    if (plan.type !== "guided") throw new AppError(422, "not_guided", "Patch plans are applied by merging the opened change; RuyaShield observes the merge.");
    if (plan.state !== "approved") throw new AppError(409, "plan_state", "Only an approved plan can be marked as applied.");
    const ap = (await tx.select().from(approvals).where(and(eq(approvals.subjectId, plan.id), eq(approvals.state, "approved"), gt(approvals.expiresAt, new Date()))).for("update"))[0];
    if (!ap || ap.subjectSha256 !== plan.contentSha256) throw new AppError(409, "approval_not_valid", "The approval for this plan is no longer valid.");
    await tx.update(approvals).set({ state: "consumed", consumedAt: new Date() }).where(eq(approvals.id, ap.id));
    const applied = await setPlanState(tx, plan, "applied_by_customer", actor, "applied_by_customer", { approvalId: ap.id, note: parsed.data.note });
    await setPlanState(tx, applied, "verifying", actor, "awaiting_verification");
    await findingToPendingVerification(tx, c.org.id, f.id, actor, { planId: plan.id, approvalId: ap.id });
    await audit(tx, { actor, action: "remediation.marked_applied", target: { type: "remediation_plan", id: plan.id }, reason: parsed.data.note, requestId: c.principal.requestId, details: { findingId: f.id, approvalId: ap.id, verified: false } });
    return { plan: applied };
  });
}

// ---------- sweeps ----------

export async function sweepExpiredApprovals(now = new Date()): Promise<number> {
  const rows = await db.execute<{ id: string; org_id: string }>(sql`SELECT * FROM expired_approvals(${now.toISOString()}::timestamptz)`);
  let n = 0;
  for (const row of rows.rows) {
    n += await withOrg(row.org_id, async (tx) => {
      const ap = (await tx.update(approvals).set({ state: "expired", endReason: "expired" })
        .where(and(eq(approvals.id, row.id), inArray(approvals.state, ["pending", "approved"]))).returning())[0];
      if (!ap) return 0;
      await audit(tx, { actor: CHANGES, action: "approval.expired", target: { type: "approval", id: ap.id }, reason: "expired", details: { planId: ap.subjectId } });
      const plan = (await tx.select().from(remediationPlans).where(eq(remediationPlans.id, ap.subjectId)).for("update"))[0];
      if (plan && (plan.state === "awaiting_approval" || plan.state === "approved")) await setPlanState(tx, plan, "proposed", CHANGES, "approval_expired", { approvalId: ap.id });
      return 1;
    });
  }
  return n;
}

/** Reads each open change from the repository. Merged → the finding awaits re-test; closed → the plan can be reworked. */
const GITHUB_OBSERVE_MS = 5 * 60_000;

export async function observeOpenChanges(opts: { orgId?: string; integrationId?: string } = {}): Promise<number> {
  const rows = (await db.execute<{ id: string; org_id: string }>(sql`SELECT * FROM open_code_changes()`)).rows
    .filter((r) => !opts.orgId || r.org_id === opts.orgId);
  let n = 0;
  for (const row of rows) {
    const pre = await withOrg(row.org_id, async (tx) => {
      const ch = (await tx.select().from(codeChanges).where(eq(codeChanges.id, row.id)))[0];
      if (!ch || ch.state !== "open" || !ch.headSha || (opts.integrationId && ch.integrationId !== opts.integrationId)) return null;
      const i = (await tx.select().from(repositoryIntegrations).where(eq(repositoryIntegrations.id, ch.integrationId)))[0];
      // GitHub is asked at most every 5 minutes per pull request (a webhook-triggered look is not throttled).
      if (i?.type === "github" && !opts.integrationId && ch.observedAt && Date.now() - ch.observedAt.getTime() < GITHUB_OBSERVE_MS) return null;
      return i ? { ch, i } : null;
    });
    if (!pre) continue;
    const seen = await observeChange(integrationRef(pre.i), { branch: pre.ch.branch, headSha: pre.ch.headSha! }).catch(() => null);
    if (!seen) continue;
    n += await withOrg(row.org_id, (tx) => applyObservation(tx, row.org_id, pre.ch, seen));
  }
  return n;
}

async function applyObservation(tx: Tx, orgId: string, ch: ChangeRow, seen: Awaited<ReturnType<typeof observeChange>>): Promise<number> {
  const cur = (await tx.select().from(codeChanges).where(and(eq(codeChanges.id, ch.id), eq(codeChanges.state, "open"))).for("update"))[0];
  if (!cur) return 0;
  const now = new Date();
  if (seen.state === "open") {
    await tx.update(codeChanges).set({ observedAt: now }).where(eq(codeChanges.id, ch.id));
    return 0;
  }
  const plan = (await tx.select().from(remediationPlans).where(eq(remediationPlans.id, ch.planId)).for("update"))[0];
  if (seen.state === "merged") {
    await tx.update(codeChanges).set({ state: "merged", mergeSha: seen.mergeSha, observedAt: now }).where(eq(codeChanges.id, ch.id));
    await audit(tx, { actor: CHANGES, action: "remediation.change_merged_observed", target: { type: "code_change", id: ch.id }, details: { planId: ch.planId, mergeSha: seen.mergeSha, verified: false } });
    if (plan?.state === "change_submitted") {
      const merged = await setPlanState(tx, plan, "merged_observed", CHANGES, "merge_observed", { codeChangeId: ch.id, mergeSha: seen.mergeSha });
      await setPlanState(tx, merged, "verifying", CHANGES, "awaiting_verification");
      await findingToPendingVerification(tx, orgId, plan.findingId, CHANGES, { planId: plan.id, codeChangeId: ch.id });
    }
  } else {
    await tx.update(codeChanges).set({ state: "closed", observedAt: now }).where(eq(codeChanges.id, ch.id));
    await audit(tx, { actor: CHANGES, action: "remediation.change_closed_observed", target: { type: "code_change", id: ch.id }, details: { planId: ch.planId } });
    if (plan?.state === "change_submitted") await setPlanState(tx, plan, "closed_unmerged", CHANGES, "branch_closed", { codeChangeId: ch.id });
  }
  return 1;
}

// ---------- verification outcome (called from the verification worker) ----------

/**
 * The only way a plan completes: a verification run of its finding finished. A passed run completes the plan;
 * failed, inconclusive or errored runs mark it failed, so it is never shown as done without a passing re-test.
 */
export async function settlePlansAfterVerification(tx: Tx, findingId: string, passed: boolean, runId: string): Promise<PlanRow[]> {
  const plans = await tx.select().from(remediationPlans).where(and(eq(remediationPlans.findingId, findingId), eq(remediationPlans.state, "verifying"))).for("update");
  const out: PlanRow[] = [];
  for (const p of plans) {
    out.push(await setPlanState(tx, p, passed ? "completed" : "remediation_failed", { type: "service", id: "verification" }, passed ? "verified_fixed" : "verification_not_passed", { verificationRunId: runId }));
  }
  return out;
}

/**
 * What the FixProof record says about remediation: the plans awaiting this verification, who approved them and the
 * change that was opened. Only facts recorded by RuyaShield; a fix made outside it is reported as not recorded.
 */
export async function remediationForFixProof(tx: Tx, findingId: string) {
  const plans = await tx.select().from(remediationPlans).where(and(eq(remediationPlans.findingId, findingId), eq(remediationPlans.state, "verifying")));
  if (!plans.length) {
    return { remediation: { recorded: null, note: "No remediation plan in RuyaShield was awaiting this verification; any fix was made outside RuyaShield." }, aiInvolvement: "none" as const };
  }
  const ids = plans.map((p) => p.id);
  const aps = await tx.select().from(approvals).where(and(inArray(approvals.subjectId, ids), inArray(approvals.state, ["approved", "consumed"])));
  const changes = await tx.select().from(codeChanges).where(inArray(codeChanges.planId, ids));
  const recorded = plans.map((p) => {
    const ap = aps.filter((a) => a.subjectId === p.id).sort((a, b) => +(b.decidedAt ?? 0) - +(a.decidedAt ?? 0))[0];
    const ch = changes.filter((x) => x.planId === p.id).sort((a, b) => +b.createdAt - +a.createdAt)[0];
    return {
      planId: p.id, type: p.type, title: p.title, version: p.version, contentSha256: p.contentSha256, diffSha256: p.diffSha256,
      fromAiRecommendation: !!p.aiClaimId,
      approval: ap ? { id: ap.id, policy: ap.policy, approverId: ap.approverId, selfApproved: ap.selfApproved, untestedOverride: ap.untestedOverride, decidedAt: ap.decidedAt?.toISOString() ?? null } : null,
      change: ch ? { branch: ch.branch, headSha: ch.headSha, mergeSha: ch.mergeSha, state: ch.state, url: ch.prUrl } : null,
    };
  });
  const ai = plans.some((p) => p.aiClaimId);
  return {
    remediation: { recorded, note: plans.some((p) => p.type === "guided") ? "Guided plans were applied by the customer; RuyaShield did not change the system." : "Changes were opened by RuyaShield and merged by the customer." },
    aiInvolvement: ai ? "remediation plan drafted from an AI recommendation and reviewed by a person; verification used deterministic checks only" as const : "none" as const,
  };
}

// ---------- reads ----------

export async function listApprovals(c: Ctx, opts: { state?: string } = {}) {
  return withOrg(c.org.id, async (tx) => {
    const rows = await tx.select({ ap: approvals, plan: remediationPlans, f: findings, a: assets }).from(approvals)
      .innerJoin(remediationPlans, eq(remediationPlans.id, approvals.subjectId))
      .innerJoin(findings, eq(findings.id, remediationPlans.findingId))
      .innerJoin(assets, eq(assets.id, findings.assetId))
      .where(opts.state ? eq(approvals.state, opts.state as ApprovalRow["state"]) : undefined)
      .orderBy(desc(approvals.createdAt)).limit(200);
    return rows.filter((r) => decide(c.principal, "finding.view", res(r.f, r.a), c.org).allow).map((r) => ({
      approval: r.ap, plan: r.plan, finding: { id: r.f.id, title: r.f.title, severity: r.f.severity, status: r.f.status },
      canDecide: r.ap.state === "pending" && decide(c.principal, "approval.decide", res(r.f, r.a, decider(c, r.ap)), c.org).allow,
    }));
  });
}

export async function codeChangesForPlan(tx: Tx, planId: string) {
  return tx.select().from(codeChanges).where(eq(codeChanges.planId, planId)).orderBy(desc(codeChanges.createdAt)).limit(20);
}
