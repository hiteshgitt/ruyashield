import { randomUUID } from "node:crypto";
import { and, desc, eq, inArray, lt, sql } from "drizzle-orm";
import { z } from "zod";
import { db, withOrg, isUuid, type Tx } from "../db/client";
import {
  aiAnalyses, aiClaims, approvals, assets, codeChanges, findings, remediationPlanHistory, remediationPlans, repositoryIntegrations, sandboxRuns,
  type FindingStatus, type PlanState, type SandboxResult,
} from "../db/schema";
import { audit, type Actor } from "../audit/audit";
import { AppError, isAppError, notFound } from "../errors";
import { authorize, decide, type OrgFlags, type Principal, type Resource } from "../policy/policy";
import { enqueue } from "../outbox/outbox";
import { canonicalJson, sha256, storeEvidence } from "../findings/evidence";
import { recordTransition } from "../findings/record";
import { systemTransitionAllowed } from "../findings/lifecycle";
import { verifiableChecks } from "../verification/verification";
import { checkoutForSandbox, checkPatch, resolveCommit, type RepoRef } from "./repo";
import { ISOLATION_LABEL, SANDBOX_LIMITS, runTests, sandboxAvailable, type CommandRunner } from "./sandbox";

// Remediation plans and sandbox runs (RS-REMED-001..003). A plan is a human-owned description of a fix: either guided
// steps the customer applies, or a patch against a connected repository. Nothing here changes a repository or a
// target; patches are only applied to a throwaway copy inside the sandbox. Every state change is written to the plan
// history and the audit log, and the database guard (0007) rejects any transition not listed there.

export type Ctx = { principal: Principal; org: OrgFlags & { id: string; approverMustDiffer?: boolean } };
type FindingRow = typeof findings.$inferSelect;
type AssetRow = typeof assets.$inferSelect;
export type PlanRow = typeof remediationPlans.$inferSelect;
type IntegrationRow = typeof repositoryIntegrations.$inferSelect;
type SandboxRow = typeof sandboxRuns.$inferSelect;

export const SANDBOX_LEASE_MS = 30 * 60_000;
const SANDBOX: Actor = { type: "service", id: "remediation-sandbox" };
export const userActor = (p: Principal) => ({ type: "user" as const, id: p.userId, ip: p.ip });
export const res = (f: FindingRow, a: AssetRow, requesterId?: string): Resource =>
  ({ type: "finding", id: f.id, clientGroupId: a.clientGroupId, ownerId: f.ownerId, requesterId });

/** Plans can be started for findings that are still open and not already waiting on verification. */
const PLANNABLE: readonly FindingStatus[] = ["new", "triaged", "confirmed", "in_remediation", "reopened"];
/** States in which the content may change; an edit moves the plan back to "proposed" (draft stays draft). */
const EDITABLE: readonly PlanState[] = ["draft", "proposed", "test_failed", "test_passed", "awaiting_approval", "approved", "rejected", "closed_unmerged", "remediation_failed"];
const SHA40 = /^[0-9a-f]{40}$/;

export function planContentSha(p: Pick<PlanRow, "type" | "title" | "description" | "affectedComponents" | "rollbackNotes" | "verificationChecks" | "integrationId" | "baseCommit" | "diffSha256">): string {
  return sha256(canonicalJson({
    type: p.type, title: p.title, description: p.description, affectedComponents: p.affectedComponents, rollbackNotes: p.rollbackNotes,
    verificationChecks: [...p.verificationChecks].sort(), integrationId: p.integrationId ?? null, baseCommit: p.baseCommit ?? null, diffSha256: p.diffSha256 ?? null,
  }));
}

export async function loadFindingFor(tx: Tx, c: Ctx, findingId: string, lock = false) {
  if (!isUuid(findingId)) throw notFound();
  const q = tx.select().from(findings).where(eq(findings.id, findingId));
  const f = (lock ? await q.for("update") : await q)[0];
  if (!f) throw notFound();
  const a = (await tx.select().from(assets).where(eq(assets.id, f.assetId)))[0];
  if (!a || !decide(c.principal, "finding.view", res(f, a), c.org).allow) throw notFound();
  return { f, a };
}

/** A plan is visible exactly when its finding is. */
export async function loadPlan(tx: Tx, c: Ctx, planId: string, lock = false) {
  if (!isUuid(planId)) throw notFound();
  const q = tx.select().from(remediationPlans).where(eq(remediationPlans.id, planId));
  const plan = (lock ? await q.for("update") : await q)[0];
  if (!plan) throw notFound();
  const { f, a } = await loadFindingFor(tx, c, plan.findingId, lock);
  return { plan, f, a };
}

export const integrationRef = (i: IntegrationRow): RepoRef => ({ externalId: i.externalId, defaultBranch: i.defaultBranch });

async function activeIntegration(tx: Tx, id: string | null | undefined): Promise<IntegrationRow> {
  if (!id || !isUuid(id)) throw new AppError(422, "integration_required", "A patch plan needs a connected repository.");
  const i = (await tx.select().from(repositoryIntegrations).where(eq(repositoryIntegrations.id, id)))[0];
  if (!i || i.status !== "active") throw new AppError(422, "integration_unavailable", "The repository connection is not active.");
  return i;
}

/** Moves a plan and records why. `patch` carries content changes made in the same step. */
export async function setPlanState(tx: Tx, plan: PlanRow, to: PlanState, actor: Actor, reason: string, details: Record<string, unknown> = {}, patch: Partial<PlanRow> = {}): Promise<PlanRow> {
  const updatedBy = actor.type === "user" ? actor.id : plan.updatedBy;
  const next = (await tx.update(remediationPlans).set({ ...patch, state: to, updatedBy, updatedAt: new Date() })
    .where(eq(remediationPlans.id, plan.id)).returning())[0];
  await tx.insert(remediationPlanHistory).values({
    orgId: plan.orgId, planId: plan.id, fromState: plan.state, toState: to,
    contentSha256: next.contentSha256, actorType: actor.type === "user" ? "user" : "service", actorId: actor.type === "anonymous" ? "anonymous" : actor.id,
    reason, details,
  });
  await audit(tx, {
    actor, action: plan.state === to ? "remediation.plan_updated" : "remediation.plan_state_changed", target: { type: "remediation_plan", id: plan.id },
    reason, details: { findingId: plan.findingId, from: plan.state, to, version: next.version, contentSha256: next.contentSha256, ...details },
  });
  return next;
}

/** Ends any pending or approved approval of the plan; a change after approval always needs a new decision. */
export async function invalidateApprovals(tx: Tx, plan: PlanRow, actor: Actor, endReason: string) {
  const ended = await tx.update(approvals).set({ state: "invalidated", endReason })
    .where(and(eq(approvals.subjectId, plan.id), inArray(approvals.state, ["pending", "approved"]))).returning({ id: approvals.id });
  for (const e of ended) {
    await audit(tx, { actor, action: "approval.invalidated", target: { type: "approval", id: e.id }, reason: endReason, details: { planId: plan.id } });
  }
  return ended.length;
}

// ---------- create / edit (RS-REMED-001) ----------

const text = (min: number, max: number) => z.string().trim().min(min).max(max);
const contentFields = {
  title: text(3, 200),
  description: text(1, 20_000),
  affectedComponents: z.array(text(1, 200)).max(50).default([]),
  rollbackNotes: z.string().max(10_000).default(""),
  verificationChecks: z.array(z.string().min(1).max(200)).max(50).optional(),
  integrationId: z.string().uuid().nullish(),
  baseCommit: z.string().regex(SHA40).nullish(),
  diff: z.string().max(262_144).nullish(),
};
const createInput = z.object({ idempotencyKey: z.string().min(8).max(100), type: z.enum(["guided", "patch"]), ...contentFields });
const editInput = z.object({
  version: z.number().int().positive(),
  title: contentFields.title.optional(), description: contentFields.description.optional(),
  affectedComponents: z.array(text(1, 200)).max(50).optional(), rollbackNotes: z.string().max(10_000).optional(),
  verificationChecks: contentFields.verificationChecks, baseCommit: contentFields.baseCommit, diff: contentFields.diff,
});

function invalid(e: z.ZodError): never {
  throw new AppError(422, "invalid_request", e.issues.map((i) => `${i.path.join(".") || "input"}: ${i.message}`).join("; "));
}

/** The re-test checks a plan names must be ones that can actually re-test this finding (default: all of them). */
async function pickChecks(tx: Tx, f: FindingRow, wanted: string[] | undefined): Promise<string[]> {
  const { usable } = await verifiableChecks(tx, f);
  const ids = usable.map((d) => d.id);
  if (wanted === undefined) return ids;
  const unknown = wanted.filter((w) => !ids.includes(w));
  if (unknown.length) throw new AppError(422, "check_unsupported", `These checks cannot re-test this finding: ${unknown.join(", ")}`);
  return [...new Set(wanted)];
}

/** Patch content must name an active repository, a real base commit, and apply cleanly there. */
async function preparePatch(tx: Tx, integrationId: string | null | undefined, baseCommit: string | null | undefined, diff: string | null | undefined) {
  if (!diff || !diff.trim()) throw new AppError(422, "invalid_patch", "A patch plan needs a diff.");
  const i = await activeIntegration(tx, integrationId);
  const ref = integrationRef(i);
  const base = baseCommit ?? await resolveCommit(ref, i.defaultBranch);
  if (baseCommit) await resolveCommit(ref, baseCommit); // must exist in this repository
  const check = await checkPatch(ref, base, diff);
  if (!check.ok) throw new AppError(422, "patch_does_not_apply", `The patch does not apply to ${base.slice(0, 12)}: ${check.reason}`);
  return { integrationId: i.id, baseCommit: base, diff, diffSha256: sha256(diff) };
}

export async function createPlan(c: Ctx, findingId: string, input: unknown) {
  const parsed = createInput.safeParse(input ?? {});
  if (!parsed.success) invalid(parsed.error);
  const d = parsed.data;
  const actor = userActor(c.principal);
  try {
    return await withOrg(c.org.id, async (tx) => {
      const { f, a } = await loadFindingFor(tx, c, findingId, true);
      await authorize(c.principal, "remediation.edit", res(f, a), c.org);
      const prior = (await tx.select().from(remediationPlans).where(eq(remediationPlans.idempotencyKey, d.idempotencyKey)))[0];
      if (prior) {
        if (prior.findingId !== f.id) throw new AppError(409, "idempotency_conflict", "This request key was already used for another finding.");
        return { plan: prior, replayed: true };
      }
      if (!PLANNABLE.includes(f.status)) throw new AppError(422, "plan_not_allowed", `A remediation plan cannot be started for a finding that is ${f.status.replace(/_/g, " ")}.`);
      const checks = await pickChecks(tx, f, d.verificationChecks);
      const patch = d.type === "patch"
        ? await preparePatch(tx, d.integrationId, d.baseCommit, d.diff)
        : { integrationId: null, baseCommit: null, diff: null, diffSha256: null };
      if (d.type === "guided" && (d.diff || d.integrationId || d.baseCommit)) throw new AppError(422, "invalid_request", "A guided plan has no diff or repository.");
      const content = { type: d.type, title: d.title, description: d.description, affectedComponents: d.affectedComponents, rollbackNotes: d.rollbackNotes, verificationChecks: checks, ...patch };
      return { plan: await insertPlan(tx, c.org.id, f.id, content, actor, d.idempotencyKey, {}), replayed: false };
    });
  } catch (e) {
    await rejected(c, e, "remediation.plan_rejected", { type: "finding", id: findingId }, ["plan_not_allowed", "check_unsupported", "invalid_patch", "patch_does_not_apply", "integration_required", "integration_unavailable", "unknown_ref"]);
    throw e;
  }
}

async function insertPlan(tx: Tx, orgId: string, findingId: string, content: Omit<PlanRow, "id" | "orgId" | "findingId" | "state" | "contentSha256" | "version" | "aiAnalysisId" | "aiClaimId" | "createdBy" | "updatedBy" | "idempotencyKey" | "createdAt" | "updatedAt">, actor: { type: "user"; id: string }, idempotencyKey: string, ai: { aiAnalysisId?: string; aiClaimId?: string }) {
  const id = randomUUID();
  const contentSha256 = planContentSha(content);
  const plan = (await tx.insert(remediationPlans).values({
    id, orgId, findingId, ...content, contentSha256, createdBy: actor.id, updatedBy: actor.id, idempotencyKey, ...ai,
  }).returning())[0];
  await tx.insert(remediationPlanHistory).values({ orgId, planId: id, fromState: null, toState: "draft", contentSha256, actorType: "user", actorId: actor.id, reason: "created", details: ai });
  await audit(tx, {
    actor, action: "remediation.plan_created", target: { type: "remediation_plan", id },
    details: { findingId, type: content.type, contentSha256, diffSha256: content.diffSha256, integrationId: content.integrationId, checks: content.verificationChecks, ...ai },
  });
  return plan;
}

export async function editPlan(c: Ctx, planId: string, input: unknown) {
  const parsed = editInput.safeParse(input ?? {});
  if (!parsed.success) invalid(parsed.error);
  const d = parsed.data;
  const actor = userActor(c.principal);
  try {
    return await withOrg(c.org.id, async (tx) => {
      const { plan, f, a } = await loadPlan(tx, c, planId, true);
      await authorize(c.principal, "remediation.edit", res(f, a), c.org);
      if (d.version !== plan.version) throw new AppError(409, "stale_plan", "The plan changed since you opened it. Reload and try again.");
      if (!EDITABLE.includes(plan.state)) throw new AppError(409, "plan_locked", `A plan that is ${plan.state.replace(/_/g, " ")} cannot be edited.`);
      if (plan.type === "guided" && (d.diff || d.baseCommit)) throw new AppError(422, "invalid_request", "A guided plan has no diff or repository.");

      const next = {
        type: plan.type, title: d.title ?? plan.title, description: d.description ?? plan.description,
        affectedComponents: d.affectedComponents ?? plan.affectedComponents, rollbackNotes: d.rollbackNotes ?? plan.rollbackNotes,
        verificationChecks: d.verificationChecks === undefined ? plan.verificationChecks : await pickChecks(tx, f, d.verificationChecks),
        integrationId: plan.integrationId, baseCommit: plan.baseCommit, diff: plan.diff, diffSha256: plan.diffSha256,
      };
      if (plan.type === "patch" && (d.diff !== undefined || d.baseCommit !== undefined)) {
        Object.assign(next, await preparePatch(tx, plan.integrationId, d.baseCommit ?? plan.baseCommit, d.diff ?? plan.diff));
      }
      const contentSha256 = planContentSha(next);
      if (contentSha256 === plan.contentSha256) return { plan, changed: false };

      const ended = await invalidateApprovals(tx, plan, actor, "plan_changed");
      const to: PlanState = plan.state === "draft" ? "draft" : "proposed";
      const updated = await setPlanState(tx, plan, to, actor, "edited", { previousSha256: plan.contentSha256, approvalsInvalidated: ended },
        { ...next, contentSha256, version: plan.version + 1 });
      return { plan: updated, changed: true };
    });
  } catch (e) {
    await rejected(c, e, "remediation.plan_rejected", { type: "remediation_plan", id: planId }, ["plan_locked", "stale_plan", "check_unsupported", "invalid_patch", "patch_does_not_apply", "integration_unavailable", "unknown_ref"]);
    throw e;
  }
}

/** draft → proposed. The finding moves to "in remediation" when its lifecycle allows it. */
export async function submitPlan(c: Ctx, planId: string) {
  const actor = userActor(c.principal);
  return withOrg(c.org.id, async (tx) => {
    const { plan, f, a } = await loadPlan(tx, c, planId, true);
    await authorize(c.principal, "remediation.edit", res(f, a), c.org);
    if (plan.state !== "draft") return { plan, changed: false };
    const next = await setPlanState(tx, plan, "proposed", actor, "submitted");
    if (systemTransitionAllowed(f.status, "in_remediation", "remediation_proposed")) {
      await recordTransition(tx, { orgId: c.org.id, findingId: f.id, from: f.status, to: "in_remediation", actor, reason: "remediation_proposed", requestId: c.principal.requestId ?? undefined, details: { planId: plan.id } });
    }
    return { plan: next, changed: true };
  });
}

// ---------- AI recommendation → draft plan (RS-AI-005 linkage) ----------

const fromAiInput = z.object({ idempotencyKey: z.string().min(8).max(100), claimId: z.string().uuid() });

/**
 * Copies a validated AI recommendation into a draft guided plan. The text is treated as an untrusted suggestion:
 * the plan starts as a draft that a person must review and submit; nothing is applied or approved by this step.
 */
export async function createPlanFromAi(c: Ctx, findingId: string, input: unknown) {
  const parsed = fromAiInput.safeParse(input ?? {});
  if (!parsed.success) invalid(parsed.error);
  const { idempotencyKey, claimId } = parsed.data;
  const actor = userActor(c.principal);
  return withOrg(c.org.id, async (tx) => {
    const { f, a } = await loadFindingFor(tx, c, findingId, true);
    await authorize(c.principal, "remediation.edit", res(f, a), c.org);
    const prior = (await tx.select().from(remediationPlans).where(eq(remediationPlans.idempotencyKey, idempotencyKey)))[0];
    if (prior) {
      if (prior.findingId !== f.id) throw new AppError(409, "idempotency_conflict", "This request key was already used for another finding.");
      return { plan: prior, replayed: true };
    }
    const row = (await tx.select({ claim: aiClaims, analysis: aiAnalyses }).from(aiClaims)
      .innerJoin(aiAnalyses, eq(aiAnalyses.id, aiClaims.analysisId)).where(eq(aiClaims.id, claimId)))[0];
    if (!row || row.analysis.findingId !== f.id) throw notFound();
    if (row.claim.type !== "recommendation" || row.analysis.status !== "completed") {
      throw new AppError(422, "not_a_recommendation", "Only a recommendation from a completed analysis can start a plan.");
    }
    if (!PLANNABLE.includes(f.status)) throw new AppError(422, "plan_not_allowed", `A remediation plan cannot be started for a finding that is ${f.status.replace(/_/g, " ")}.`);
    const { usable } = await verifiableChecks(tx, f);
    const usableIds = usable.map((d) => d.id);
    const named = row.claim.verificationCheckIds.filter((id) => usableIds.includes(id));
    const steps = row.claim.steps.length ? `\n\nSuggested steps (AI-generated, review before use):\n${row.claim.steps.map((s, i) => `${i + 1}. ${s}`).join("\n")}` : "";
    const content = {
      type: "guided" as const, title: `Fix: ${f.title}`.slice(0, 200),
      description: `${row.claim.text}${steps}`.slice(0, 20_000), affectedComponents: [], rollbackNotes: "",
      verificationChecks: named.length ? named : usableIds, integrationId: null, baseCommit: null, diff: null, diffSha256: null,
    };
    const plan = await insertPlan(tx, c.org.id, f.id, content, actor, idempotencyKey, { aiAnalysisId: row.analysis.id, aiClaimId: row.claim.id });
    return { plan, replayed: false };
  });
}

// ---------- sandbox (RS-REMED-002/003) ----------

const sandboxInput = z.object({ idempotencyKey: z.string().min(8).max(100) });

export async function requestSandbox(c: Ctx, planId: string, input: unknown) {
  const parsed = sandboxInput.safeParse(input ?? {});
  if (!parsed.success) throw new AppError(422, "invalid_request", "A request key is required.");
  const { idempotencyKey } = parsed.data;
  const actor = userActor(c.principal);
  try {
    return await withOrg(c.org.id, async (tx) => {
      const { plan, f, a } = await loadPlan(tx, c, planId, true);
      await authorize(c.principal, "remediation.sandbox", res(f, a), c.org);
      const prior = (await tx.select().from(sandboxRuns).where(eq(sandboxRuns.idempotencyKey, idempotencyKey)))[0];
      if (prior) {
        if (prior.planId !== plan.id) throw new AppError(409, "idempotency_conflict", "This request key was already used for another plan.");
        return { run: prior, replayed: true };
      }
      if (plan.type !== "patch" || !plan.diff || !plan.diffSha256 || !plan.baseCommit) throw new AppError(422, "sandbox_not_applicable", "Only patch plans can be tested in the sandbox.");
      if (!["proposed", "test_failed", "test_passed"].includes(plan.state)) throw new AppError(409, "plan_state", `A plan that is ${plan.state.replace(/_/g, " ")} cannot be tested now.`);
      const i = await activeIntegration(tx, plan.integrationId);
      if (!i.testCommands.length) throw new AppError(422, "no_test_commands", "The repository connection has no test commands configured.");

      let current = plan;
      if (current.state !== "proposed") current = await setPlanState(tx, current, "proposed", actor, "retest");
      const id = randomUUID();
      const run = (await tx.insert(sandboxRuns).values({
        id, orgId: c.org.id, planId: plan.id, patchSha256: plan.diffSha256, contentSha256: plan.contentSha256, baseCommit: plan.baseCommit,
        isolation: ISOLATION_LABEL, limits: { ...SANDBOX_LIMITS }, commands: i.testCommands, requestedBy: c.principal.userId, idempotencyKey,
      }).returning())[0];
      await setPlanState(tx, current, "sandbox_testing", actor, "sandbox_requested", { sandboxRunId: id });
      await enqueue(tx, { orgId: c.org.id, topic: "remediation.sandbox", businessKey: `sandbox:${id}:1`, payload: { runId: id } });
      await audit(tx, {
        actor, action: "remediation.sandbox_requested", target: { type: "sandbox_run", id }, requestId: c.principal.requestId,
        details: { planId: plan.id, findingId: f.id, patchSha256: plan.diffSha256, baseCommit: plan.baseCommit, commands: i.testCommands, isolation: ISOLATION_LABEL },
      });
      return { run, replayed: false };
    });
  } catch (e) {
    await rejected(c, e, "remediation.sandbox_rejected", { type: "remediation_plan", id: planId }, ["sandbox_not_applicable", "plan_state", "no_test_commands", "integration_unavailable", "integration_required"]);
    throw e;
  }
}

export interface SandboxDeps { runner?: CommandRunner; now?: () => Date }

/** Worker: applies the patch to a throwaway copy and runs the snapshot of test commands there. */
export async function runSandbox(orgId: string, payload: { runId?: unknown }, deps: SandboxDeps = {}): Promise<string> {
  const now = deps.now ?? (() => new Date());
  const id = typeof payload.runId === "string" ? payload.runId : "";
  if (!isUuid(id)) return "invalid_payload";

  const claim = await withOrg(orgId, async (tx) => {
    const run = (await tx.select().from(sandboxRuns).where(eq(sandboxRuns.id, id)).for("update"))[0];
    if (!run) return { skip: "missing" };
    if (run.status !== "queued") return { skip: `not_queued:${run.status}` };
    const r = (await tx.update(sandboxRuns).set({ status: "running", startedAt: now() }).where(eq(sandboxRuns.id, id)).returning())[0];
    await audit(tx, { actor: SANDBOX, action: "remediation.sandbox_started", target: { type: "sandbox_run", id }, details: { planId: run.planId, isolation: run.isolation } });
    const plan = (await tx.select().from(remediationPlans).where(eq(remediationPlans.id, run.planId)))[0];
    const i = plan?.integrationId ? (await tx.select().from(repositoryIntegrations).where(eq(repositoryIntegrations.id, plan.integrationId)))[0] : undefined;
    return { run: r, plan, i };
  });
  if ("skip" in claim) return claim.skip ?? "skipped";
  const { run, plan, i } = claim;

  if (!plan || plan.state !== "sandbox_testing" || plan.contentSha256 !== run.contentSha256 || !plan.diff) return finishSandbox(orgId, run, { result: "error", reason: "plan_changed", exitCode: null, commands: [] }, now);
  if (!i || i.status !== "active") return finishSandbox(orgId, run, { result: "error", reason: "integration_unavailable", exitCode: null, commands: [] }, now);
  if (!deps.runner && !sandboxAvailable()) return finishSandbox(orgId, run, { result: "error", reason: "sandbox_unavailable", exitCode: null, commands: [] }, now);

  let checkout: Awaited<ReturnType<typeof checkoutForSandbox>>;
  try {
    checkout = await checkoutForSandbox(integrationRef(i), run.baseCommit, plan.diff);
  } catch (e) {
    checkout = { error: isAppError(e) ? e.code : "checkout_failed" };
  }
  if ("error" in checkout) return finishSandbox(orgId, run, { result: "apply_failed", reason: checkout.error, exitCode: null, commands: [] }, now);
  try {
    const outcome = await runTests(checkout.dir, run.commands, deps.runner, { ...SANDBOX_LIMITS, ...(run.limits as Partial<typeof SANDBOX_LIMITS>) });
    return await finishSandbox(orgId, run, outcome, now);
  } catch {
    return finishSandbox(orgId, run, { result: "error", reason: "internal_error", exitCode: null, commands: [] }, now);
  } finally {
    await checkout.cleanup();
  }
}

async function finishSandbox(orgId: string, run: SandboxRow, o: { result: SandboxResult; reason: string | null; exitCode: number | null; commands: { argv: string[]; exitCode: number | null; timedOut: boolean; output: string; truncated: boolean }[] }, now: () => Date) {
  return withOrg(orgId, async (tx) => {
    const mine = (await tx.select().from(sandboxRuns).where(and(eq(sandboxRuns.id, run.id), eq(sandboxRuns.status, "running"))).for("update"))[0];
    if (!mine) return "lease_lost";
    const logs = await storeEvidence(tx, {
      orgId, body: {
        kind: "sandbox_logs", sandboxRunId: run.id, planId: run.planId, isolation: run.isolation, result: o.result, reason: o.reason,
        commands: o.commands.map((c) => ({ argv: c.argv, exitCode: c.exitCode, timedOut: c.timedOut, truncated: c.truncated, output: c.output })),
      },
    });
    await tx.update(sandboxRuns).set({ status: "completed", result: o.result, reason: o.reason, exitCode: o.exitCode, logsEvidenceId: logs.id, finishedAt: now() })
      .where(eq(sandboxRuns.id, run.id));
    await settlePlanAfterSandbox(tx, run, o.result, o.reason, logs.id);
    await audit(tx, {
      actor: SANDBOX, action: "remediation.sandbox_completed", target: { type: "sandbox_run", id: run.id },
      outcome: o.result === "test_passed" ? "success" : o.result === "test_failed" ? "denied" : "error", reason: o.reason ?? o.result,
      details: { planId: run.planId, result: o.result, exitCode: o.exitCode, logsEvidenceId: logs.id, logsSha256: logs.sha256 },
    });
    return `completed:${o.result}`;
  });
}

/** Only an actual pass marks the plan tested; every other result (including errors and timeouts) is a failed test. */
async function settlePlanAfterSandbox(tx: Tx, run: SandboxRow, result: SandboxResult, reason: string | null, logsEvidenceId: string | null) {
  const plan = (await tx.select().from(remediationPlans).where(eq(remediationPlans.id, run.planId)).for("update"))[0];
  if (!plan || plan.state !== "sandbox_testing") return;
  const to: PlanState = result === "test_passed" && plan.contentSha256 === run.contentSha256 ? "test_passed" : "test_failed";
  await setPlanState(tx, plan, to, SANDBOX, `sandbox_${result}`, { sandboxRunId: run.id, sandboxReason: reason, logsEvidenceId });
}

/** A run whose worker died is closed as an error after the lease, and its plan becomes "test failed". */
export async function sweepSandboxRuns(now = new Date()): Promise<number> {
  const before = new Date(now.getTime() - SANDBOX_LEASE_MS);
  const stuck = await db.execute<{ id: string; org_id: string }>(sql`SELECT * FROM stuck_sandbox_runs(${before.toISOString()}::timestamptz)`);
  let n = 0;
  for (const row of stuck.rows) {
    n += await withOrg(row.org_id, async (tx) => {
      const u = await tx.update(sandboxRuns).set({ status: "completed", result: "error", reason: "runner_lost", finishedAt: now })
        .where(and(eq(sandboxRuns.id, row.id), eq(sandboxRuns.status, "running"), lt(sandboxRuns.startedAt, before))).returning();
      if (!u.length) return 0;
      await settlePlanAfterSandbox(tx, u[0], "error", "runner_lost", null);
      await audit(tx, { actor: SANDBOX, action: "remediation.sandbox_completed", target: { type: "sandbox_run", id: row.id }, outcome: "error", reason: "runner_lost", details: { planId: u[0].planId } });
      return 1;
    });
  }
  return n;
}

// ---------- reads ----------

export async function listPlansForFinding(c: Ctx, findingId: string) {
  return withOrg(c.org.id, async (tx) => {
    const { f } = await loadFindingFor(tx, c, findingId);
    return tx.select().from(remediationPlans).where(eq(remediationPlans.findingId, f.id)).orderBy(desc(remediationPlans.createdAt));
  });
}

export async function getPlan(c: Ctx, planId: string) {
  return withOrg(c.org.id, async (tx) => {
    const { plan, f } = await loadPlan(tx, c, planId);
    const [history, runs, approvalRows, changes] = await Promise.all([
      tx.select().from(remediationPlanHistory).where(eq(remediationPlanHistory.planId, plan.id)).orderBy(desc(remediationPlanHistory.createdAt)).limit(100),
      tx.select().from(sandboxRuns).where(eq(sandboxRuns.planId, plan.id)).orderBy(desc(sandboxRuns.createdAt)).limit(20),
      tx.select().from(approvals).where(eq(approvals.subjectId, plan.id)).orderBy(desc(approvals.createdAt)).limit(20),
      tx.select().from(codeChanges).where(eq(codeChanges.planId, plan.id)).orderBy(desc(codeChanges.createdAt)).limit(20),
    ]);
    const integration = plan.integrationId ? (await tx.select().from(repositoryIntegrations).where(eq(repositoryIntegrations.id, plan.integrationId)))[0] ?? null : null;
    return { plan, finding: f, history, sandboxRuns: runs, approvals: approvalRows, codeChanges: changes, integration };
  });
}

/** Audits expected refusals as denied attempts in their own transaction, so the record survives the rollback. */
export async function rejected(c: Ctx, e: unknown, action: string, target: { type: string; id: string }, codes: string[]) {
  if (!isAppError(e) || !codes.includes(e.code)) return;
  await withOrg(c.org.id, (tx) => audit(tx, {
    actor: userActor(c.principal), action, target: isUuid(target.id) ? target : null, outcome: "denied",
    reason: e.code, requestId: c.principal.requestId, details: { message: e.message },
  }));
}
