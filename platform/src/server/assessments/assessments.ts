import { randomUUID } from "node:crypto";
import { and, asc, desc, eq, inArray, sql } from "drizzle-orm";
import { z } from "zod";
import { withOrg, isUuid, type Tx } from "../db/client";
import {
  assessments, assets, attestations, checkDefinitions, checkRuns, findingOccurrences, findings, orgs, plans,
  repositoryIntegrations, scopeVersions, usageRecords, webmonitorReferrals, type AssessmentStatus, type CheckRunStatus, type Coverage,
} from "../db/schema";
import { audit, type Actor } from "../audit/audit";
import { AppError, isAppError, notFound } from "../errors";
import { authorize, decide, isProOrg, type OrgFlags, type Principal, type Resource } from "../policy/policy";
import { freeVisibleIds } from "../findings/findings";
import { grantFor } from "../policy/matrix";
import { enqueue } from "../outbox/outbox";
import { EgressError, type DnsDeps, type EgressDeps } from "../net/egress";
import { eligibilityOf } from "../assets/assets";
import { scopeSha, validateScope, type CatalogueEntry, type Scope } from "./scope";
import { signJobToken, verifyJobToken } from "./token";
import { createGuard, ScopeBlocked } from "./guard";
import { ADAPTERS, ENGINE_VERSION, fingerprint, normalizeResult, targetForKind, targetOf, type CheckAdapter, type CheckResult } from "./checks";
import { snapshotRepo, type RepoRef, type RepoSnapshot } from "../remediation/repo";
import { ingestFinding, markMissed } from "../findings/ingest";
import { recordSuggestions } from "../assets/suggestions";
import { queueReferralPublish, referralForLaunch } from "../webmonitor/referrals";
import { queueRunFinished } from "./notify";

export const ACTIVE_STATUSES: AssessmentStatus[] = ["queued", "running", "cancelling"];
export const TERMINAL_STATUSES: AssessmentStatus[] = ["cancelled", "completed", "completed_with_errors", "failed", "timed_out", "rejected"];
export const LEASE_MS = 120_000;

type Ctx = { principal: Principal; org: OrgFlags & { id: string } };
type AssetRow = typeof assets.$inferSelect;
type AssessmentRow = typeof assessments.$inferSelect;
const userActor = (p: Principal) => ({ type: "user" as const, id: p.userId, ip: p.ip });
const RUNNER: Actor = { type: "service", id: "assessment-runner" };
const res = (a: AssetRow, requesterId?: string): Resource => ({ type: "asset", id: a.id, clientGroupId: a.clientGroupId, ownerId: a.createdBy, requesterId });
const period = (d = new Date()) => d.toISOString().slice(0, 7);

async function loadAsset(tx: Tx, id: string, lock = false) {
  if (!isUuid(id)) throw notFound();
  const q = tx.select().from(assets).where(eq(assets.id, id));
  const a = (lock ? await q.for("update") : await q)[0];
  if (!a) throw notFound();
  return a;
}

const canView = (p: Principal, a: AssetRow, org: OrgFlags) => decide(p, "asset.view", res(a), org).allow;

const toScope = (s: typeof scopeVersions.$inferSelect): Scope => ({
  hosts: s.hosts, basePaths: s.basePaths, excludedPaths: s.excludedPaths, checkIds: s.checkIds,
  classes: s.classes as Scope["classes"], windowStart: s.windowStart, windowEnd: s.windowEnd,
  maxRequests: s.maxRequests, maxDurationS: s.maxDurationS,
});

/** Has an adapter, and that adapter targets this kind of asset. */
export function fitsKind(checkId: string, kind: string, adapters: ReadonlyMap<string, CheckAdapter> = ADAPTERS): boolean {
  const ad = adapters.get(checkId);
  return !!ad && targetOf(ad) === targetForKind(kind);
}

// ---------- launch (RS-SCAN-001) ----------

const launchInput = z.object({ assetId: z.string(), idempotencyKey: z.string().trim().min(8).max(100), referralId: z.string().optional() }).passthrough();

export async function launchAssessment(c: Ctx, input: unknown) {
  const parsed = launchInput.safeParse(input);
  if (!parsed.success) throw new AppError(422, "invalid_scope", parsed.error.issues[0].message);
  const { assetId, idempotencyKey, referralId } = parsed.data;
  const actor = userActor(c.principal);

  try {
    return await withOrg(c.org.id, async (tx) => {
      // Lock order: org (quota) then asset (one active assessment, scope version numbering).
      const org = (await tx.select().from(orgs).where(eq(orgs.id, c.org.id)).for("update"))[0];
      const a = await loadAsset(tx, assetId, true);
      if (!canView(c.principal, a, c.org)) throw notFound();
      await authorize(c.principal, "assessment.launch", res(a), c.org);

      const prior = (await tx.select().from(assessments).where(eq(assessments.idempotencyKey, idempotencyKey)))[0];
      if (prior) {
        if (prior.assetId !== a.id) throw new AppError(409, "idempotency_conflict", "This request key was already used for another asset.");
        return { assessment: prior, replayed: true };
      }

      if (a.killScanning) {
        await audit(tx, { actor, action: "authz.denied", target: { type: "asset", id: a.id }, outcome: "denied", reason: "kill_switch_engaged", requestId: c.principal.requestId, details: { attempted: "assessment.launch" } });
        throw new AppError(423, "kill_switch_engaged", "Scanning is stopped for this asset.");
      }
      const atts = await tx.select().from(attestations).where(eq(attestations.assetId, a.id));
      const elig = eligibilityOf(a, atts, undefined, { a2: org.allowIntrusiveNetwork });
      if (!elig.eligible) throw new AppError(403, "authorization_required", elig.reason);
      // A WebMonitor referral never widens scope: it must be consented and for this verified asset's host (RS-WMON-002).
      const referral = referralId ? await referralForLaunch(tx, referralId, a.host) : null;

      const active = await tx.select({ id: assessments.id }).from(assessments)
        .where(and(eq(assessments.assetId, a.id), inArray(assessments.status, ACTIVE_STATUSES)));
      if (active.length) throw new AppError(409, "assessment_active", "An assessment is already queued or running for this asset.");

      const plan = (await tx.select().from(plans).where(eq(plans.id, org.plan)))[0];
      if (!plan) throw new AppError(402, "quota_exceeded", "No plan is configured for this organization.");
      const used = (await tx.select({ n: sql<number>`coalesce(sum(${usageRecords.quantity}), 0)::int` }).from(usageRecords)
        .where(and(eq(usageRecords.kind, "assessment"), eq(usageRecords.period, period()))))[0].n;
      if (used >= plan.maxAssessmentsPerMonth) throw new AppError(402, "quota_exceeded", `This month's limit of ${plan.maxAssessmentsPerMonth} assessments is used up.`);

      // Host checks run against hosts, repository checks against repository assets; never the other way round.
      const catalogue: CatalogueEntry[] = (await tx.select().from(checkDefinitions))
        .map((d) => ({ id: d.id, class: d.class, enabled: d.enabled && fitsKind(d.id, a.kind), requestBudget: d.requestBudget }));
      const scope = validateScope(input, { assetHost: a.host, allowedClasses: elig.allowedClasses, catalogue, planMaxRequests: plan.maxRequestsPerAssessment });
      const sha = scopeSha(scope);

      // Port checks (A2) are rate-limited per asset: at most one launch an hour, whatever its outcome.
      if (scope.checkIds.some((id) => id.startsWith("net."))) {
        const recent = await tx.select({ id: assessments.id }).from(assessments)
          .innerJoin(scopeVersions, eq(scopeVersions.id, assessments.scopeVersionId))
          .where(and(eq(assessments.assetId, a.id), sql`${assessments.queuedAt} > now() - interval '1 hour'`,
            sql`exists (select 1 from unnest(${scopeVersions.checkIds}) id where id like 'net.%')`))
          .limit(1);
        if (recent.length) throw new AppError(429, "rate_limited", "Port checks can run at most once an hour per asset.");
      }

      let sv = (await tx.select().from(scopeVersions).where(and(eq(scopeVersions.assetId, a.id), eq(scopeVersions.sha256, sha))))[0];
      if (!sv) {
        const next = (await tx.select({ v: sql<number>`coalesce(max(${scopeVersions.version}), 0)::int + 1` }).from(scopeVersions).where(eq(scopeVersions.assetId, a.id)))[0].v;
        sv = (await tx.insert(scopeVersions).values({ orgId: c.org.id, assetId: a.id, version: next, ...scope, sha256: sha, createdBy: c.principal.userId }).returning())[0];
      }

      const id = randomUUID();
      const row = (await tx.insert(assessments).values({
        id, orgId: c.org.id, assetId: a.id, scopeVersionId: sv.id, scopeSha256: sha, status: "queued",
        requestedBy: c.principal.userId, idempotencyKey, engineVersion: ENGINE_VERSION, referralId: referral?.id ?? null,
      }).returning())[0];
      if (referral) await tx.update(webmonitorReferrals).set({ assessmentId: id }).where(eq(webmonitorReferrals.id, referral.id));
      await tx.insert(checkRuns).values(scope.checkIds.map((checkId) => ({ orgId: c.org.id, assessmentId: id, checkId })));
      await tx.insert(usageRecords).values({ orgId: c.org.id, kind: "assessment", sourceId: id, period: period() }).onConflictDoNothing();
      const token = signJobToken({ org: c.org.id, assessment: id, sha, exp: scope.windowEnd.getTime() });
      await enqueue(tx, { orgId: c.org.id, topic: "assessment.run", businessKey: `assessment:${id}:1`, payload: { assessmentId: id, token }, availableAt: scope.windowStart });
      await audit(tx, {
        actor, action: "assessment.launched", target: { type: "assessment", id }, requestId: c.principal.requestId,
        details: { assetId: a.id, host: a.host, referralId: referral?.id ?? null, scopeVersion: sv.version, scopeSha256: sha, checks: scope.checkIds, classes: scope.classes, basis: elig.basis, windowStart: scope.windowStart, windowEnd: scope.windowEnd, maxRequests: scope.maxRequests },
      });
      return { assessment: row, replayed: false };
    });
  } catch (e) {
    // Record refusals we decided on (authz denials are already audited by the policy layer).
    if (isAppError(e) && ["invalid_scope", "check_prohibited", "approval_required", "authorization_required", "quota_exceeded", "assessment_active", "referral_invalid", "referral_not_consented", "referral_host_mismatch"].includes(e.code)) {
      await withOrg(c.org.id, (tx) => audit(tx, {
        actor, action: "assessment.rejected", target: isUuid(assetId) ? { type: "asset", id: assetId } : null, outcome: "denied",
        reason: e.code, requestId: c.principal.requestId, details: { message: e.message },
      }));
    }
    throw e;
  }
}

// ---------- cancel ----------

export async function cancelAssessment(c: Ctx, id: string) {
  return withOrg(c.org.id, async (tx) => {
    if (!isUuid(id)) throw notFound();
    const x = (await tx.select().from(assessments).where(eq(assessments.id, id)).for("update"))[0];
    if (!x) throw notFound();
    const a = await loadAsset(tx, x.assetId);
    if (!canView(c.principal, a, c.org)) throw notFound();
    await authorize(c.principal, "assessment.cancel", res(a, x.requestedBy), c.org);
    if (x.status === "cancelling") return x;
    if (TERMINAL_STATUSES.includes(x.status)) throw new AppError(409, "not_cancellable", `This assessment is already ${x.status.replace(/_/g, " ")}.`);
    const now = new Date();
    let next: AssessmentRow;
    if (x.status === "queued" || x.status === "draft") {
      next = (await tx.update(assessments).set({ status: "cancelled", reason: "cancelled_by_user", cancelRequestedAt: now, cancelledBy: c.principal.userId, finishedAt: now, leaseUntil: null })
        .where(eq(assessments.id, id)).returning())[0];
      await tx.update(checkRuns).set({ status: "skipped", reason: "cancelled", finishedAt: now })
        .where(and(eq(checkRuns.assessmentId, id), eq(checkRuns.status, "pending")));
      next = (await tx.update(assessments).set({ coverage: await coverageOf(tx, id) }).where(eq(assessments.id, id)).returning())[0];
    } else {
      // Running: the runner stops before its next check; the sweep finishes it if the runner is gone.
      next = (await tx.update(assessments).set({ status: "cancelling", cancelRequestedAt: now, cancelledBy: c.principal.userId })
        .where(eq(assessments.id, id)).returning())[0];
    }
    await audit(tx, { actor: userActor(c.principal), action: next.status === "cancelled" ? "assessment.cancelled" : "assessment.cancel_requested", target: { type: "assessment", id }, requestId: c.principal.requestId, details: { from: x.status } });
    return next;
  });
}

// ---------- read ----------

export async function listAssessments(c: Ctx, opts: { assetId?: string } = {}) {
  if (grantFor(c.principal.role, "asset.view") === "N") throw new AppError(403, "forbidden");
  return withOrg(c.org.id, async (tx) => {
    const q = tx.select({ assessment: assessments, asset: assets }).from(assessments).innerJoin(assets, eq(assets.id, assessments.assetId));
    const rows = await (opts.assetId && isUuid(opts.assetId) ? q.where(eq(assessments.assetId, opts.assetId)) : q).orderBy(desc(assessments.queuedAt)).limit(100);
    return rows.filter((r) => canView(c.principal, r.asset, c.org));
  });
}

export async function getAssessment(c: Ctx, id: string) {
  return withOrg(c.org.id, async (tx) => {
    if (!isUuid(id)) throw notFound();
    const x = (await tx.select().from(assessments).where(eq(assessments.id, id)))[0];
    if (!x) throw notFound();
    const a = await loadAsset(tx, x.assetId);
    if (!canView(c.principal, a, c.org)) throw notFound();
    const scope = (await tx.select().from(scopeVersions).where(eq(scopeVersions.id, x.scopeVersionId)))[0];
    const runs = await tx.select({ run: checkRuns, def: checkDefinitions }).from(checkRuns)
      .leftJoin(checkDefinitions, eq(checkDefinitions.id, checkRuns.checkId))
      .where(eq(checkRuns.assessmentId, id)).orderBy(asc(checkRuns.checkId));
    const canFindings = decide(c.principal, "finding.view", res(a), c.org).allow;
    const found = canFindings
      ? await tx.select({ finding: findings, occurrence: findingOccurrences }).from(findingOccurrences)
        .innerJoin(findings, eq(findings.id, findingOccurrences.findingId))
        .where(eq(findingOccurrences.assessmentId, id))
      : [];
    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 } as const;
    found.sort((p, q) => order[p.finding.severity] - order[q.finding.severity] || p.finding.title.localeCompare(q.finding.title));
    // Severities of everything this run found (the meter stays complete); Free lists only its top findings.
    const severities = found.map((r) => r.finding.severity);
    let shown = found;
    if (!isProOrg(c.org) && found.length) {
      const visible = await freeVisibleIds(tx, c);
      shown = found.filter((r) => visible.has(r.finding.id));
    }
    return { assessment: x, asset: a, scope, runs, findings: shown, severities, lockedFindings: found.length - shown.length, canFindings };
  });
}

/** Can the "no issues found" message be shown? Only for a completed run where every planned check succeeded. */
export function isCleanResult(x: Pick<AssessmentRow, "status" | "coverage">, findingCount: number): boolean {
  return x.status === "completed" && !!x.coverage?.complete && findingCount === 0;
}

// ---------- runner (worker side, RS-SCAN-002/003) ----------

export interface RunDeps {
  egress?: Omit<EgressDeps, "onHop">;
  dns?: DnsDeps;
  adapters?: ReadonlyMap<string, CheckAdapter>;
  now?: () => Date;
  sleep?: (ms: number) => Promise<void>;
  minIntervalMs?: number;
  /** Reads a repository at its default branch (tests inject an in-memory snapshot). */
  repoSnapshot?: (r: RepoRef) => Promise<RepoSnapshot>;
}

async function coverageOf(tx: Tx, assessmentId: string): Promise<Coverage> {
  const runs = await tx.select({ status: checkRuns.status, requestsUsed: checkRuns.requestsUsed }).from(checkRuns).where(eq(checkRuns.assessmentId, assessmentId));
  const n = (s: CheckRunStatus) => runs.filter((r) => r.status === s).length;
  const ok = n("ok");
  return {
    planned: runs.length, ok, error: n("error"), timeout: n("timeout"), skipped: n("skipped") + n("pending"),
    requests: runs.reduce((t, r) => t + r.requestsUsed, 0), complete: runs.length > 0 && ok === runs.length,
  };
}

type Stop = { status: AssessmentStatus; reason: string } | null;

/**
 * Executes one queued assessment. Network work happens outside DB transactions. Every step re-checks
 * that this worker still holds the run (attempts = mine), so a run the sweep re-queued is never written twice.
 */
export async function runAssessment(orgId: string, payload: { assessmentId?: unknown; token?: unknown }, deps: RunDeps = {}): Promise<string> {
  const now = deps.now ?? (() => new Date());
  const id = typeof payload.assessmentId === "string" ? payload.assessmentId : "";
  if (!isUuid(id)) return "invalid_payload";

  // 1. Authenticate the job and claim it.
  const claim = await withOrg(orgId, async (tx) => {
    const x = (await tx.select().from(assessments).where(eq(assessments.id, id)).for("update"))[0];
    if (!x) return { skip: "missing" as const };
    if (x.status !== "queued") return { skip: `not_queued:${x.status}` };
    const sv = (await tx.select().from(scopeVersions).where(eq(scopeVersions.id, x.scopeVersionId)))[0];
    const tok = verifyJobToken(payload.token, { org: orgId, assessment: id, sha: x.scopeSha256 }, now().getTime());
    const intact = !!sv && sv.sha256 === x.scopeSha256 && scopeSha(toScope(sv)) === x.scopeSha256;
    if (!tok.ok || !intact) {
      const reason = !intact ? "scope_integrity_failed" : `job_token_${tok.ok ? "ok" : tok.reason}`;
      await failBeforeStart(tx, x.id, "failed", reason);
      await audit(tx, { actor: RUNNER, action: "assessment.failed", target: { type: "assessment", id }, outcome: "error", reason });
      return { skip: reason };
    }
    const t = now();
    if (t < sv.windowStart) return { skip: "window_not_open" };
    const attempts = x.attempts + 1;
    const r = (await tx.update(assessments).set({ status: "running", attempts, leaseUntil: new Date(t.getTime() + LEASE_MS), startedAt: x.startedAt ?? t })
      .where(and(eq(assessments.id, id), eq(assessments.status, "queued"))).returning())[0];
    await audit(tx, { actor: RUNNER, action: "assessment.started", target: { type: "assessment", id }, details: { attempt: attempts, engineVersion: ENGINE_VERSION } });
    return { x: r, sv, attempts };
  });
  if ("skip" in claim) return claim.skip ?? "skipped";
  const { x, sv, attempts } = claim;
  const scope = toScope(sv);
  const adapters = deps.adapters ?? ADAPTERS;
  const guard = createGuard(scope, { sleep: deps.sleep, minIntervalMs: deps.minIntervalMs, now: () => now().getTime() });

  // 2. Run each pending check, re-checking authority before every one.
  let stop: Stop = null;
  let lost = false;
  const pending = await withOrg(orgId, (tx) => tx.select({ run: checkRuns, def: checkDefinitions }).from(checkRuns)
    .innerJoin(checkDefinitions, eq(checkDefinitions.id, checkRuns.checkId))
    .where(and(eq(checkRuns.assessmentId, id), eq(checkRuns.status, "pending"))).orderBy(asc(checkRuns.checkId)));

  for (const { run, def } of pending) {
    const gate = await withOrg(orgId, async (tx) => {
      const hb = await tx.update(assessments).set({ leaseUntil: new Date(now().getTime() + LEASE_MS) })
        .where(and(eq(assessments.id, id), eq(assessments.attempts, attempts), eq(assessments.status, "running"))).returning({ id: assessments.id });
      if (!hb.length) {
        const cur = (await tx.select().from(assessments).where(eq(assessments.id, id)))[0];
        if (cur?.status === "cancelling" && cur.attempts === attempts) return { stop: { status: "cancelled", reason: cur.cancelledBy ? "cancelled_by_user" : "kill_switch_engaged" } as Stop };
        return { lost: true };
      }
      const o = (await tx.select({ kill: orgs.killScanning, a2: orgs.allowIntrusiveNetwork }).from(orgs).where(eq(orgs.id, orgId)))[0];
      const a = await loadAsset(tx, x.assetId);
      if (o?.kill || a.killScanning) return { stop: { status: "cancelled", reason: "kill_switch_engaged" } as Stop };
      const atts = await tx.select().from(attestations).where(eq(attestations.assetId, a.id));
      const elig = eligibilityOf(a, atts, undefined, { a2: !!o?.a2 });
      if (!elig.eligible || !scope.classes.every((k) => (elig.allowedClasses as string[]).includes(k))) {
        return { stop: { status: "failed", reason: "authorization_lapsed" } as Stop };
      }
      let repo: RepoRef | null = null;
      if (a.kind === "repository") {
        // A repository asset is only as authorized as its integration: a disabled integration stops the run.
        const i = a.repositoryIntegrationId ? (await tx.select().from(repositoryIntegrations).where(eq(repositoryIntegrations.id, a.repositoryIntegrationId)))[0] : undefined;
        if (!i || i.status !== "active") return { stop: { status: "failed", reason: "authorization_lapsed" } as Stop };
        repo = { externalId: i.externalId, defaultBranch: i.defaultBranch };
      }
      const t = now().getTime();
      if (t >= scope.windowEnd.getTime()) return { stop: { status: "timed_out", reason: "window_ended" } as Stop };
      if (t - (x.startedAt ?? now()).getTime() >= scope.maxDurationS * 1000) return { stop: { status: "timed_out", reason: "max_duration_reached" } as Stop };
      return { go: a.host, kind: a.kind, repo };
    });
    if ("lost" in gate) { lost = true; break; }
    if ("stop" in gate) { stop = gate.stop ?? null; break; }

    const adapter = adapters.get(def.id);
    const startedAt = now();
    let result: CheckResult;
    let finished = false;
    const hop = guard.forCheck(def.id, def.requestBudget, { hostOnly: def.id.startsWith("tls.") || def.id.startsWith("net.") });
    const onHop = async (u: URL) => {
      if (finished) throw new ScopeBlocked("closed", u.toString());
      await hop(u);
    };
    let snap: RepoSnapshot | undefined;
    let pre: string | null = !adapter ? "no_adapter" : targetOf(adapter) !== targetForKind(gate.kind) ? "target_mismatch" : null;
    if (!pre && gate.repo && targetOf(adapter!) === "repository") {
      try { snap = await (deps.repoSnapshot ?? snapshotRepo)(gate.repo); } catch { pre = "repository_unreadable"; }
    }
    if (pre || !adapter) {
      result = { status: "error", reason: pre ?? "no_adapter", evidence: {} };
    } else {
      let timer: ReturnType<typeof setTimeout> | undefined;
      const timeout = new Promise<"timeout">((r) => { timer = setTimeout(() => r("timeout"), def.timeoutMs); });
      try {
        const out = await Promise.race([
          adapter.run({ host: gate.go, onHop, egress: deps.egress ?? {}, dns: deps.dns ?? {}, timeoutMs: def.timeoutMs, sleep: deps.sleep, now, repo: snap }),
          timeout,
        ]);
        result = out === "timeout" ? { status: "error", reason: "timeout", evidence: {} } : normalizeResult(out);
      } catch (e) {
        const reason = e instanceof ScopeBlocked ? `scope_blocked:${e.reason}` : e instanceof EgressError ? `egress:${e.code}` : "internal_error";
        result = { status: "error", reason, evidence: {} };
      } finally {
        clearTimeout(timer);
        finished = true;
      }
    }
    const status: CheckRunStatus = result.status === "ok" ? "ok" : result.reason === "timeout" ? "timeout" : "error";
    const blocked = guard.blocked.filter((b) => b.checkId === def.id);

    const wrote = await withOrg(orgId, async (tx) => {
      const mine = (await tx.select({ id: assessments.id }).from(assessments)
        .where(and(eq(assessments.id, id), eq(assessments.attempts, attempts), inArray(assessments.status, ["running", "cancelling"]))).for("update"))[0];
      if (!mine) return false;
      await tx.update(checkRuns).set({
        status, reason: result.status === "error" ? result.reason : null, requestsUsed: guard.requestsFor(def.id),
        engineVersion: ENGINE_VERSION, evidence: result.evidence, startedAt, finishedAt: now(),
      }).where(eq(checkRuns.id, run.id));
      if (result.status === "ok") {
        const ic = { orgId, assetId: x.assetId, assessmentId: id, checkRunId: run.id, checkKey: def.checkKey };
        for (const f of result.findings) await ingestFinding(tx, ic, f);
        await markMissed(tx, ic, result.findings.map((f) => fingerprint(def.checkKey, f.location, f.issueKey)));
        if (def.checkKey === "discovery.ct") await recordSuggestions(tx, orgId, x.assetId, result.evidence.suggestedHosts);
      }
      for (const b of blocked) {
        await audit(tx, { actor: RUNNER, action: "egress.denied", target: { type: "assessment", id }, outcome: "denied", reason: b.reason, details: { checkId: b.checkId, url: b.url } });
      }
      return true;
    });
    if (!wrote) { lost = true; break; }
  }
  guard.close();
  if (lost) return "lease_lost";

  // 3. Finish. Coverage decides the outcome; partial work is never reported as a clean completion.
  return withOrg(orgId, async (tx) => {
    const cur = (await tx.select().from(assessments).where(and(eq(assessments.id, id), eq(assessments.attempts, attempts))).for("update"))[0];
    if (!cur || !["running", "cancelling"].includes(cur.status)) return "lease_lost";
    if (!stop && cur.status === "cancelling") stop = { status: "cancelled", reason: cur.cancelledBy ? "cancelled_by_user" : "kill_switch_engaged" };
    const t = now();
    if (stop) {
      await tx.update(checkRuns).set({ status: "skipped", reason: stop.reason, finishedAt: t })
        .where(and(eq(checkRuns.assessmentId, id), eq(checkRuns.status, "pending")));
    }
    const coverage = await coverageOf(tx, id);
    const status: AssessmentStatus = stop?.status
      ?? (coverage.complete ? "completed" : coverage.ok === 0 ? "failed" : "completed_with_errors");
    const reason = stop?.reason ?? (coverage.complete ? null : coverage.ok === 0 ? "no_check_succeeded" : "some_checks_failed");
    await tx.update(assessments).set({ status, reason, coverage, finishedAt: t, leaseUntil: null }).where(eq(assessments.id, id));
    await audit(tx, {
      actor: RUNNER, action: "assessment.finished", target: { type: "assessment", id }, outcome: status === "completed" ? "success" : "error",
      reason: reason ?? undefined, details: { status, coverage, blocked: guard.blocked.length },
    });
    await queueReferralPublish(tx, orgId, cur.referralId, `assessment:${id}`);
    await queueRunFinished(tx, orgId, id);
    return status;
  });
}

async function failBeforeStart(tx: Tx, id: string, status: AssessmentStatus, reason: string) {
  const t = new Date();
  await tx.update(checkRuns).set({ status: "skipped", reason, finishedAt: t }).where(and(eq(checkRuns.assessmentId, id), eq(checkRuns.status, "pending")));
  const r = await tx.update(assessments).set({ status, reason, finishedAt: t, leaseUntil: null, coverage: await coverageOf(tx, id) }).where(eq(assessments.id, id)).returning({ orgId: assessments.orgId });
  if (r[0]) await queueRunFinished(tx, r[0].orgId, id);
}

/** Sweep (worker): kill switches, expired windows and lost leases (see sweep_assessments() in 0002). */
export async function sweepAssessments(): Promise<number> {
  const { db } = await import("../db/client");
  const r = await db.execute<{ org_id: string; assessment_id: string; from_status: string; to_status: string; reason: string }>(sql`SELECT * FROM sweep_assessments()`);
  for (const row of r.rows) {
    await withOrg(row.org_id, async (tx) => {
      if (TERMINAL_STATUSES.includes(row.to_status as AssessmentStatus)) {
        await tx.update(checkRuns).set({ status: "skipped", reason: row.reason, finishedAt: new Date() })
          .where(and(eq(checkRuns.assessmentId, row.assessment_id), eq(checkRuns.status, "pending")));
        await tx.update(assessments).set({ coverage: await coverageOf(tx, row.assessment_id) }).where(eq(assessments.id, row.assessment_id));
        await queueRunFinished(tx, row.org_id, row.assessment_id);
      } else if (row.to_status === "queued") {
        // Retry with a freshly signed token: the original message's token may already be scrubbed.
        const a = (await tx.select({ attempts: assessments.attempts, sha: assessments.scopeSha256, end: scopeVersions.windowEnd })
          .from(assessments).innerJoin(scopeVersions, eq(scopeVersions.id, assessments.scopeVersionId))
          .where(eq(assessments.id, row.assessment_id)))[0];
        const token = signJobToken({ org: row.org_id, assessment: row.assessment_id, sha: a.sha, exp: a.end.getTime() });
        await enqueue(tx, { orgId: row.org_id, topic: "assessment.run", businessKey: `assessment:${row.assessment_id}:${a.attempts + 1}`, payload: { assessmentId: row.assessment_id, token } });
      }
      await audit(tx, { actor: { type: "service", id: "assessment-sweeper" }, action: "assessment.swept", target: { type: "assessment", id: row.assessment_id }, reason: row.reason, details: { from: row.from_status, to: row.to_status } });
    });
  }
  return r.rows.length;
}

/** Checks shown in the launch form. Prohibited checks are listed but never selectable; A2 is selectable only where the asset's eligibility allows it. */
export async function listCatalogue(c: Ctx, kind?: string) {
  return withOrg(c.org.id, async (tx) => (await tx.select().from(checkDefinitions).orderBy(asc(checkDefinitions.class), asc(checkDefinitions.id)))
    .filter((d) => !kind || !ADAPTERS.has(d.id) || fitsKind(d.id, kind))
    .map((d) => ({ ...d, launchable: d.enabled && ADAPTERS.has(d.id) && (d.class === "P" || d.class === "A1" || d.class === "A2") })));
}
