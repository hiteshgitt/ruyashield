import { randomUUID } from "node:crypto";
import { and, asc, desc, eq, inArray, isNull, lt, sql } from "drizzle-orm";
import { z } from "zod";
import { db, withOrg, isUuid, type Tx } from "../db/client";
import {
  assets, attestations, checkDefinitions, repositoryIntegrations, checkRuns, evidenceItems, findings, fixproofRecords, memberships, orgs, verificationRuns,
  type CheckVerdict, type VerificationCheckResult, type VerificationOutcome,
} from "../db/schema";
import { audit, type Actor } from "../audit/audit";
import { AppError, isAppError, notFound } from "../errors";
import { authorize, decide, type OrgFlags, type Principal, type Resource } from "../policy/policy";
import { enqueue } from "../outbox/outbox";
import { EgressError } from "../net/egress";
import { eligibilityOf } from "../assets/assets";
import { createGuard, ScopeBlocked } from "../assessments/guard";
import type { Scope } from "../assessments/scope";
import { ADAPTERS, ENGINE_VERSION, fingerprint, normalizeResult, targetForKind, targetOf, type CheckResult } from "../assessments/checks";
import { snapshotRepo, type RepoRef, type RepoSnapshot } from "../remediation/repo";
import type { RunDeps } from "../assessments/assessments";
import { canonicalJson, sha256, storeEvidence } from "../findings/evidence";
import { notify, recordTransition } from "../findings/record";
import { systemTransitionAllowed } from "../findings/lifecycle";
import { textPdf } from "@/server/pdf";

type Ctx = { principal: Principal; org: OrgFlags & { id: string } };
type FindingRow = typeof findings.$inferSelect;
type AssetRow = typeof assets.$inferSelect;
type DefRow = typeof checkDefinitions.$inferSelect;
type RunRow = typeof verificationRuns.$inferSelect;
type FixProofRow = typeof fixproofRecords.$inferSelect;

export const FIXPROOF_FORMAT = "ruyashield.fixproof/1";
export const RUN_LEASE_MS = 10 * 60_000;
const VERIFIER: Actor = { type: "service", id: "verification-runner" };
const userActor = (p: Principal) => ({ type: "user" as const, id: p.userId, ip: p.ip });
const res = (f: FindingRow, a: AssetRow): Resource => ({ type: "finding", id: f.id, clientGroupId: a.clientGroupId, ownerId: f.ownerId });
const LIMITATIONS = [
  "Verifies only the listed checks against the listed asset at the stated time.",
  "It is not a statement that the asset is free of other issues, and later changes to the asset are not covered.",
  "Evidence was captured from the target and is untrusted content; it was redacted before hashing.",
];

async function loadFinding(tx: Tx, c: Ctx, id: string, lock = false) {
  if (!isUuid(id)) throw notFound();
  const q = tx.select().from(findings).where(eq(findings.id, id));
  const f = (lock ? await q.for("update") : await q)[0];
  if (!f) throw notFound();
  const a = (await tx.select().from(assets).where(eq(assets.id, f.assetId)))[0];
  if (!a || !decide(c.principal, "finding.view", res(f, a), c.org).allow) throw notFound();
  return { f, a };
}

/** Checks that can re-test a finding: same check key, enabled, marked verification-capable, with a runnable adapter. */
export async function verifiableChecks(tx: Tx, f: FindingRow) {
  const defs = await tx.select().from(checkDefinitions).where(eq(checkDefinitions.checkKey, f.checkKey)).orderBy(asc(checkDefinitions.id));
  return {
    usable: defs.filter((d) => d.enabled && d.verificationSupported && ADAPTERS.has(d.id)),
    notUsable: defs.filter((d) => !(d.enabled && d.verificationSupported && ADAPTERS.has(d.id))),
  };
}

// ---------- pure decision logic (RS-VERIF-002, RS-VERIF-003) ----------

/** One check's verdict. Absence of the issue only counts as "passed" when the check looked at the same place. */
export function classify(f: { fingerprint: string; location: string }, checkKey: string, r: CheckResult): CheckVerdict {
  if (r.status === "error") return "error";
  if (r.findings.some((c) => fingerprint(checkKey, c.location, c.issueKey) === f.fingerprint)) return "failed";
  const ev = r.evidence as Record<string, unknown> | null;
  const finalUrl = ev?.finalUrl;
  // A check may judge more than one URL (e.g. the plain-HTTP probe); it lists them in checkedLocations.
  const checked = Array.isArray(ev?.checkedLocations) ? (ev.checkedLocations as unknown[]) : [];
  if (typeof finalUrl === "string" && finalUrl !== f.location && !checked.includes(f.location)) return "inconclusive";
  return "passed";
}

/** The run outcome. Errors and inconclusive checks never count as a pass. */
export function mapResults(verdicts: readonly CheckVerdict[]): VerificationOutcome {
  if (!verdicts.length) return "unverified";
  if (verdicts.includes("failed")) return "failed";
  if (verdicts.every((v) => v === "passed")) return "verified";
  if (verdicts.includes("passed")) return "partially_verified";
  return "unverified";
}

// ---------- request (RS-VERIF-001) ----------

const requestInput = z.object({ idempotencyKey: z.string().min(8).max(100) });

export async function requestVerification(c: Ctx, findingId: string, input: unknown) {
  const parsed = requestInput.safeParse(input ?? {});
  if (!parsed.success) throw new AppError(422, "invalid_request", "A request key is required.");
  const { idempotencyKey } = parsed.data;
  const actor = userActor(c.principal);
  try {
    return await withOrg(c.org.id, async (tx) => {
      const { f, a } = await loadFinding(tx, c, findingId, true);
      await authorize(c.principal, "verification.request", res(f, a), c.org);

      const prior = (await tx.select().from(verificationRuns).where(eq(verificationRuns.idempotencyKey, idempotencyKey)))[0];
      if (prior) {
        if (prior.findingId !== f.id) throw new AppError(409, "idempotency_conflict", "This request key was already used for another finding.");
        return { run: prior, replayed: true };
      }
      if (f.status !== "fix_pending_verification") {
        throw new AppError(422, "verification_not_allowed", "Only findings marked “fix applied” can be re-tested.");
      }
      const o = (await tx.select({ kill: orgs.killScanning, a2: orgs.allowIntrusiveNetwork }).from(orgs).where(eq(orgs.id, c.org.id)))[0];
      if (o?.kill || a.killScanning) {
        await audit(tx, { actor, action: "authz.denied", target: { type: "asset", id: a.id }, outcome: "denied", reason: "kill_switch_engaged", requestId: c.principal.requestId, details: { attempted: "verification.request", findingId: f.id } });
        throw new AppError(423, "kill_switch_engaged", "Scanning is stopped for this asset.");
      }
      const { usable } = await verifiableChecks(tx, f);
      if (!usable.length) throw new AppError(422, "check_unsupported", "No available check can re-test this finding automatically.");
      const elig = eligibilityOf(a, await tx.select().from(attestations).where(eq(attestations.assetId, a.id)), undefined, { a2: !!o?.a2 });
      if (!elig.eligible || !usable.every((d) => (elig.allowedClasses as string[]).includes(d.class))) {
        throw new AppError(403, "authorization_required", elig.eligible ? "This asset's authorization does not cover the re-test's check class." : elig.reason);
      }
      const active = await tx.select({ id: verificationRuns.id }).from(verificationRuns)
        .where(and(eq(verificationRuns.findingId, f.id), inArray(verificationRuns.status, ["queued", "running"])));
      if (active.length) throw new AppError(409, "verification_active", "A re-test is already queued or running for this finding.");

      const id = randomUUID();
      const run = (await tx.insert(verificationRuns).values({
        id, orgId: c.org.id, findingId: f.id, assetId: a.id, requestedBy: c.principal.userId, idempotencyKey,
      }).returning())[0];
      await enqueue(tx, { orgId: c.org.id, topic: "verification.run", businessKey: `verification:${id}:1`, payload: { runId: id } });
      await audit(tx, {
        actor, action: "verification.requested", target: { type: "verification", id }, requestId: c.principal.requestId,
        details: { findingId: f.id, assetId: a.id, host: a.host, checks: usable.map((d) => d.id), basis: elig.basis },
      });
      return { run, replayed: false };
    });
  } catch (e) {
    if (isAppError(e) && ["verification_not_allowed", "check_unsupported", "authorization_required", "verification_active"].includes(e.code)) {
      await withOrg(c.org.id, (tx) => audit(tx, {
        actor, action: "verification.rejected", target: isUuid(findingId) ? { type: "finding", id: findingId } : null, outcome: "denied",
        reason: e.code, requestId: c.principal.requestId, details: { message: e.message },
      }));
    }
    throw e;
  }
}

// ---------- run (worker) ----------

export async function runVerification(orgId: string, payload: { runId?: unknown }, deps: RunDeps = {}): Promise<string> {
  const now = deps.now ?? (() => new Date());
  const id = typeof payload.runId === "string" ? payload.runId : "";
  if (!isUuid(id)) return "invalid_payload";

  const claim = await withOrg(orgId, async (tx) => {
    const run = (await tx.select().from(verificationRuns).where(eq(verificationRuns.id, id)).for("update"))[0];
    if (!run) return { skip: "missing" };
    if (run.status !== "queued") return { skip: `not_queued:${run.status}` };
    const r = (await tx.update(verificationRuns).set({ status: "running", attempts: run.attempts + 1, startedAt: now() })
      .where(eq(verificationRuns.id, id)).returning())[0];
    await audit(tx, { actor: VERIFIER, action: "verification.started", target: { type: "verification", id }, details: { findingId: run.findingId, engineVersion: ENGINE_VERSION } });
    const f = (await tx.select().from(findings).where(eq(findings.id, run.findingId)))[0];
    return { run: r, f, ...(await verifiableChecks(tx, f)) };
  });
  if ("skip" in claim) return claim.skip ?? "skipped";
  const { run, f, usable, notUsable } = claim;
  // A scheduled re-test only makes sense while the fix stands as verified; a person may have changed it since.
  if (run.trigger === "scheduled_regression" && f.status !== "resolved_verified") return finishNotRun(orgId, run, "finding_state_changed", now);
  if (!usable.length) return finishNotRun(orgId, run, "check_unsupported", now);

  const detectionVersion = await withOrg(orgId, async (tx) => {
    if (!f.latestEvidenceId) return null;
    const row = (await tx.select({ v: checkRuns.engineVersion }).from(evidenceItems)
      .innerJoin(checkRuns, eq(checkRuns.id, evidenceItems.checkRunId)).where(eq(evidenceItems.id, f.latestEvidenceId)))[0];
    return row?.v ?? null;
  });

  const start = now();
  const asset = await withOrg(orgId, async (tx) => (await tx.select().from(assets).where(eq(assets.id, run.assetId)))[0]);
  const scope: Scope = {
    hosts: [asset.host], basePaths: ["/"], excludedPaths: [], checkIds: usable.map((d) => d.id), classes: [...new Set(usable.map((d) => d.class))] as Scope["classes"],
    windowStart: start, windowEnd: new Date(start.getTime() + 3_600_000), maxRequests: usable.reduce((n, d) => n + d.requestBudget, 0), maxDurationS: 600,
  };
  const adapters = deps.adapters ?? ADAPTERS;
  const guard = createGuard(scope, { sleep: deps.sleep, minIntervalMs: deps.minIntervalMs, now: () => now().getTime() });
  const results: VerificationCheckResult[] = [];

  for (const def of usable) {
    // Authority is re-checked before every check: a kill switch or lapsed authorization stops the re-test.
    const gate = await withOrg(orgId, async (tx) => {
      const o = (await tx.select({ kill: orgs.killScanning, a2: orgs.allowIntrusiveNetwork }).from(orgs).where(eq(orgs.id, orgId)))[0];
      const a = (await tx.select().from(assets).where(eq(assets.id, run.assetId)))[0];
      if (!a || o?.kill || a.killScanning) return { stop: "kill_switch_engaged" };
      const elig = eligibilityOf(a, await tx.select().from(attestations).where(eq(attestations.assetId, a.id)), undefined, { a2: !!o?.a2 });
      if (!elig.eligible || !(elig.allowedClasses as string[]).includes(def.class)) return { stop: "authorization_lapsed" };
      if (now().getTime() - start.getTime() >= scope.maxDurationS * 1000) return { stop: "max_duration_reached" };
      let repo: RepoRef | null = null;
      if (a.kind === "repository") {
        const i = a.repositoryIntegrationId ? (await tx.select().from(repositoryIntegrations).where(eq(repositoryIntegrations.id, a.repositoryIntegrationId)))[0] : undefined;
        if (!i || i.status !== "active") return { stop: "authorization_lapsed" };
        repo = { externalId: i.externalId, defaultBranch: i.defaultBranch };
      }
      return { host: a.host, kind: a.kind, repo };
    });
    if ("stop" in gate) {
      guard.close();
      // Nothing is concluded from a partial re-test that authority stopped.
      return finishNotRun(orgId, run, gate.stop ?? "stopped", now, results);
    }

    const result = await runCheck(def, gate, guard, adapters, deps, now);
    const verdict = classify(f, def.checkKey, result);
    const blocked = guard.blocked.filter((b) => b.checkId === def.id);
    const ev = await withOrg(orgId, async (tx) => {
      const stored = await storeEvidence(tx, {
        orgId, body: {
          kind: "verification", verificationRunId: run.id, findingId: f.id, checkId: def.id, engineVersion: ENGINE_VERSION,
          status: result.status, reason: result.status === "error" ? result.reason : null, evidence: result.evidence,
          findings: result.status === "ok" ? result.findings : [],
        },
      });
      for (const b of blocked) {
        await audit(tx, { actor: VERIFIER, action: "egress.denied", target: { type: "verification", id: run.id }, outcome: "denied", reason: b.reason, details: { checkId: b.checkId, url: b.url } });
      }
      return stored;
    });
    results.push({
      checkId: def.id, engineVersion: ENGINE_VERSION, status: verdict,
      reason: result.status === "error" ? result.reason : verdict === "inconclusive" ? "different_location_checked" : null,
      evidenceId: ev.id, evidenceSha256: ev.sha256,
      sameVersionAsDetection: detectionVersion === null ? null : detectionVersion === ENGINE_VERSION,
      requests: guard.requestsFor(def.id),
    });
  }
  guard.close();
  return finishCompleted(orgId, run, f, usable, notUsable, results, now);
}

async function runCheck(def: DefRow, t: { host: string; kind: string; repo: RepoRef | null }, guard: ReturnType<typeof createGuard>, adapters: NonNullable<RunDeps["adapters"]>, deps: RunDeps, now: () => Date): Promise<CheckResult> {
  const adapter = adapters.get(def.id);
  if (!adapter) return { status: "error", reason: "no_adapter", evidence: {} };
  if (targetOf(adapter) !== targetForKind(t.kind)) return { status: "error", reason: "target_mismatch", evidence: {} };
  let repo: RepoSnapshot | undefined;
  if (t.repo && targetOf(adapter) === "repository") {
    // Re-tests read the default branch as it is now, so a merged fix is what gets verified.
    try { repo = await (deps.repoSnapshot ?? snapshotRepo)(t.repo); } catch { return { status: "error", reason: "repository_unreadable", evidence: {} }; }
  }
  const host = t.host;
  let finished = false;
  const hop = guard.forCheck(def.id, def.requestBudget, { hostOnly: def.id.startsWith("tls.") || def.id.startsWith("net.") });
  const onHop = async (u: URL) => {
    if (finished) throw new ScopeBlocked("closed", u.toString());
    await hop(u);
  };
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<"timeout">((r) => { timer = setTimeout(() => r("timeout"), def.timeoutMs); });
  try {
    const out = await Promise.race([
      adapter.run({ host, onHop, egress: deps.egress ?? {}, dns: deps.dns ?? {}, timeoutMs: def.timeoutMs, sleep: deps.sleep, now, repo }),
      timeout,
    ]);
    return out === "timeout" ? { status: "error", reason: "timeout", evidence: {} } : normalizeResult(out);
  } catch (e) {
    const reason = e instanceof ScopeBlocked ? `scope_blocked:${e.reason}` : e instanceof EgressError ? `egress:${e.code}` : "internal_error";
    return { status: "error", reason, evidence: {} };
  } finally {
    clearTimeout(timer);
    finished = true;
  }
}

async function finishNotRun(orgId: string, run: RunRow, reason: string, now: () => Date, results: VerificationCheckResult[] = []) {
  return withOrg(orgId, async (tx) => {
    const r = await tx.update(verificationRuns).set({ status: "not_run", outcome: null, reason, results, finishedAt: now() })
      .where(and(eq(verificationRuns.id, run.id), eq(verificationRuns.status, "running"))).returning({ id: verificationRuns.id });
    if (!r.length) return "lease_lost";
    await audit(tx, { actor: VERIFIER, action: "verification.not_run", target: { type: "verification", id: run.id }, outcome: "denied", reason, details: { findingId: run.findingId, checksAttempted: results.length } });
    return `not_run:${reason}`;
  });
}

/** Who hears about a scheduled re-test: the finding owner, else an org admin (scheduled runs have no requester). */
async function regressionRecipient(tx: Tx, orgId: string, f: FindingRow): Promise<string | null> {
  if (f.ownerId) return f.ownerId;
  return (await tx.select({ id: memberships.userId }).from(memberships)
    .where(and(eq(memberships.orgId, orgId), eq(memberships.role, "org_admin"))).orderBy(asc(memberships.createdAt)).limit(1))[0]?.id ?? null;
}

async function finishCompleted(orgId: string, run: RunRow, f0: FindingRow, usable: DefRow[], notUsable: DefRow[], results: VerificationCheckResult[], now: () => Date) {
  const outcome = mapResults(results.map((r) => r.status));
  const regression = run.trigger === "scheduled_regression";
  return withOrg(orgId, async (tx) => {
    const mine = (await tx.select().from(verificationRuns).where(and(eq(verificationRuns.id, run.id), eq(verificationRuns.status, "running"))).for("update"))[0];
    if (!mine) return "lease_lost";
    const f = (await tx.select().from(findings).where(eq(findings.id, f0.id)).for("update"))[0];
    const t = now();

    // An inconclusive scheduled re-test proves nothing either way: the standing FixProof is kept, the status is
    // unchanged, and someone is told it could not be confirmed. It is never shown as a pass.
    if (regression && (outcome === "unverified" || outcome === "partially_verified")) {
      await tx.update(verificationRuns).set({ status: "completed", outcome, results, fixproofId: null, finishedAt: t, reason: null }).where(eq(verificationRuns.id, run.id));
      await notify(tx, { orgId, userId: await regressionRecipient(tx, orgId, f), findingId: f.id, kind: "regression_inconclusive" });
      await audit(tx, {
        actor: VERIFIER, action: "verification.completed", target: { type: "verification", id: run.id }, outcome: "error", reason: outcome,
        details: { findingId: f.id, trigger: run.trigger, fixproofId: null, checks: results.map((r) => ({ id: r.checkId, status: r.status })), findingStatus: f.status },
      });
      await audit(tx, { actor: VERIFIER, action: "verification.inconclusive", target: { type: "verification", id: run.id }, outcome: "error", reason: outcome, details: { findingId: f.id, trigger: run.trigger } });
      return `completed:${outcome}`;
    }

    // FixProof chain: one writer per org at a time so seq and prev_sha256 stay consistent.
    await tx.execute(sql`select pg_advisory_xact_lock(hashtext(${"fixproof:" + orgId}))`);
    const seq = (await tx.select({ n: sql<number>`coalesce(max(${fixproofRecords.seq}), 0)::int + 1` }).from(fixproofRecords))[0].n;
    const prev = (await tx.select({ sha: fixproofRecords.sha256 }).from(fixproofRecords).orderBy(desc(fixproofRecords.seq)).limit(1))[0]?.sha ?? null;
    const version = (await tx.select({ n: sql<number>`coalesce(max(${fixproofRecords.version}), 0)::int + 1` }).from(fixproofRecords).where(eq(fixproofRecords.findingId, f.id)))[0].n;
    const titles = new Map(usable.map((d) => [d.id, d.title]));
    const fpId = randomUUID();
    // Dynamic import: remediation/plans imports this module.
    const remed = await import("../remediation/approvals");
    const { remediation, aiInvolvement } = await remed.remediationForFixProof(tx, f.id);
    const content = {
      format: FIXPROOF_FORMAT, id: fpId, orgId, seq, version, findingId: f.id, verificationRunId: run.id, status: outcome,
      prevSha256: prev, createdAt: t.toISOString(),
      requested: regression ? { by: null, trigger: run.trigger, at: run.createdAt.toISOString() } : { by: run.requestedBy, at: run.createdAt.toISOString() },
      tested: { from: (mine.startedAt ?? t).toISOString(), to: t.toISOString(), engineVersion: ENGINE_VERSION },
      finding: { title: f.title, severity: f.severity, location: f.location, checkKey: f.checkKey, fingerprint: f.fingerprint },
      originalEvidence: f.latestEvidenceId ? { id: f.latestEvidenceId } : null,
      remediation,
      checks: results.map((r) => ({ ...r, title: titles.get(r.checkId) ?? r.checkId })),
      notTested: notUsable.map((d) => ({ checkId: d.id, title: d.title, reason: !d.enabled ? "disabled" : !d.verificationSupported ? "verification_not_supported" : "no_adapter" })),
      limitations: LIMITATIONS,
      aiInvolvement,
    };
    const hash = sha256(canonicalJson(content));
    await tx.update(fixproofRecords).set({ supersededAt: t, supersededReason: regression && outcome === "failed" ? "regression" : "newer_verification" })
      .where(and(eq(fixproofRecords.findingId, f.id), isNull(fixproofRecords.supersededAt)));
    await tx.insert(fixproofRecords).values({
      id: fpId, orgId, seq, findingId: f.id, verificationRunId: run.id, version, status: outcome, content, sha256: hash, prevSha256: prev, createdAt: t,
    });
    await tx.update(verificationRuns).set({ status: "completed", outcome, results, fixproofId: fpId, finishedAt: t, reason: null }).where(eq(verificationRuns.id, run.id));
    await audit(tx, { actor: VERIFIER, action: "fixproof.created", target: { type: "fixproof", id: fpId }, details: { findingId: f.id, verificationRunId: run.id, version, seq, status: outcome, sha256: hash } });

    // Only a verified run resolves the finding; only a confirmed re-detection reopens it.
    const to = outcome === "verified" ? "resolved_verified" as const : outcome === "failed" ? "reopened" as const : null;
    let transitioned = false;
    if (regression) {
      // A passing regression re-test keeps the status; a confirmed re-detection reopens the verified fix.
      if (outcome === "failed" && f.status === "resolved_verified" && systemTransitionAllowed(f.status, "reopened", "regression")) {
        await recordTransition(tx, { orgId, findingId: f.id, from: f.status, to: "reopened", actor: VERIFIER, reason: "regression", details: { verificationRunId: run.id, fixproofId: fpId } });
        transitioned = true;
        await notify(tx, { orgId, userId: await regressionRecipient(tx, orgId, f), findingId: f.id, kind: "regression" });
      }
    } else {
      const why = outcome === "verified" ? "verified_fixed" as const : "verification_failed" as const;
      if (to && f.status === "fix_pending_verification" && systemTransitionAllowed(f.status, to, why)) {
        await recordTransition(tx, { orgId, findingId: f.id, from: f.status, to, actor: VERIFIER, reason: why, details: { verificationRunId: run.id, fixproofId: fpId } });
        transitioned = true;
        if (to === "reopened") await notify(tx, { orgId, userId: f.ownerId ?? run.requestedBy, findingId: f.id, kind: "verification_failed" });
      }
      // Plans waiting on this re-test complete only when it verified the fix; anything else marks them failed.
      await remed.settlePlansAfterVerification(tx, f.id, outcome === "verified", run.id);
    }
    // A referred assessment's link-back is refreshed with the new FixProof status, if the customer agreed to share it.
    const wm = await import("../webmonitor/referrals");
    for (const referralId of await wm.referralsForFinding(tx, f.id)) await wm.queueReferralPublish(tx, orgId, referralId, `fixproof:${fpId}`);
    await audit(tx, {
      actor: VERIFIER, action: "verification.completed", target: { type: "verification", id: run.id },
      outcome: outcome === "verified" ? "success" : outcome === "failed" ? "denied" : "error", reason: outcome,
      details: { findingId: f.id, trigger: run.trigger, fixproofId: fpId, checks: results.map((r) => ({ id: r.checkId, status: r.status })), findingStatus: transitioned ? (regression ? "reopened" : to) : f.status },
    });
    if (outcome === "unverified" || outcome === "partially_verified") {
      await audit(tx, { actor: VERIFIER, action: "verification.inconclusive", target: { type: "verification", id: run.id }, outcome: "error", reason: outcome, details: { findingId: f.id } });
    }
    return `completed:${outcome}`;
  });
}

/** A run whose worker died stays "running"; after the lease it is closed as not_run so a new re-test can be requested. */
export async function sweepVerifications(now = new Date()): Promise<number> {
  const before = new Date(now.getTime() - RUN_LEASE_MS);
  const stuck = await db.execute<{ id: string; org_id: string }>(sql`SELECT * FROM stuck_verification_runs(${before.toISOString()}::timestamptz)`);
  let n = 0;
  for (const row of stuck.rows) {
    n += await withOrg(row.org_id, async (tx) => {
      const u = await tx.update(verificationRuns).set({ status: "not_run", reason: "runner_lost", finishedAt: now })
        .where(and(eq(verificationRuns.id, row.id), eq(verificationRuns.status, "running"), lt(verificationRuns.startedAt, before)))
        .returning({ findingId: verificationRuns.findingId });
      if (u.length) await audit(tx, { actor: VERIFIER, action: "verification.not_run", target: { type: "verification", id: row.id }, outcome: "error", reason: "runner_lost", details: { findingId: u[0].findingId } });
      return u.length;
    });
  }
  return n;
}

// ---------- scheduled regression re-tests (RS-FIXP-006) ----------

const REGRESSION_ACTOR: Actor = { type: "service", id: "regression-scheduler" };

/**
 * Queues a re-test for each verified-fixed finding whose org has a regression interval and whose last re-test is
 * older than it. The same authority gates as a manual re-test apply; if they fail, a not_run record is written and a
 * person is told, so a skipped re-test is never mistaken for a pass. Called by the worker's sweep.
 */
export async function scheduleRegressions(now = new Date()): Promise<{ queued: number; notRun: number }> {
  const due = await db.execute<{ org_id: string; finding_id: string }>(sql`SELECT * FROM due_regression_checks(${now.toISOString()}::timestamptz)`);
  const day = now.toISOString().slice(0, 10);
  let queued = 0, notRun = 0;
  for (const row of due.rows) {
    const r = await withOrg(row.org_id, async (tx) => {
      const f = (await tx.select().from(findings).where(eq(findings.id, row.finding_id)).for("update"))[0];
      if (!f || f.status !== "resolved_verified") return null;
      const a = (await tx.select().from(assets).where(eq(assets.id, f.assetId)))[0];
      const o = (await tx.select({ kill: orgs.killScanning, a2: orgs.allowIntrusiveNetwork }).from(orgs).where(eq(orgs.id, row.org_id)))[0];
      const { usable } = await verifiableChecks(tx, f);
      const elig = eligibilityOf(a, await tx.select().from(attestations).where(eq(attestations.assetId, a.id)), undefined, { a2: !!o?.a2 });
      const reason = o?.kill || a.killScanning ? "kill_switch_engaged"
        : !usable.length ? "check_unsupported"
        : !elig.eligible || !usable.every((d) => (elig.allowedClasses as string[]).includes(d.class)) ? "authorization_lapsed" : null;
      const id = randomUUID();
      const inserted = await tx.insert(verificationRuns).values({
        id, orgId: row.org_id, findingId: f.id, assetId: a.id, requestedBy: null, trigger: "scheduled_regression",
        idempotencyKey: `regression:${f.id}:${day}`,
        ...(reason ? { status: "not_run" as const, reason, finishedAt: now } : {}),
      }).onConflictDoNothing().returning({ id: verificationRuns.id });
      if (!inserted.length) return null;
      if (reason) {
        await notify(tx, { orgId: row.org_id, userId: await regressionRecipient(tx, row.org_id, f), findingId: f.id, kind: "regression_not_run" });
        await audit(tx, { actor: REGRESSION_ACTOR, action: "verification.not_run", target: { type: "verification", id }, outcome: "denied", reason, details: { findingId: f.id, trigger: "scheduled_regression" } });
        return "not_run" as const;
      }
      await enqueue(tx, { orgId: row.org_id, topic: "verification.run", businessKey: `verification:${id}:1`, payload: { runId: id } });
      await audit(tx, {
        actor: REGRESSION_ACTOR, action: "verification.requested", target: { type: "verification", id },
        details: { findingId: f.id, assetId: a.id, host: a.host, checks: usable.map((d) => d.id), basis: elig.basis, trigger: "scheduled_regression" },
      });
      return "queued" as const;
    });
    if (r === "queued") queued++;
    else if (r === "not_run") notRun++;
  }
  return { queued, notRun };
}

// ---------- FixProof read, integrity and export (RS-FIXP-002..004, RS-FIXP-006) ----------

export type FixProofIntegrity = { ok: boolean; hash: boolean; fields: boolean; chain: boolean | null };

/** Recomputes the record's hash, checks the row agrees with its content, and checks the link to the previous record. */
export function verifyFixProof(row: Pick<FixProofRow, "content" | "sha256" | "prevSha256" | "id" | "seq" | "version" | "status" | "findingId" | "verificationRunId">, prev: { sha256: string } | null | undefined): FixProofIntegrity {
  const c = row.content as Record<string, unknown>;
  const hash = sha256(canonicalJson(c)) === row.sha256;
  const fields = c.id === row.id && c.seq === row.seq && c.version === row.version && c.status === row.status
    && c.findingId === row.findingId && c.verificationRunId === row.verificationRunId && (c.prevSha256 ?? null) === (row.prevSha256 ?? null);
  const chain = row.seq === 1 ? row.prevSha256 === null : prev === undefined ? null : !!prev && prev.sha256 === row.prevSha256;
  return { ok: hash && fields && chain !== false, hash, fields, chain };
}

async function loadFixProof(tx: Tx, c: Ctx, id: string) {
  if (!isUuid(id)) throw notFound();
  const row = (await tx.select().from(fixproofRecords).where(eq(fixproofRecords.id, id)))[0];
  if (!row) throw notFound();
  const { f, a } = await loadFinding(tx, c, row.findingId);
  const prev = row.seq > 1 ? (await tx.select({ sha256: fixproofRecords.sha256 }).from(fixproofRecords).where(eq(fixproofRecords.seq, row.seq - 1)))[0] ?? null : null;
  return { row, f, a, integrity: verifyFixProof(row, prev) };
}

async function integrityFailed(c: Ctx, row: FixProofRow, integrity: FixProofIntegrity) {
  await withOrg(c.org.id, (tx) => audit(tx, {
    actor: userActor(c.principal), action: "fixproof.integrity_failed", target: { type: "fixproof", id: row.id }, outcome: "error",
    requestId: c.principal.requestId, details: { findingId: row.findingId, expected: row.sha256, ...integrity },
  }));
}

export async function getFixProof(c: Ctx, id: string) {
  const { row, f, a, integrity } = await withOrg(c.org.id, (tx) => loadFixProof(tx, c, id));
  await authorize(c.principal, "fixproof.view", res(f, a), c.org);
  if (!integrity.ok) await integrityFailed(c, row, integrity);
  return {
    id: row.id, findingId: row.findingId, version: row.version, seq: row.seq, status: row.status, sha256: row.sha256, prevSha256: row.prevSha256,
    createdAt: row.createdAt, supersededAt: row.supersededAt, supersededReason: row.supersededReason, integrity,
    content: integrity.ok ? row.content : null,
  };
}

export async function exportFixProof(c: Ctx, id: string, format: string) {
  if (format !== "json" && format !== "pdf") throw new AppError(422, "invalid_format", "Format must be json or pdf.");
  const { row, f, a, integrity } = await withOrg(c.org.id, (tx) => loadFixProof(tx, c, id));
  await authorize(c.principal, "fixproof.view", res(f, a), c.org);
  if (!integrity.ok) {
    await integrityFailed(c, row, integrity);
    throw new AppError(409, "fixproof_integrity_failed", "This FixProof record failed its integrity check and cannot be exported.");
  }
  await withOrg(c.org.id, (tx) => audit(tx, {
    actor: userActor(c.principal), action: "fixproof.exported", target: { type: "fixproof", id: row.id }, requestId: c.principal.requestId,
    details: { findingId: row.findingId, format, sha256: row.sha256 },
  }));
  const name = `fixproof-${row.findingId.slice(0, 8)}-v${row.version}`;
  if (format === "json") {
    return { filename: `${name}.json`, contentType: "application/json", body: JSON.stringify({ format: FIXPROOF_FORMAT, record: row.content, sha256: row.sha256 }, null, 2) };
  }
  return { filename: `${name}.pdf`, contentType: "application/pdf", body: fixProofPdf(row) };
}

/** Run history and FixProof records for the finding page. */
export async function listVerifications(c: Ctx, findingId: string) {
  return withOrg(c.org.id, async (tx) => {
    const { f, a } = await loadFinding(tx, c, findingId);
    const r = res(f, a);
    const runs = await tx.select().from(verificationRuns).where(eq(verificationRuns.findingId, f.id)).orderBy(desc(verificationRuns.createdAt)).limit(20);
    const canProof = decide(c.principal, "fixproof.view", r, c.org).allow;
    const records = canProof ? await tx.select().from(fixproofRecords).where(eq(fixproofRecords.findingId, f.id)).orderBy(desc(fixproofRecords.version)) : [];
    const active = records.find((x) => !x.supersededAt) ?? null;
    let integrity: FixProofIntegrity | null = null;
    if (active) {
      const prev = active.seq > 1 ? (await tx.select({ sha256: fixproofRecords.sha256 }).from(fixproofRecords).where(eq(fixproofRecords.seq, active.seq - 1)))[0] ?? null : null;
      integrity = verifyFixProof(active, prev);
    }
    const { usable } = await verifiableChecks(tx, f);
    return {
      runs, records, active, integrity, supported: usable.map((d) => ({ id: d.id, title: d.title })),
      can: { request: decide(c.principal, "verification.request", r, c.org).allow, viewProof: canProof },
    };
  });
}

function fixProofPdf(row: FixProofRow): Buffer {
  const c = row.content as Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
  const lines: string[] = [
    "RuyaShield FixProof record", "",
    `Status: ${c.status}    Version ${c.version}    Record #${c.seq}`,
    `Created: ${c.createdAt}`,
    `Finding: ${c.finding?.title} (${c.finding?.severity})`,
    `Location: ${c.finding?.location}`,
    `Check key: ${c.finding?.checkKey}`,
    `Tested: ${c.tested?.from} to ${c.tested?.to} (engine ${c.tested?.engineVersion})`, "",
    "Checks run:",
    ...(c.checks ?? []).flatMap((k: VerificationCheckResult & { title: string }) => [
      `  - ${k.title} [${k.checkId}]: ${k.status}${k.reason ? ` (${k.reason})` : ""}`,
      `    evidence sha256 ${k.evidenceSha256 ?? "none"}; requests ${k.requests}; same engine as detection: ${k.sameVersionAsDetection ?? "unknown"}`,
    ]),
    "", "Not tested:",
    ...((c.notTested ?? []).length ? c.notTested.map((n: { title: string; reason: string }) => `  - ${n.title}: ${n.reason}`) : ["  - (no other checks for this issue)"]),
    `Remediation: ${c.remediation?.note ?? "not recorded"}`,
    ...(Array.isArray(c.remediation?.recorded) ? c.remediation.recorded.map((r: { type: string; title: string; version: number; contentSha256: string; approval: { policy: string; selfApproved: boolean; untestedOverride: boolean } | null; change: { branch: string; mergeSha: string | null } | null }) =>
      `  - ${r.type} plan "${r.title}" v${r.version} (${r.contentSha256.slice(0, 16)}); approval: ${r.approval ? `${r.approval.policy}${r.approval.selfApproved ? ", self-approved" : ""}${r.approval.untestedOverride ? ", untested override" : ""}` : "none"}${r.change ? `; branch ${r.change.branch}${r.change.mergeSha ? `, merged ${r.change.mergeSha.slice(0, 12)}` : ""}` : ""}`) : []),
    `AI involvement: ${c.aiInvolvement}`, "", "Limitations:",
    ...(c.limitations ?? []).map((l: string) => `  - ${l}`), "",
    "Integrity (tamper-evident):",
    `  sha256      ${row.sha256}`,
    `  prev sha256 ${row.prevSha256 ?? "none (first record)"}`,
    "  The sha256 covers the canonical JSON of the record (keys sorted). Verify with the JSON export.",
  ];
  return textPdf(lines);
}
