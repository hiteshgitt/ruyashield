import { and, desc, eq, gt, gte, inArray, isNull, or, sql, type SQL } from "drizzle-orm";
import { withOrg, isUuid } from "../db/client";
import {
  assessments, assets, clientGroups, findings, memberships, riskAcceptances, verificationRuns,
  type Coverage, type Severity,
} from "../db/schema";
import { AppError, forbidden } from "../errors";
import { authorize, decide, isProOrg, type OrgFlags, type Principal } from "../policy/policy";
import { freeVisibleIds } from "../findings/findings";
import { grantFor, type Action } from "../policy/matrix";
import { OPEN_STATUSES } from "../findings/lifecycle";
import { prioritySql } from "../findings/priority";

// Read model shared by the dashboard (RS-RPT-001) and generated reports (RS-RPT-002). Counts come straight
// from recorded state: nothing here is estimated, and a check that did not run is never counted as passed.

export type Ctx = { principal: Principal; org: OrgFlags & { id: string } };
export const WINDOW_DAYS = 30;
const SEVERITIES: readonly Severity[] = ["critical", "high", "medium", "low", "info"];

export interface SecuritySummary {
  generatedAt: Date;
  windowDays: number;
  scope: { clientGroupId: string | null; clientGroupName: string | null; restrictedToGroups: boolean };
  assets: { total: number; verified: number; unverified: number; lapsedOrRevoked: number };
  findings: { open: Record<Severity, number>; openTotal: number; untriagedCritical: number; overdue: number; resolvedVerifiedInWindow: number };
  verification: { verified: number; partiallyVerified: number; failed: number; unverified: number; notRun: number };
  assessments: { total: number; completed: number; completedWithErrors: number; failed: number; lastCompletedAt: Date | null };
  failedVerifications: { findingId: string; title: string; host: string; outcome: string; finishedAt: Date | null }[];
  incompleteAssessments: { id: string; host: string; status: string; reason: string | null; coverage: Coverage | null; finishedAt: Date | null }[];
  acceptedRisks: { findingId: string; title: string; severity: Severity; host: string; justification: string; expiresAt: Date }[];
  topOpen: { id: string; title: string; severity: Severity; status: string; host: string; dueAt: Date | null }[];
  onboarding: { hasAsset: boolean; hasVerifiedAsset: boolean; hasAssessment: boolean; hasCompletedAssessment: boolean; hasTeammate: boolean };
}

/** Asset filter for the caller: restricted members with an "S" grant see only their client groups (same rule as listFindings). */
export function assetScope(p: Principal, action: Action, clientGroupId: string | null): SQL[] {
  const where: SQL[] = [];
  if (grantFor(p.role, action) === "S" && p.restricted) {
    where.push(p.clientGroupIds.length ? inArray(assets.clientGroupId, [...p.clientGroupIds]) : sql`false`);
  }
  if (clientGroupId) where.push(eq(assets.clientGroupId, clientGroupId));
  return where;
}

const n = (v: unknown) => Number(v ?? 0);

export async function securitySummary(
  c: Ctx, opts: { clientGroupId?: string | null; action?: "dashboard.view" | "report.generate" } = {}, now = new Date(),
): Promise<SecuritySummary> {
  const p = c.principal;
  const action = opts.action ?? "dashboard.view";
  // Org-wide view: an "S" grant passes here and is narrowed by assetScope below.
  const d = decide(p, action, { type: "org", ownerId: p.userId }, c.org);
  if (!d.allow) throw d.status === 402 ? new AppError(402, d.code, "This is part of RuyaShield Pro.") : forbidden();
  await authorize(p, action, { type: "org", id: c.org.id, ownerId: p.userId }, c.org);
  const groupId = opts.clientGroupId || null;
  if (groupId && !isUuid(groupId)) throw new AppError(422, "invalid_filter", "Unknown client group.");
  if (groupId && grantFor(p.role, action) === "S" && p.restricted && !p.clientGroupIds.includes(groupId)) throw forbidden();
  const since = new Date(now.getTime() - WINDOW_DAYS * 86_400_000);
  const scope = assetScope(p, action, groupId);
  const inScope = scope.length ? and(...scope) : undefined;

  return withOrg(c.org.id, async (tx) => {
    let clientGroupName: string | null = null;
    if (groupId) {
      const g = await tx.select({ name: clientGroups.name }).from(clientGroups).where(eq(clientGroups.id, groupId)).limit(1);
      if (!g[0]) throw new AppError(422, "invalid_filter", "Unknown client group.");
      clientGroupName = g[0].name;
    }

    const [a] = await tx.select({
      total: sql<number>`count(*)`,
      verified: sql<number>`count(*) filter (where ${assets.status} = 'verified')`,
      unverified: sql<number>`count(*) filter (where ${assets.status} = 'unverified')`,
      gone: sql<number>`count(*) filter (where ${assets.status} in ('lapsed','revoked'))`,
    }).from(assets).where(inScope);

    const open = inArray(findings.status, [...OPEN_STATUSES]);
    const sevRows = await tx.select({ severity: findings.severity, count: sql<number>`count(*)` })
      .from(findings).innerJoin(assets, eq(assets.id, findings.assetId))
      .where(and(open, inScope)).groupBy(findings.severity);
    const openBySev = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
    for (const r of sevRows) openBySev[r.severity] = n(r.count);
    const [f] = await tx.select({
      untriagedCritical: sql<number>`count(*) filter (where ${findings.status} = 'new' and ${findings.severity} = 'critical')`,
      overdue: sql<number>`count(*) filter (where ${open} and ${findings.dueAt} < ${now})`,
      resolved: sql<number>`count(*) filter (where ${findings.status} = 'resolved_verified' and ${findings.statusChangedAt} >= ${since})`,
    }).from(findings).innerJoin(assets, eq(assets.id, findings.assetId)).where(inScope);

    const [v] = await tx.select({
      verified: sql<number>`count(*) filter (where ${verificationRuns.outcome} = 'verified')`,
      partial: sql<number>`count(*) filter (where ${verificationRuns.outcome} = 'partially_verified')`,
      failed: sql<number>`count(*) filter (where ${verificationRuns.outcome} = 'failed')`,
      unverified: sql<number>`count(*) filter (where ${verificationRuns.outcome} = 'unverified')`,
      notRun: sql<number>`count(*) filter (where ${verificationRuns.status} = 'not_run')`,
    }).from(verificationRuns).innerJoin(assets, eq(assets.id, verificationRuns.assetId))
      .where(and(gte(verificationRuns.createdAt, since), inScope));

    const [s] = await tx.select({
      total: sql<number>`count(*)`,
      completed: sql<number>`count(*) filter (where ${assessments.status} = 'completed')`,
      withErrors: sql<number>`count(*) filter (where ${assessments.status} = 'completed_with_errors')`,
      failed: sql<number>`count(*) filter (where ${assessments.status} in ('failed','timed_out','rejected'))`,
      last: sql<Date | null>`max(${assessments.finishedAt}) filter (where ${assessments.status} in ('completed','completed_with_errors'))`,
    }).from(assessments).innerJoin(assets, eq(assets.id, assessments.assetId))
      .where(and(gte(assessments.queuedAt, since), inScope));

    const failedVerifications = await tx.select({
      findingId: verificationRuns.findingId, title: findings.title, host: assets.host,
      outcome: sql<string>`coalesce(${verificationRuns.outcome}, ${verificationRuns.status})`, finishedAt: verificationRuns.finishedAt,
    }).from(verificationRuns).innerJoin(findings, eq(findings.id, verificationRuns.findingId)).innerJoin(assets, eq(assets.id, verificationRuns.assetId))
      .where(and(gte(verificationRuns.createdAt, since), or(inArray(verificationRuns.outcome, ["failed", "partially_verified", "unverified"]), eq(verificationRuns.status, "not_run")), inScope))
      .orderBy(desc(verificationRuns.createdAt)).limit(50);

    const incompleteAssessments = await tx.select({
      id: assessments.id, host: assets.host, status: assessments.status, reason: assessments.reason,
      coverage: assessments.coverage, finishedAt: assessments.finishedAt,
    }).from(assessments).innerJoin(assets, eq(assets.id, assessments.assetId))
      .where(and(gte(assessments.queuedAt, since), inArray(assessments.status, ["completed_with_errors", "failed", "timed_out", "rejected"]), inScope))
      .orderBy(desc(assessments.queuedAt)).limit(50);

    const acceptedRisks = await tx.select({
      findingId: findings.id, title: findings.title, severity: findings.severity, host: assets.host,
      justification: riskAcceptances.justification, expiresAt: riskAcceptances.expiresAt,
    }).from(riskAcceptances).innerJoin(findings, eq(findings.id, riskAcceptances.findingId)).innerJoin(assets, eq(assets.id, findings.assetId))
      .where(and(isNull(riskAcceptances.revokedAt), isNull(riskAcceptances.expiredAt), gt(riskAcceptances.expiresAt, now), eq(findings.status, "accepted_risk"), inScope))
      .orderBy(riskAcceptances.expiresAt).limit(100);

    const score = prioritySql(findings.severity, findings.confidence, assets.criticality);
    const topOpen = await tx.select({ id: findings.id, title: findings.title, severity: findings.severity, status: findings.status, host: assets.host, dueAt: findings.dueAt })
      .from(findings).innerJoin(assets, eq(assets.id, findings.assetId)).where(and(open, inScope)).orderBy(desc(score), findings.id).limit(10)
      .then(async (rows) => {
        if (isProOrg(c.org)) return rows;
        const visible = await freeVisibleIds(tx, c);
        return rows.filter((r) => visible.has(r.id));
      });

    const [m] = await tx.select({ count: sql<number>`count(*)` }).from(memberships).where(eq(memberships.orgId, c.org.id));
    const [anyAssessment] = await tx.select({
      any: sql<number>`count(*)`, done: sql<number>`count(*) filter (where ${assessments.status} in ('completed','completed_with_errors'))`,
    }).from(assessments).innerJoin(assets, eq(assets.id, assessments.assetId)).where(inScope);

    return {
      generatedAt: now, windowDays: WINDOW_DAYS,
      scope: { clientGroupId: groupId, clientGroupName, restrictedToGroups: grantFor(p.role, action) === "S" && p.restricted },
      assets: { total: n(a.total), verified: n(a.verified), unverified: n(a.unverified), lapsedOrRevoked: n(a.gone) },
      findings: {
        open: openBySev, openTotal: Object.values(openBySev).reduce((x, y) => x + y, 0),
        untriagedCritical: n(f.untriagedCritical), overdue: n(f.overdue), resolvedVerifiedInWindow: n(f.resolved),
      },
      verification: { verified: n(v.verified), partiallyVerified: n(v.partial), failed: n(v.failed), unverified: n(v.unverified), notRun: n(v.notRun) },
      assessments: { total: n(s.total), completed: n(s.completed), completedWithErrors: n(s.withErrors), failed: n(s.failed), lastCompletedAt: s.last ? new Date(s.last) : null },
      failedVerifications, incompleteAssessments, acceptedRisks, topOpen,
      onboarding: {
        hasAsset: n(a.total) > 0, hasVerifiedAsset: n(a.verified) > 0, hasAssessment: n(anyAssessment.any) > 0,
        hasCompletedAssessment: n(anyAssessment.done) > 0, hasTeammate: n(m.count) > 1,
      },
    };
  });
}

/** True when there is nothing to report yet: the dashboard shows setup steps instead of an "all clear". */
export const needsOnboarding = (s: SecuritySummary) => !s.onboarding.hasVerifiedAsset || !s.onboarding.hasCompletedAssessment;
