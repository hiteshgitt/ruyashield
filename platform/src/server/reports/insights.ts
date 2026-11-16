import { and, eq, gte, inArray, sql } from "drizzle-orm";
import { withOrg } from "../db/client";
import { assessments, assets, checkDefinitions, checkRuns, findings, type Criticality, type Severity } from "../db/schema";
import { forbidden } from "../errors";
import { decide } from "../policy/policy";
import { OPEN_STATUSES } from "../findings/lifecycle";
import { assetScope, type Ctx } from "./summary";
import { SECURITY_AREAS, type AreaTier } from "./areas";

// Dashboard-only read model (charts). Kept apart from securitySummary so reports and /v1/dashboard are unchanged.
// Like the summary, everything comes from recorded state; nothing is estimated or back-filled.

export const TREND_WEEKS = 12;

/** Points one open finding takes off the score, per assessed asset. Info findings cost nothing. */
export const SCORE_WEIGHTS: Record<Severity, number> = { critical: 20, high: 10, medium: 4, low: 1, info: 0 };

export type Grade = "A" | "B" | "C" | "D" | "F";
export interface Score { value: number; grade: Grade; penalty: number; assessedAssets: number }

/**
 * Exposure score (score/1): 100 minus the weighted open findings per assessed asset, floored at 0.
 * Returns null when no asset has a completed assessment, so "no data" is never shown as a perfect score.
 */
export function exposureScore(open: Record<Severity, number>, assessedAssets: number): Score | null {
  if (assessedAssets <= 0) return null;
  const penalty = (Object.keys(SCORE_WEIGHTS) as Severity[]).reduce((t, s) => t + SCORE_WEIGHTS[s] * (open[s] ?? 0), 0);
  const value = Math.max(0, Math.round(100 - penalty / assessedAssets));
  const grade: Grade = value >= 90 ? "A" : value >= 75 ? "B" : value >= 60 ? "C" : value >= 40 ? "D" : "F";
  return { value, grade, penalty, assessedAssets };
}

export { SECURITY_AREAS, TIER_LABEL, type AreaTier } from "./areas";

export interface AreaRow {
  key: string; label: string; tier: AreaTier; why: string; covered: boolean;
  open: number; worst: Severity | null; bySeverity: Record<Severity, number>;
  /** Assets where one of the area's checks last completed with status ok, and when. Zero/null = never ran in scope. */
  assetsChecked: number; lastRunAt: Date | null;
}
export interface TrendWeek { weekStart: Date; opened: number; resolved: number }
export interface AssetTile {
  id: string; host: string; status: string; criticality: Criticality | null;
  open: Record<Severity, number>; openTotal: number; worst: Severity | null; lastAssessedAt: Date | null;
}
export interface DashboardInsights { score: Score | null; trend: TrendWeek[]; assets: AssetTile[]; areas: AreaRow[] }

const SEV_ORDER: readonly Severity[] = ["critical", "high", "medium", "low", "info"];
const n = (v: unknown) => Number(v ?? 0);
const zero = () => Object.fromEntries(SEV_ORDER.map((s) => [s, 0])) as Record<Severity, number>;
const worstOf = (r: Record<Severity, number>) => SEV_ORDER.find((s) => r[s] > 0) ?? null;

/** Monday 00:00 UTC of the week containing `d` (matches Postgres date_trunc('week') in UTC). */
export function weekStart(d: Date): Date {
  const x = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
  x.setUTCDate(x.getUTCDate() - ((x.getUTCDay() + 6) % 7));
  return x;
}

export async function dashboardInsights(c: Ctx, opts: { clientGroupId?: string | null } = {}, now = new Date()): Promise<DashboardInsights> {
  // securitySummary has already authorized (and audited) this request; this is a plain re-check, not a second audit entry.
  if (!decide(c.principal, "dashboard.view", { type: "org", ownerId: c.principal.userId }, c.org).allow) throw forbidden();
  const scope = assetScope(c.principal, "dashboard.view", opts.clientGroupId || null);
  const inScope = scope.length ? and(...scope) : undefined;
  const firstWeek = new Date(weekStart(now).getTime() - (TREND_WEEKS - 1) * 7 * 86_400_000);
  const open = inArray(findings.status, [...OPEN_STATUSES]);

  return withOrg(c.org.id, async (tx) => {
    const done = sql`${assessments.status} in ('completed','completed_with_errors')`;
    const assetRows = await tx.select({ id: assets.id, host: assets.host, status: assets.status, criticality: assets.criticality })
      .from(assets).where(inScope).orderBy(assets.host).limit(120);
    const lastRows = assetRows.length ? await tx.select({ assetId: assessments.assetId, last: sql<string | null>`max(${assessments.finishedAt})` })
      .from(assessments).where(and(done, inArray(assessments.assetId, assetRows.map((a) => a.id)))).groupBy(assessments.assetId) : [];
    const lastByAsset = new Map(lastRows.map((r) => [r.assetId, r.last]));

    const sevRows = await tx.select({ assetId: findings.assetId, severity: findings.severity, checkKey: findings.checkKey, count: sql<number>`count(*)` })
      .from(findings).innerJoin(assets, eq(assets.id, findings.assetId))
      .where(and(open, inScope)).groupBy(findings.assetId, findings.severity, findings.checkKey);

    const byAsset = new Map<string, Record<Severity, number>>();
    const byCheck = new Map<string, Record<Severity, number>>();
    const totals = zero();
    for (const r of sevRows) {
      const k = n(r.count);
      (byAsset.get(r.assetId) ?? byAsset.set(r.assetId, zero()).get(r.assetId)!)[r.severity] += k;
      (byCheck.get(r.checkKey) ?? byCheck.set(r.checkKey, zero()).get(r.checkKey)!)[r.severity] += k;
      totals[r.severity] += k;
    }

    const tiles: AssetTile[] = assetRows.map((a) => {
      const o = byAsset.get(a.id) ?? zero();
      return {
        id: a.id, host: a.host, status: a.status, criticality: a.criticality ?? null, open: o,
        openTotal: SEV_ORDER.reduce((t, s) => t + o[s], 0), worst: worstOf(o), lastAssessedAt: lastByAsset.get(a.id) ? new Date(lastByAsset.get(a.id)!) : null,
      };
    });
    // Riskiest first: worst severity, then open count, then host.
    tiles.sort((x, y) => (x.worst ? SEV_ORDER.indexOf(x.worst) : 9) - (y.worst ? SEV_ORDER.indexOf(y.worst) : 9) || y.openTotal - x.openTotal || x.host.localeCompare(y.host));

    // Which checks actually completed (status ok) in scope, so an area is never shown clean just because nothing ran.
    const ranRows = await tx.select({ checkKey: checkDefinitions.checkKey, assets: sql<number>`count(distinct ${assessments.assetId})`, last: sql<string | null>`max(${checkRuns.finishedAt})` })
      .from(checkRuns).innerJoin(checkDefinitions, eq(checkDefinitions.id, checkRuns.checkId))
      .innerJoin(assessments, eq(assessments.id, checkRuns.assessmentId)).innerJoin(assets, eq(assets.id, assessments.assetId))
      .where(and(eq(checkRuns.status, "ok"), inScope)).groupBy(checkDefinitions.checkKey);
    const ran = new Map(ranRows.map((r) => [r.checkKey, r]));

    const areas: AreaRow[] = SECURITY_AREAS.map((a) => {
      const sev = zero();
      for (const ck of a.checks) { const r = byCheck.get(ck); if (r) for (const s of SEV_ORDER) sev[s] += r[s]; }
      return { key: a.key, label: a.label, tier: a.tier, why: a.why, covered: a.checks.length > 0, open: SEV_ORDER.reduce((t, s) => t + sev[s], 0), worst: worstOf(sev), bySeverity: sev,
        assetsChecked: Math.max(0, ...a.checks.map((ck) => n(ran.get(ck)?.assets))),
        lastRunAt: a.checks.reduce<Date | null>((m, ck) => { const v = ran.get(ck)?.last; const d = v ? new Date(v) : null; return d && (!m || d > m) ? d : m; }, null) };
    });

    const opened = await tx.select({ wk: sql<string>`to_char(date_trunc('week', ${findings.firstSeen} at time zone 'UTC'), 'YYYY-MM-DD')`, count: sql<number>`count(*)` })
      .from(findings).innerJoin(assets, eq(assets.id, findings.assetId))
      .where(and(gte(findings.firstSeen, firstWeek), inScope)).groupBy(sql`1`);
    const resolved = await tx.select({ wk: sql<string>`to_char(date_trunc('week', ${findings.statusChangedAt} at time zone 'UTC'), 'YYYY-MM-DD')`, count: sql<number>`count(*)` })
      .from(findings).innerJoin(assets, eq(assets.id, findings.assetId))
      .where(and(eq(findings.status, "resolved_verified"), gte(findings.statusChangedAt, firstWeek), inScope)).groupBy(sql`1`);
    const om = new Map(opened.map((r) => [r.wk, n(r.count)]));
    const rm = new Map(resolved.map((r) => [r.wk, n(r.count)]));
    const trend: TrendWeek[] = Array.from({ length: TREND_WEEKS }, (_, i) => {
      const ws = new Date(firstWeek.getTime() + i * 7 * 86_400_000);
      const key = ws.toISOString().slice(0, 10);
      return { weekStart: ws, opened: om.get(key) ?? 0, resolved: rm.get(key) ?? 0 };
    });

    const assessed = tiles.filter((t) => t.lastAssessedAt).length;
    return { score: exposureScore(totals, assessed), trend, assets: tiles, areas };
  });
}
