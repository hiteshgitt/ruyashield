import { cvss3Score } from "../assessments/deps";
import { and, desc, eq, gte, inArray, sql } from "drizzle-orm";
import { withOrg } from "../db/client";
import { assessments, assets, auditEvents, codeChanges, findings, remediationPlans, type AssessmentStatus, type Severity } from "../db/schema";
import { AppError, forbidden } from "../errors";
import { decide, type OrgFlags, type Principal, type Resource } from "../policy/policy";
import { OPEN_STATUSES } from "../findings/lifecycle";
import { parseHost } from "../assets/host";
import { recordWatchedHosts } from "./watch";

// Read model for the WebMonitor "connect account" integration: per-host security status for the sites a
// WebMonitor user monitors. Called with a read-only API token (assets:read + findings:read). Only counts,
// statuses, finding titles and CVSS vectors leave RuyaShield: no evidence, locations or remediation text.

type Ctx = { principal: Principal; org: OrgFlags & { id: string; name?: string } };

export const MAX_POSTURE_HOSTS = 100;
const TOP_OPEN = 3;
// Changes RuyaShield made to a site recently, so WebMonitor can line them up with downtime ("possible cause").
export const CHANGE_WINDOW_DAYS = 7;
const MAX_CHANGES = 10;
const SEVERITIES: readonly Severity[] = ["critical", "high", "medium", "low", "info"];
const SEV_RANK = sql`CASE ${findings.severity} WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END`;

export type HostPosture =
  | { host: string; tracked: false }
  | {
    host: string; tracked: true;
    asset: { id: string; name: string; status: string; verifiedAt: Date | null };
    findings: { open: Record<Severity, number>; openTotal: number; top: { title: string; severity: Severity; cvss?: { score: number | null; vector: string } }[] } | null;
    lastAssessment: { status: AssessmentStatus; finishedAt: Date | null; complete: boolean | null } | null;
    changes: SiteChange[];
    link: string;
  };

/**
 * A change RuyaShield made, or saw made, on a site. Edge fixes are applied by RuyaShield itself at Cloudflare;
 * a merged fix is the customer merging a RuyaShield pull request (`at` is when RuyaShield saw the merge, so the
 * deploy can come later). Newest first.
 */
export type SiteChange = {
  kind: "edge_applied" | "edge_undone" | "code_merged";
  at: Date;
  title: string;
  link: string;
};

export interface PostureResponse {
  org: { name: string };
  generatedAt: Date;
  hosts: HostPosture[];
}

const appUrl = (path: string) => new URL(path, process.env.APP_URL ?? "http://localhost:3200").toString();

/** Parses `?hosts=a.com,b.com`; invalid entries are refused rather than silently dropped. */
export function parseHostList(raw: string | null): string[] {
  const parts = (raw ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  if (parts.length > MAX_POSTURE_HOSTS) throw new AppError(422, "too_many_hosts", `Ask for at most ${MAX_POSTURE_HOSTS} hosts.`);
  const out: string[] = [];
  for (const p of parts) {
    try { out.push(parseHost(p)); } catch { throw new AppError(422, "invalid_host", "One of the hosts is not a valid domain name."); }
  }
  return [...new Set(out)];
}

export async function hostPosture(c: Ctx, hosts: string[], now = new Date()): Promise<PostureResponse> {
  const p = c.principal;
  // The token must be able to see assets at all; finding counts are added only where findings are visible too.
  if (!decide(p, "asset.view", { type: "org", ownerId: p.userId }, c.org).allow) throw forbidden();
  const orgName = c.org.name ?? "";
  if (!hosts.length) return { org: { name: orgName }, generatedAt: now, hosts: [] };

  return withOrg(c.org.id, async (tx) => {
    // WebMonitor sends every site it monitors; remember them so RuyaShield can show uptime coverage.
    if (p.tokenId) await recordWatchedHosts(tx, c.org.id, p.tokenId, hosts, now);
    const rows = await tx.select().from(assets).where(and(eq(assets.kind, "domain"), inArray(assets.host, hosts)));
    const res = (a: typeof rows[number]): Resource => ({ type: "asset", id: a.id, clientGroupId: a.clientGroupId, ownerId: a.createdBy });
    const visible = rows.filter((a) => decide(p, "asset.view", res(a), c.org).allow);
    const withFindings = new Set(visible.filter((a) => decide(p, "finding.view", res(a), c.org).allow).map((a) => a.id));
    const ids = visible.map((a) => a.id);
    const findingIds = [...withFindings];

    const counts = findingIds.length ? await tx.select({ assetId: findings.assetId, severity: findings.severity, n: sql<number>`count(*)::int` })
      .from(findings).where(and(inArray(findings.assetId, findingIds), inArray(findings.status, [...OPEN_STATUSES])))
      .groupBy(findings.assetId, findings.severity) : [];

    const top = findingIds.length ? await tx.execute<{ asset_id: string; title: string; severity: Severity; cvss_vector: string | null }>(sql`
      SELECT asset_id, title, severity, cvss_vector FROM (
        SELECT ${findings.assetId} AS asset_id, ${findings.title} AS title, ${findings.severity} AS severity, ${findings.cvssVector} AS cvss_vector,
          row_number() OVER (PARTITION BY ${findings.assetId} ORDER BY ${SEV_RANK} DESC, ${findings.lastSeen} DESC) AS rn
        FROM ${findings}
        WHERE ${inArray(findings.assetId, findingIds)} AND ${inArray(findings.status, [...OPEN_STATUSES])}
      ) t WHERE rn <= ${TOP_OPEN}`) : { rows: [] };

    const last = ids.length ? await tx.selectDistinctOn([assessments.assetId], {
      assetId: assessments.assetId, status: assessments.status, finishedAt: assessments.finishedAt, coverage: assessments.coverage,
    }).from(assessments).where(inArray(assessments.assetId, ids))
      .orderBy(assessments.assetId, desc(assessments.queuedAt)) : [];

    const changes = await recentChanges(tx, ids, findingIds, now);

    const byHost = new Map(visible.map((a) => [a.host, a]));
    return {
      org: { name: orgName },
      generatedAt: now,
      hosts: hosts.map((host): HostPosture => {
        const a = byHost.get(host);
        if (!a) return { host, tracked: false };
        let f: Extract<HostPosture, { tracked: true }>["findings"] = null;
        if (withFindings.has(a.id)) {
          const open = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
          for (const r of counts) if (r.assetId === a.id) open[r.severity] = Number(r.n);
          f = {
            open, openTotal: Object.values(open).reduce((x, y) => x + y, 0),
            top: top.rows.filter((r) => r.asset_id === a.id)
              .map((r) => ({ title: r.title, severity: r.severity, ...(r.cvss_vector ? { cvss: { score: cvss3Score(r.cvss_vector), vector: r.cvss_vector } } : {}) }))
              .sort((x, y) => SEVERITIES.indexOf(x.severity) - SEVERITIES.indexOf(y.severity)),
          };
        }
        const l = last.find((r) => r.assetId === a.id);
        return {
          host, tracked: true,
          asset: { id: a.id, name: a.displayName, status: a.status, verifiedAt: a.verifiedAt },
          findings: f,
          lastAssessment: l ? { status: l.status, finishedAt: l.finishedAt, complete: l.coverage?.complete ?? null } : null,
          changes: changes.get(a.id) ?? [],
          link: appUrl(`/assets/${a.id}`),
        };
      }),
    };
  });
}

type Tx = Parameters<Parameters<typeof withOrg>[1]>[0];

const EDGE_TITLE: Record<string, string> = {
  "edge.applied": "Security headers added at Cloudflare by RuyaShield",
  "edge.undone": "RuyaShield's Cloudflare security headers removed",
};

/**
 * Per asset: edge fixes applied or undone (from the audit log; needs asset.view) and RuyaShield pull requests
 * seen merged (needs finding.view, since the title comes from the finding's plan). Titles only, no diffs.
 */
export async function recentChanges(tx: Tx, assetIds: string[], findingAssetIds: string[], now = new Date()): Promise<Map<string, SiteChange[]>> {
  const out = new Map<string, SiteChange[]>();
  if (!assetIds.length) return out;
  const since = new Date(now.getTime() - CHANGE_WINDOW_DAYS * 86_400_000);
  const add = (assetId: string, c: SiteChange) => out.set(assetId, [...(out.get(assetId) ?? []), c]);

  const edge = await tx.select({ action: auditEvents.action, targetId: auditEvents.targetId, ts: auditEvents.ts })
    .from(auditEvents)
    .where(and(inArray(auditEvents.action, Object.keys(EDGE_TITLE)), eq(auditEvents.targetType, "asset"),
      eq(auditEvents.outcome, "success"), inArray(auditEvents.targetId, assetIds), gte(auditEvents.ts, since)));
  for (const e of edge) {
    if (!e.targetId) continue;
    add(e.targetId, { kind: e.action === "edge.applied" ? "edge_applied" : "edge_undone", at: e.ts, title: EDGE_TITLE[e.action], link: appUrl(`/assets/${e.targetId}`) });
  }

  if (findingAssetIds.length) {
    const merged = await tx.select({ assetId: findings.assetId, at: codeChanges.observedAt, title: remediationPlans.title, prUrl: codeChanges.prUrl })
      .from(codeChanges)
      .innerJoin(remediationPlans, eq(remediationPlans.id, codeChanges.planId))
      .innerJoin(findings, eq(findings.id, remediationPlans.findingId))
      .where(and(eq(codeChanges.state, "merged"), inArray(findings.assetId, findingAssetIds), gte(codeChanges.observedAt, since)));
    for (const m of merged) {
      if (!m.at) continue;
      add(m.assetId, { kind: "code_merged", at: m.at, title: `RuyaShield fix merged: ${m.title}`.slice(0, 200), link: m.prUrl ?? appUrl(`/assets/${m.assetId}`) });
    }
  }

  for (const [id, list] of out) out.set(id, list.sort((x, y) => y.at.getTime() - x.at.getTime()).slice(0, MAX_CHANGES));
  return out;
}
