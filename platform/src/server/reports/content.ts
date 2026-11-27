import { findingCvss, type Cvss } from "../assessments/ratings";
import { and, desc, eq, inArray, sql } from "drizzle-orm";
import { z } from "zod";
import { withOrg } from "../db/client";
import { assessments, assets, findings, type Severity } from "../db/schema";
import { OPEN_STATUSES } from "../findings/lifecycle";
import { prioritySql } from "../findings/priority";
import { getStats, type AttackStats } from "../attacks/attacks";
import { assetScope, type Ctx } from "./summary";

// What goes into a report: presets, the sections a person can tick, and the detail data behind them
// (per-asset table, the open findings list, the attack summary). The summary counts come from summary.ts.

export const SECTIONS = {
  summary: { label: "Executive summary", hint: "Key figures, the highest-priority findings and what to fix first." },
  assets: { label: "Assets", hint: "Every asset with its ownership status, last assessment and open findings." },
  findings: { label: "Open findings", hint: "Each open finding with its asset, status and due date." },
  verification: { label: "Fix verification", hint: "Re-test outcomes: verified fixes and re-tests that did not pass." },
  assessments: { label: "Assessments and coverage", hint: "Assessment outcomes and checks that did not complete." },
  risks: { label: "Accepted risks", hint: "Risks accepted with a justification and expiry; still open." },
  attacks: { label: "Attack monitoring", hint: "Hostile traffic in the window: countries, networks and attack types." },
} as const;
export type SectionKey = keyof typeof SECTIONS;
export const SECTION_KEYS = Object.keys(SECTIONS) as SectionKey[];

export const PRESETS = {
  executive: { label: "Executive summary", hint: "One or two pages for leadership: score, key figures, top risks.", sections: ["summary", "verification"] as SectionKey[], minSeverity: "high" as Severity, includeFixes: false },
  client: { label: "Client report", hint: "For a client: assets, findings with fixes, proof of fixed issues.", sections: ["summary", "assets", "findings", "verification", "risks"] as SectionKey[], minSeverity: "low" as Severity, includeFixes: true },
  technical: { label: "Full technical", hint: "Everything, for the team doing the work.", sections: [...SECTION_KEYS], minSeverity: "info" as Severity, includeFixes: true },
} as const;
export type PresetKey = keyof typeof PRESETS | "custom";

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];
export const severitiesFrom = (min: Severity) => SEVERITY_ORDER.slice(0, SEVERITY_ORDER.indexOf(min) + 1);

export const ReportOptions = z.object({
  title: z.string().trim().max(120).optional().default(""),
  preset: z.enum(["executive", "client", "technical", "custom"]).default("client"),
  sections: z.array(z.enum(SECTION_KEYS as [SectionKey, ...SectionKey[]])).optional(),
  minSeverity: z.enum(["critical", "high", "medium", "low", "info"]).optional(),
  includeFixes: z.boolean().optional(),
});
export type ReportOptionsInput = z.input<typeof ReportOptions>;

/** Presets fill in sections, severity and fixes; "custom" uses what was ticked. The summary is always in. */
export function resolveOptions(input: unknown) {
  const v = ReportOptions.parse(input ?? {});
  const base = v.preset === "custom" ? PRESETS.technical : PRESETS[v.preset];
  const sections = new Set<SectionKey>(v.preset === "custom" ? (v.sections?.length ? v.sections : base.sections) : base.sections);
  sections.add("summary");
  return {
    title: v.title,
    preset: v.preset as PresetKey,
    sections: SECTION_KEYS.filter((k) => sections.has(k)),
    minSeverity: (v.preset === "custom" ? v.minSeverity ?? "info" : base.minSeverity) as Severity,
    includeFixes: v.preset === "custom" ? v.includeFixes ?? true : base.includeFixes,
  };
}
export type ResolvedOptions = ReturnType<typeof resolveOptions>;

export const MAX_FINDINGS = 300;

export interface ReportDetail {
  assets: { host: string; name: string; environment: string; status: string; verifiedAt: Date | null; lastStatus: string | null; lastFinishedAt: Date | null; open: Record<Severity, number> }[];
  findings: { title: string; host: string; severity: Severity; status: string; location: string; firstSeen: Date; dueAt: Date | null; remediation: string | null; cvss: Cvss }[];
  findingsTotal: number;
  attacks: AttackStats | null;
}

/** The detail data for the chosen sections, in the caller's scope (client group and restricted membership). */
export async function reportDetail(c: Ctx, o: ResolvedOptions, clientGroupId: string | null): Promise<ReportDetail> {
  const scope = assetScope(c.principal, "report.generate", clientGroupId);
  const severities = severitiesFrom(o.minSeverity);
  return withOrg(c.org.id, async (tx) => {
    let assetRows: ReportDetail["assets"] = [];
    if (o.sections.includes("assets")) {
      const rows = await tx.select().from(assets).where(scope.length ? and(...scope) : undefined).orderBy(assets.host);
      const ids = rows.map((a) => a.id);
      const counts = ids.length ? await tx.select({ assetId: findings.assetId, severity: findings.severity, n: sql<number>`count(*)::int` })
        .from(findings).where(and(inArray(findings.assetId, ids), inArray(findings.status, [...OPEN_STATUSES])))
        .groupBy(findings.assetId, findings.severity) : [];
      const last = ids.length ? await tx.selectDistinctOn([assessments.assetId], { assetId: assessments.assetId, status: assessments.status, finishedAt: assessments.finishedAt })
        .from(assessments).where(inArray(assessments.assetId, ids)).orderBy(assessments.assetId, desc(assessments.queuedAt)) : [];
      assetRows = rows.map((a) => {
        const open = Object.fromEntries(SEVERITY_ORDER.map((s) => [s, 0])) as Record<Severity, number>;
        for (const r of counts) if (r.assetId === a.id) open[r.severity] = Number(r.n);
        const l = last.find((x) => x.assetId === a.id);
        return { host: a.host, name: a.displayName, environment: a.environment, status: a.status, verifiedAt: a.verifiedAt, lastStatus: l?.status ?? null, lastFinishedAt: l?.finishedAt ?? null, open };
      });
    }

    let findingRows: ReportDetail["findings"] = [];
    let findingsTotal = 0;
    if (o.sections.includes("findings")) {
      const where = and(inArray(findings.status, [...OPEN_STATUSES]), inArray(findings.severity, severities), ...scope);
      const score = prioritySql(findings.severity, findings.confidence, assets.criticality);
      const [{ n }] = await tx.select({ n: sql<number>`count(*)::int` }).from(findings).innerJoin(assets, eq(assets.id, findings.assetId)).where(where);
      findingsTotal = Number(n);
      const rows = await tx.select({ f: findings, host: assets.host }).from(findings).innerJoin(assets, eq(assets.id, findings.assetId))
        .where(where).orderBy(desc(score), findings.id).limit(MAX_FINDINGS);
      findingRows = rows.map(({ f, host }) => ({
        title: f.title, host, severity: f.severity, status: f.status, location: f.location, firstSeen: f.firstSeen, dueAt: f.dueAt,
        remediation: o.includeFixes ? f.remediation : null, cvss: findingCvss(f),
      }));
    }
    return { assets: assetRows, findings: findingRows, findingsTotal, attacks: null };
  }).then(async (d) => {
    if (!o.sections.includes("attacks")) return d;
    // Attack monitoring is optional data: without sources (or access) the section says so instead of failing.
    const attacks = await getStats(c, { days: 30 }).catch(() => null);
    return { ...d, attacks };
  });
}
