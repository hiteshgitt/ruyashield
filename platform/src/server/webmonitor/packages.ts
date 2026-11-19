import { sql } from "drizzle-orm";
import { z } from "zod";
import { db } from "../db/client";
import { parseHost } from "../assets/host";
import { isAppError } from "../errors";
import type { CheckAdapter, CheckResult, FindingCandidate } from "../assessments/checks";
import type { Severity } from "../db/schema";
import { webmonitorAdapter } from "./adapter";

// Vulnerable packages reported by WebMonitor (signed server-to-server, like referral handoffs). WebMonitor reads
// the installed npm / Composer packages from the site's own integration (which needs the site's API key, so the
// data comes from the site itself), looks them up in OSV.dev and sends the vulnerable ones here, for customers who
// connected RuyaShield. The webmonitor.packages check turns the latest report into findings for verified assets.

export const MAX_PACKAGE_REPORT_BYTES = 128 * 1024;
export const REPORT_MAX_AGE_MS = 3 * 24 * 3600 * 1000;

const pkg = z.object({
  name: z.string().regex(/^[@a-z0-9][\w./@-]{0,213}$/i),
  version: z.string().regex(/^[\w.+-]{1,64}$/),
  severity: z.enum(["critical", "high", "moderate", "low", "unknown"]),
  ids: z.array(z.string().regex(/^[A-Za-z0-9._:-]{3,64}$/)).min(1).max(10),
  aliases: z.array(z.string().regex(/^CVE-\d{4}-\d{3,9}$/)).max(5).default([]),
  fixed: z.string().regex(/^[\w.+-]{1,64}$/).nullable().default(null),
  summary: z.string().max(300).nullable().default(null),
});
export const reportSchema = z.object({
  host: z.string().min(1).max(300),
  ecosystem: z.enum(["npm", "packagist"]),
  observedAt: z.iso.datetime({ offset: true }),
  packages: z.array(pkg).max(200),
});
export type PackageReport = z.infer<typeof reportSchema>;

type Result = { status: number; body: Record<string, unknown> };
const err = (status: number, code: string): Result => ({ status, body: { error: { code } } });

/** Verifies the signature and stores the report (a newer report replaces an older one; an older one is ignored). */
export async function receivePackageReport(h: { timestamp?: string | null; signature?: string | null }, body: string, now = new Date()): Promise<Result> {
  const auth = webmonitorAdapter().verifyHandoff(h, body, now.getTime());
  if (!auth.ok) return err(auth.status, auth.code);
  let r: PackageReport;
  let host: string;
  try {
    const parsed = reportSchema.safeParse(JSON.parse(body));
    if (!parsed.success) return err(422, "invalid_report");
    r = parsed.data;
    host = parseHost(r.host);
  } catch (e) {
    return err(422, isAppError(e) ? "invalid_host" : "invalid_report");
  }
  const observed = new Date(r.observedAt);
  if (observed.getTime() > now.getTime() + 5 * 60_000) return err(422, "observed_in_future");
  await db.execute(sql`
    INSERT INTO webmonitor_package_reports (host, ecosystem, packages, observed_at, received_at)
    VALUES (${host}, ${r.ecosystem}, ${JSON.stringify(r.packages)}::jsonb, ${observed}, ${now})
    ON CONFLICT (host) DO UPDATE SET ecosystem = excluded.ecosystem, packages = excluded.packages,
      observed_at = excluded.observed_at, received_at = excluded.received_at
    WHERE webmonitor_package_reports.observed_at <= excluded.observed_at`);
  return { status: 202, body: { status: "received", host, packages: r.packages.length } };
}

export interface StoredReport { host: string; ecosystem: "npm" | "packagist"; packages: PackageReport["packages"]; observedAt: Date }

/** The newest report for the host, or for its www./bare twin (WebMonitor may monitor either form). */
export async function lookupPackageReport(host: string): Promise<StoredReport | null> {
  const twin = host.startsWith("www.") ? host.slice(4) : `www.${host}`;
  const r = await db.execute<{ host: string; ecosystem: "npm" | "packagist"; packages: PackageReport["packages"]; observed_at: string | Date }>(sql`
    SELECT host, ecosystem, packages, observed_at FROM webmonitor_package_reports
    WHERE host IN (${host}, ${twin}) ORDER BY observed_at DESC LIMIT 1`);
  const row = r.rows[0];
  return row ? { host: row.host, ecosystem: row.ecosystem, packages: row.packages, observedAt: new Date(row.observed_at) } : null;
}

const SEVERITY: Record<PackageReport["packages"][number]["severity"], Severity> = { critical: "critical", high: "high", moderate: "medium", low: "low", unknown: "medium" };
const REGISTRY = { npm: "npm", packagist: "Composer" } as const;

/** Finding keys allow [a-z0-9_.-] only: "@scope/name" becomes "pkg.npm._scope_name". */
export const packageIssueKey = (ecosystem: string, name: string) => `pkg.${ecosystem}.${name.toLowerCase().replace(/[^a-z0-9_.-]/g, "_")}`.slice(0, 80);
const MAX_FINDINGS = 50;

/** One finding per vulnerable package, keyed by package: a FixProof re-test passes once a fresh report no longer lists it. Pure. */
export function packageFindings(host: string, report: StoredReport): FindingCandidate[] {
  return report.packages.map((p) => {
    const ref = p.aliases[0] ?? p.ids[0];
    const more = p.ids.length > 1 ? ` and ${p.ids.length - 1} more advisor${p.ids.length === 2 ? "y" : "ies"}` : "";
    return {
      issueKey: packageIssueKey(report.ecosystem, p.name),
      title: `${p.name} ${p.version} has a known vulnerability (${ref}${more})`,
      severity: SEVERITY[p.severity],
      location: `https://${host}/ (${REGISTRY[report.ecosystem]} package ${p.name})`,
      evidence: {
        source: "WebMonitor integration (installed packages) + OSV.dev", ecosystem: report.ecosystem, package: p.name, installed: p.version,
        advisories: p.ids, cves: p.aliases, fixedIn: p.fixed, summary: p.summary, reportObservedAt: report.observedAt.toISOString(),
      },
      remediation: p.fixed
        ? `Update ${p.name} to ${p.fixed} or later (${report.ecosystem === "npm" ? `npm install ${p.name}@^${p.fixed}` : `composer require ${p.name}:^${p.fixed}`}), redeploy, then re-test. WebMonitor reports the new version within about 12 hours.`
        : `No fixed release of ${p.name} yet. Read the advisory (${p.ids[0]}) for a workaround, or replace the package. WebMonitor keeps checking.`,
    };
  });
}

export function createWebMonitorPackagesAdapter(deps: { lookup?: typeof lookupPackageReport; now?: () => Date } = {}): CheckAdapter {
  const lookup = deps.lookup ?? lookupPackageReport;
  return {
    id: "webmonitor.packages@1", checkKey: "webmonitor.packages",
    async run(c): Promise<CheckResult> {
      const now = (c.now ?? deps.now ?? (() => new Date()))();
      const report = await lookup(c.host);
      // Never reported: the site is not monitored by WebMonitor (or has no packages to report), so nothing to judge.
      if (!report) return { status: "ok", findings: [], evidence: { webmonitorReport: "none" } };
      // Too old to trust: an error keeps open findings open instead of closing them on stale data.
      if (now.getTime() - report.observedAt.getTime() > REPORT_MAX_AGE_MS) {
        return { status: "error", reason: "webmonitor_report_stale", evidence: { reportObservedAt: report.observedAt.toISOString() } };
      }
      // Past the per-check cap it is an error, never a truncated list that would close the dropped findings.
      if (report.packages.length > MAX_FINDINGS) {
        return { status: "error", reason: "too_many_findings", evidence: { vulnerablePackages: report.packages.length, max: MAX_FINDINGS } };
      }
      return {
        status: "ok", findings: packageFindings(c.host, report),
        evidence: { reportHost: report.host, ecosystem: report.ecosystem, reportObservedAt: report.observedAt.toISOString(), vulnerablePackages: report.packages.length },
      };
    },
  };
}
