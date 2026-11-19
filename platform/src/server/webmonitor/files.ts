import { sql } from "drizzle-orm";
import { z } from "zod";
import { db } from "../db/client";
import { parseHost } from "../assets/host";
import { isAppError } from "../errors";
import type { CheckAdapter, CheckResult, FindingCandidate } from "../assessments/checks";
import type { Severity } from "../db/schema";
import { webmonitorAdapter } from "./adapter";

// Suspicious-file reports from WebMonitor's read-only in-site scanner, signed like referral handoffs. The
// webmonitor.files check turns the latest report into findings (file, line, rule, snippet) for verified assets.

export const MAX_FILE_REPORT_BYTES = 256 * 1024;
export const FILE_REPORT_MAX_AGE_MS = 3 * 24 * 3600 * 1000;
const MAX_FINDINGS = 50;

const finding = z.object({
  id: z.string().regex(/^[\w-]{4,40}$/),
  path: z.string().min(1).max(300),
  line: z.number().int().min(0).max(10_000_000),
  rule: z.string().regex(/^[a-z0-9-]{2,40}$/),
  severity: z.enum(["critical", "high", "medium", "low"]),
  title: z.string().min(1).max(200),
  snippet: z.string().max(200).default(""),
});
export const fileReportSchema = z.object({
  host: z.string().min(1).max(300),
  observedAt: z.iso.datetime({ offset: true }),
  complete: z.boolean(),
  findings: z.array(finding).max(300),
});
export type FileReport = z.infer<typeof fileReportSchema>;

type Result = { status: number; body: Record<string, unknown> };
const err = (status: number, code: string): Result => ({ status, body: { error: { code } } });

export async function receiveFileReport(h: { timestamp?: string | null; signature?: string | null }, body: string, now = new Date()): Promise<Result> {
  const auth = webmonitorAdapter().verifyHandoff(h, body, now.getTime());
  if (!auth.ok) return err(auth.status, auth.code);
  let r: FileReport;
  let host: string;
  try {
    const parsed = fileReportSchema.safeParse(JSON.parse(body));
    if (!parsed.success) return err(422, "invalid_report");
    r = parsed.data;
    host = parseHost(r.host);
  } catch (e) {
    return err(422, isAppError(e) ? "invalid_host" : "invalid_report");
  }
  const observed = new Date(r.observedAt);
  if (observed.getTime() > now.getTime() + 5 * 60_000) return err(422, "observed_in_future");
  await db.execute(sql`
    INSERT INTO webmonitor_file_reports (host, findings, complete, observed_at, received_at)
    VALUES (${host}, ${JSON.stringify(r.findings)}::jsonb, ${r.complete}, ${observed}, ${now})
    ON CONFLICT (host) DO UPDATE SET findings = excluded.findings, complete = excluded.complete, observed_at = excluded.observed_at, received_at = excluded.received_at
    WHERE webmonitor_file_reports.observed_at <= excluded.observed_at`);
  return { status: 202, body: { status: "received", host, findings: r.findings.length } };
}

export interface StoredFileReport { host: string; findings: FileReport["findings"]; complete: boolean; observedAt: Date }

export async function lookupFileReport(host: string): Promise<StoredFileReport | null> {
  const twin = host.startsWith("www.") ? host.slice(4) : `www.${host}`;
  const r = await db.execute<{ host: string; findings: FileReport["findings"]; complete: boolean; observed_at: string | Date }>(sql`
    SELECT host, findings, complete, observed_at FROM webmonitor_file_reports WHERE host IN (${host}, ${twin}) ORDER BY observed_at DESC LIMIT 1`);
  const row = r.rows[0];
  return row ? { host: row.host, findings: row.findings, complete: row.complete, observedAt: new Date(row.observed_at) } : null;
}

const SEVERITY: Record<FileReport["findings"][number]["severity"], Severity> = { critical: "critical", high: "high", medium: "medium", low: "low" };
export const fileIssueKey = (f: { rule: string; path: string }) => `file.${f.rule}.${f.path.toLowerCase().replace(/[^a-z0-9_.-]/g, "_")}`.slice(0, 80);

/** One finding per (rule, file). Pure. */
export function fileFindings(host: string, report: StoredFileReport): FindingCandidate[] {
  const seen = new Set<string>();
  const out: FindingCandidate[] = [];
  for (const f of report.findings) {
    const key = fileIssueKey(f);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({
      issueKey: key,
      title: `${f.title}: ${f.path}`.slice(0, 200),
      severity: SEVERITY[f.severity],
      location: `https://${host}/ (file ${f.path}${f.line ? `, line ${f.line}` : ""})`.slice(0, 300),
      evidence: { source: "WebMonitor file scan (read-only, inside the site)", path: f.path, line: f.line, rule: f.rule, snippet: f.snippet, reportObservedAt: report.observedAt.toISOString() },
      remediation: f.rule.startsWith("core-")
        ? "Reinstall WordPress core from the official package (Dashboard → Updates → Re-install), then re-test. If a file was added, delete it after checking it is not yours, and change admin, FTP and database passwords."
        : `Open ${f.path}${f.line ? ` at line ${f.line}` : ""}. If the code is not yours, take a backup, delete or restore the file from a clean copy, change admin, FTP and database passwords, update everything, then re-test. WebMonitor's next full scan confirms it is gone.`,
    });
  }
  return out;
}

export function createWebMonitorFilesAdapter(deps: { lookup?: typeof lookupFileReport; now?: () => Date } = {}): CheckAdapter {
  const lookup = deps.lookup ?? lookupFileReport;
  return {
    id: "webmonitor.files@1", checkKey: "webmonitor.files",
    async run(c): Promise<CheckResult> {
      const now = (c.now ?? deps.now ?? (() => new Date()))();
      const report = await lookup(c.host);
      if (!report) return { status: "ok", findings: [], evidence: { webmonitorReport: "none" } };
      if (now.getTime() - report.observedAt.getTime() > FILE_REPORT_MAX_AGE_MS) {
        return { status: "error", reason: "webmonitor_report_stale", evidence: { reportObservedAt: report.observedAt.toISOString() } };
      }
      // A partial pass cannot prove a file is clean: only a complete one may show fewer findings than before.
      const findings = fileFindings(c.host, report);
      if (findings.length > MAX_FINDINGS) return { status: "error", reason: "too_many_findings", evidence: { findings: findings.length, max: MAX_FINDINGS } };
      if (!report.complete && findings.length === 0) return { status: "error", reason: "webmonitor_scan_in_progress", evidence: { reportObservedAt: report.observedAt.toISOString() } };
      return { status: "ok", findings, evidence: { reportHost: report.host, complete: report.complete, reportObservedAt: report.observedAt.toISOString(), findings: findings.length } };
    },
  };
}
