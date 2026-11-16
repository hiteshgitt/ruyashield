import type { SecuritySummary } from "./summary";

// Pure report renderers (RS-RPT-002). Both formats carry the same sections, so a CSV reader and a PDF reader
// see the same failed checks, accepted risks and limitations.

export const NOT_A_CERTIFICATION =
  "This report is not a certification, audit opinion or compliance attestation. It summarizes automated, non-intrusive checks that ran against verified, in-scope assets.";
export const LIMITATIONS = [
  "Only assets with verified ownership or recorded written authorization were assessed.",
  "Assessments are non-intrusive and do not attempt exploitation; issues that need authenticated or intrusive testing are not covered.",
  "Checks that errored, timed out or were skipped are listed as incomplete coverage, not as passed.",
  "A finding counts as resolved only after a verification re-test confirmed the fix. Failed, partial and inconclusive re-tests are listed separately.",
  "Accepted risks remain open risks. They are listed separately and are not counted as resolved.",
  "Results reflect the time of each check; the environment may have changed since.",
];
export const FOOTER = "Generated with RuyaShield";

const d = (x: Date | null | undefined) => (x ? new Date(x).toISOString().replace("T", " ").slice(0, 16) + " UTC" : "-");

export function reportLines(s: SecuritySummary, orgName: string): string[] {
  const scope = s.scope.clientGroupName ? `Client group: ${s.scope.clientGroupName}` : s.scope.restrictedToGroups ? "Scope: your assigned client groups" : "Scope: all assets";
  const L: string[] = [
    `Security summary - ${orgName}`, scope, `Generated ${d(s.generatedAt)}; activity window: last ${s.windowDays} days`, "",
    NOT_A_CERTIFICATION, "",
    "ASSETS",
    `  Total ${s.assets.total}; verified ${s.assets.verified}; unverified ${s.assets.unverified}; lapsed or revoked ${s.assets.lapsedOrRevoked}`, "",
    "OPEN FINDINGS",
    `  Total ${s.findings.openTotal}: critical ${s.findings.open.critical}, high ${s.findings.open.high}, medium ${s.findings.open.medium}, low ${s.findings.open.low}, info ${s.findings.open.info}`,
    `  Untriaged critical: ${s.findings.untriagedCritical}`,
    `  Past due date: ${s.findings.overdue}`,
    `  Resolved with a verified re-test (window): ${s.findings.resolvedVerifiedInWindow}`, "",
    "VERIFICATION RE-TESTS (window)",
    `  Verified ${s.verification.verified}; partially verified ${s.verification.partiallyVerified}; failed ${s.verification.failed}; inconclusive ${s.verification.unverified}; not run ${s.verification.notRun}`, "",
    "ASSESSMENTS (window)",
    `  Completed ${s.assessments.completed}; completed with errors ${s.assessments.completedWithErrors}; failed, timed out or rejected ${s.assessments.failed}; last completed ${d(s.assessments.lastCompletedAt)}`, "",
    "HIGHEST-PRIORITY OPEN FINDINGS",
    ...(s.topOpen.length ? s.topOpen.map((f) => `  [${f.severity}] ${f.title} - ${f.host} - ${f.status} - due ${d(f.dueAt)}`) : ["  None in the assessed scope (this is not a guarantee that no issues exist)."]), "",
    "FAILED OR INCONCLUSIVE VERIFICATION RE-TESTS",
    ...(s.failedVerifications.length ? s.failedVerifications.map((v) => `  ${v.title} - ${v.host} - ${v.outcome} - ${d(v.finishedAt)}`) : ["  None"]), "",
    "INCOMPLETE ASSESSMENTS",
    ...(s.incompleteAssessments.length ? s.incompleteAssessments.map((a) => `  ${a.host} - ${a.status}${a.coverage ? ` - ${a.coverage.ok}/${a.coverage.planned} checks ok, ${a.coverage.error} error, ${a.coverage.timeout} timeout, ${a.coverage.skipped} skipped` : ""}${a.reason ? ` - ${a.reason}` : ""}`) : ["  None"]), "",
    "ACCEPTED RISKS (still open; not counted as resolved)",
    ...(s.acceptedRisks.length ? s.acceptedRisks.map((r) => `  [${r.severity}] ${r.title} - ${r.host} - expires ${d(r.expiresAt)} - ${r.justification}`) : ["  None"]), "",
    "LIMITATIONS",
    ...LIMITATIONS.map((l) => `  - ${l}`), "",
    FOOTER,
  ];
  return L;
}

/** CSV cell: quoted, and a leading formula character is neutralized so spreadsheets don't execute it. */
export function csvCell(v: unknown): string {
  let s = v == null ? "" : v instanceof Date ? v.toISOString() : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return `"${s.replace(/"/g, '""')}"`;
}

export function reportCsv(s: SecuritySummary, orgName: string): string {
  const rows: unknown[][] = [["section", "item", "detail", "status", "date"]];
  const add = (...r: unknown[]) => rows.push(r);
  add("meta", "organization", orgName, "", s.generatedAt);
  add("meta", "scope", s.scope.clientGroupName ?? (s.scope.restrictedToGroups ? "assigned client groups" : "all assets"), "", "");
  add("meta", "window_days", s.windowDays, "", "");
  add("meta", "statement", NOT_A_CERTIFICATION, "", "");
  for (const [k, v] of Object.entries(s.assets)) add("assets", k, v, "", "");
  for (const [k, v] of Object.entries(s.findings.open)) add("open_findings", k, v, "", "");
  add("open_findings", "untriaged_critical", s.findings.untriagedCritical, "", "");
  add("open_findings", "overdue", s.findings.overdue, "", "");
  add("open_findings", "resolved_verified_in_window", s.findings.resolvedVerifiedInWindow, "", "");
  for (const [k, v] of Object.entries(s.verification)) add("verification", k, v, "", "");
  for (const [k, v] of Object.entries(s.assessments)) add("assessments", k, v instanceof Date ? "" : v, "", v instanceof Date ? v : "");
  for (const f of s.topOpen) add("top_open_finding", f.title, f.host, `${f.severity}/${f.status}`, f.dueAt);
  for (const v of s.failedVerifications) add("failed_verification", v.title, v.host, v.outcome, v.finishedAt);
  for (const a of s.incompleteAssessments) add("incomplete_assessment", a.host, a.reason ?? "", a.status, a.finishedAt);
  for (const r of s.acceptedRisks) add("accepted_risk", r.title, `${r.host}: ${r.justification}`, r.severity, r.expiresAt);
  for (const l of LIMITATIONS) add("limitation", l, "", "", "");
  add("footer", FOOTER, "", "", "");
  return rows.map((r) => r.map(csvCell).join(",")).join("\r\n") + "\r\n";
}
