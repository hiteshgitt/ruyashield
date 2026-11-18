import type { SecuritySummary } from "./summary";
import type { Block, Rgb } from "../richpdf";
import { SEVERITY_COLOR } from "../richpdf";
import { SECTIONS, type ReportDetail, type ResolvedOptions } from "./content";


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

// ---------- formatted report (sections chosen by preset or by hand) ----------


const day = (x: Date | null | undefined) => (x ? new Date(x).toISOString().slice(0, 10) : "-");
const words = (s: string) => s.replace(/_/g, " ");
const GOOD: Rgb = [0.13, 0.6, 0.38];

export function reportTitle(o: ResolvedOptions, orgName: string) {
  return o.title || `${o.preset === "executive" ? "Executive security summary" : o.preset === "technical" ? "Technical security report" : "Security report"} - ${orgName}`;
}

export function reportBlocks(s: SecuritySummary, detail: ReportDetail, o: ResolvedOptions, orgName: string): Block[] {
  const has = (k: keyof typeof SECTIONS) => o.sections.includes(k);
  const scope = s.scope.clientGroupName ? `Client group: ${s.scope.clientGroupName}` : s.scope.restrictedToGroups ? "Scope: your assigned client groups" : "Scope: all assets";
  const sev = s.findings.open;
  const B: Block[] = [
    { t: "cover", title: reportTitle(o, orgName), subtitle: orgName, meta: [scope, `Generated ${d(s.generatedAt)} - activity window: last ${s.windowDays} days`, `Sections: ${o.sections.map((k) => SECTIONS[k].label).join(", ")}`] },
  ];

  // Summary (always)
  B.push({ t: "h1", text: "Summary" });
  B.push({ t: "stats", items: [
    { label: "Open findings", value: String(s.findings.openTotal), tone: sev.critical + sev.high ? SEVERITY_COLOR.critical : s.findings.openTotal ? SEVERITY_COLOR.medium : GOOD },
    { label: "Critical / high", value: `${sev.critical} / ${sev.high}`, tone: sev.critical ? SEVERITY_COLOR.critical : sev.high ? SEVERITY_COLOR.high : GOOD },
    { label: "Fixed and re-tested", value: String(s.findings.resolvedVerifiedInWindow), tone: GOOD },
    { label: "Past due date", value: String(s.findings.overdue), tone: s.findings.overdue ? SEVERITY_COLOR.high : GOOD },
    { label: "Assets", value: String(s.assets.total) },
    { label: "Verified assets", value: String(s.assets.verified), tone: GOOD },
    { label: "Assessments", value: String(s.assessments.total) },
    { label: "Last completed", value: day(s.assessments.lastCompletedAt) },
  ] });
  B.push({ t: "p", text: `Open findings by severity: critical ${sev.critical}, high ${sev.high}, medium ${sev.medium}, low ${sev.low}, info ${sev.info}. Untriaged critical: ${s.findings.untriagedCritical}.`, muted: true });
  B.push({ t: "h2", text: "Highest-priority open findings" });
  if (s.topOpen.length) for (const f of s.topOpen.slice(0, has("findings") ? 5 : 10)) B.push({ t: "finding", severity: f.severity, title: f.title, meta: `${f.host} - ${words(f.status)}${f.dueAt ? ` - due ${day(f.dueAt)}` : ""}` });
  else B.push({ t: "p", text: "No open findings in the assessed scope. This reflects the checks that ran, not a guarantee that no issues exist.", muted: true });
  B.push({ t: "note", text: NOT_A_CERTIFICATION });

  if (has("assets")) {
    B.push({ t: "h1", text: "Assets" });
    B.push({ t: "table", head: ["Asset", "Ownership", "Last assessment", "Open: crit / high / med / low"], widths: [3.2, 1.4, 2, 2.2],
      rows: detail.assets.map((a) => [`${a.name} (${a.host})`, `${words(a.status)}${a.verifiedAt ? `, ${day(a.verifiedAt)}` : ""}`, a.lastStatus ? `${words(a.lastStatus)}, ${day(a.lastFinishedAt)}` : "never", `${a.open.critical} / ${a.open.high} / ${a.open.medium} / ${a.open.low}`]) });
  }

  if (has("findings")) {
    B.push({ t: "h1", text: "Open findings" });
    B.push({ t: "p", text: `${detail.findingsTotal} open finding${detail.findingsTotal === 1 ? "" : "s"} of ${o.minSeverity} severity or higher, highest priority first${detail.findingsTotal > detail.findings.length ? `; the first ${detail.findings.length} are listed` : ""}.`, muted: true });
    for (const f of detail.findings) {
      B.push({ t: "finding", severity: f.severity, title: f.title, meta: `${f.host} - ${f.location} - ${words(f.status)} - first seen ${day(f.firstSeen)}${f.dueAt ? ` - due ${day(f.dueAt)}` : ""}`, body: f.remediation ? `Fix: ${f.remediation}` : undefined });
    }
    if (!detail.findings.length) B.push({ t: "p", text: "None at this severity in the assessed scope.", muted: true });
  }

  if (has("verification")) {
    const v = s.verification;
    B.push({ t: "h1", text: "Fix verification" });
    B.push({ t: "stats", items: [
      { label: "Verified", value: String(v.verified), tone: GOOD },
      { label: "Partially verified", value: String(v.partiallyVerified), tone: SEVERITY_COLOR.medium },
      { label: "Failed", value: String(v.failed), tone: v.failed ? SEVERITY_COLOR.critical : GOOD },
      { label: "Inconclusive / not run", value: String(v.unverified + v.notRun) },
    ] });
    B.push({ t: "p", text: "Only a verified re-test confirms a fix. Failed, partial and inconclusive re-tests are listed below.", muted: true });
    B.push({ t: "table", head: ["Finding", "Asset", "Outcome", "Finished"], widths: [3.4, 2, 1.4, 1.2], rows: s.failedVerifications.map((x) => [x.title, x.host, words(x.outcome), day(x.finishedAt)]) });
  }

  if (has("assessments")) {
    const a = s.assessments;
    B.push({ t: "h1", text: "Assessments and coverage" });
    B.push({ t: "p", text: `In the last ${s.windowDays} days: ${a.total} assessments; ${a.completed} completed, ${a.completedWithErrors} completed with errors, ${a.failed} failed, timed out or rejected. Last completed ${day(a.lastCompletedAt)}.` });
    B.push({ t: "h2", text: "Assessments that did not complete every check" });
    B.push({ t: "table", head: ["Asset", "Status", "Checks", "Reason"], widths: [2.4, 1.6, 2.6, 2.4], rows: s.incompleteAssessments.map((x) => [x.host, words(x.status), x.coverage ? `${x.coverage.ok}/${x.coverage.planned} ok, ${x.coverage.error} error, ${x.coverage.timeout} timeout, ${x.coverage.skipped} skipped` : "-", x.reason ?? "-"]) });
  }

  if (has("risks")) {
    B.push({ t: "h1", text: "Accepted risks" });
    B.push({ t: "p", text: "Accepted risks remain open and are not counted as resolved.", muted: true });
    B.push({ t: "table", head: ["Finding", "Severity", "Asset", "Justification", "Expires"], widths: [2.6, 1, 1.8, 3, 1.2], rows: s.acceptedRisks.map((r) => [r.title, r.severity, r.host, r.justification, day(r.expiresAt)]) });
  }

  if (has("attacks")) {
    const at = detail.attacks;
    B.push({ t: "h1", text: "Attack monitoring" });
    if (!at || at.coverage === "none") {
      B.push({ t: "p", text: "No attack source (Cloudflare or log agent) covers these assets, so there is no attack data. This is not the same as no attacks.", muted: true });
    } else {
      B.push({ t: "stats", items: [
        { label: "Hostile requests", value: String(at.total), tone: SEVERITY_COLOR.high },
        { label: "Unique IPs", value: String(at.uniqueIps) },
        { label: "Countries", value: String(at.countries) },
        { label: "Blocked", value: String(at.blocked), tone: GOOD },
      ] });
      B.push({ t: "table", head: ["Attack type", "Requests"], widths: [4, 1], rows: at.byType.slice(0, 8).map((x) => [x.label, String(x.n)]) });
      B.push({ t: "table", head: ["Country", "Requests"], widths: [4, 1], rows: at.byCountry.slice(0, 8).map((x) => [x.country ?? "Unknown", String(x.n)]) });
    }
  }

  B.push({ t: "h1", text: "Limitations" });
  B.push({ t: "bullets", items: LIMITATIONS, muted: true });
  return B;
}

/** CSV of the same report: the summary rows plus the chosen detail sections. */
export function reportCsvDetailed(s: SecuritySummary, detail: ReportDetail, o: ResolvedOptions, orgName: string): string {
  const base = reportCsv(s, orgName).trimEnd().split("\r\n");
  const footer = base.pop()!;
  const extra: unknown[][] = [];
  extra.push(["meta", "title", reportTitle(o, orgName), "", ""]);
  extra.push(["meta", "sections", o.sections.join(" "), "", ""]);
  for (const a of detail.assets) extra.push(["asset", a.host, `${a.name}; last assessment ${a.lastStatus ?? "never"}; open critical ${a.open.critical}, high ${a.open.high}, medium ${a.open.medium}, low ${a.open.low}`, a.status, a.lastFinishedAt]);
  for (const f of detail.findings) extra.push(["finding", f.title, `${f.host} ${f.location}${f.remediation ? ` | fix: ${f.remediation}` : ""}`, `${f.severity}/${f.status}`, f.dueAt]);
  if (detail.attacks && detail.attacks.coverage !== "none") for (const t of detail.attacks.byType) extra.push(["attack_type", t.label, t.n, "", ""]);
  return [...base, ...extra.map((r) => r.map(csvCell).join(",")), footer].join("\r\n") + "\r\n";
}
