import { describe, expect, it } from "vitest";
import { decide, type Principal } from "@/server/policy/policy";
import { ACTIONS, BREAK_GLASS_ACTIONS, STEP_UP_ACTIONS, TOKEN_SCOPE_ACTIONS, TOKEN_SCOPES, type Role } from "@/server/policy/matrix";
import { isOperator } from "@/server/operator/breakglass";
import { textPdf } from "@/server/pdf";
import { csvCell, LIMITATIONS, NOT_A_CERTIFICATION, reportCsv, reportLines } from "@/server/reports/render";
import { isSecurityCritical, NOTIFY_KINDS } from "@/server/notifications/notifications";
import type { SecuritySummary } from "@/server/reports/summary";

const now = new Date("2026-11-01T12:00:00Z");
const p = (role: Role, extra: Partial<Principal> = {}): Principal => ({
  userId: "u1", orgId: "o1", role, restricted: false, clientGroupIds: [], mfa: true, authTime: now, ...extra,
});
const open = { killScanning: false, killAi: false };

describe("API token scopes", () => {
  it("allow only the actions their scopes list, even for an org admin", () => {
    const t = p("org_admin", { tokenScopes: ["findings:read"], authTime: new Date(0) });
    expect(decide(t, "finding.view", {}, open, now).allow).toBe(true);
    expect(decide(t, "asset.view", {}, open, now)).toMatchObject({ allow: false, code: "insufficient_scope" });
    expect(decide(t, "finding.triage", {}, open, now)).toMatchObject({ allow: false, code: "insufficient_scope" });
  });

  it("never reach a step-up action", () => {
    for (const s of TOKEN_SCOPES) for (const a of TOKEN_SCOPE_ACTIONS[s]) expect(STEP_UP_ACTIONS.has(a)).toBe(false);
    const all = p("org_admin", { tokenScopes: TOKEN_SCOPES, authTime: new Date(0) });
    for (const a of STEP_UP_ACTIONS) expect(decide(all, a, {}, open, now).allow).toBe(false);
  });

  it("cannot exceed the creator's role", () => {
    const t = p("viewer", { tokenScopes: ["reports:generate"], authTime: new Date(0) });
    expect(decide(t, "report.generate", {}, open, now).allow).toBe(decide(p("viewer"), "report.generate", {}, open, now).allow);
  });
});

describe("break-glass", () => {
  it("is read-only whatever the role", () => {
    const b = p("org_admin", { breakGlassId: "bg1" });
    for (const a of ACTIONS) expect(decide(b, a, {}, open, now).allow).toBe(BREAK_GLASS_ACTIONS.has(a));
    expect(decide(b, "finding.triage", {}, open, now)).toMatchObject({ code: "break_glass_read_only" });
    expect(decide(p("viewer", { breakGlassId: "bg1", mfa: false }), "finding.view", {}, open, now)).toMatchObject({ code: "step_up_required" });
  });

  it("names operators only from the allowlist", () => {
    expect(isOperator("ops@example.com", " Ops@Example.com , b@example.com")).toBe(true);
    expect(isOperator("x@example.com", "ops@example.com")).toBe(false);
    expect(isOperator("ops@example.com", "")).toBe(false);
    expect(isOperator("ops@example.com", undefined)).toBe(false);
  });
});

describe("textPdf", () => {
  it("writes a well-formed PDF with a correct xref offset", () => {
    const buf = textPdf(["Hello (world) \\ test", "é non-ascii", ...Array.from({ length: 130 }, (_, i) => `line ${i}`)]);
    const s = buf.toString("latin1");
    expect(s.startsWith("%PDF-1.4\n")).toBe(true);
    expect(s.trimEnd().endsWith("%%EOF")).toBe(true);
    const xref = Number(/startxref\n(\d+)\n/.exec(s)![1]);
    expect(s.slice(xref, xref + 4)).toBe("xref");
    expect(s).toContain("/Count 3");
    expect(s).toContain("Hello \\(world\\) \\\\ test");
    expect(s).toContain("? non-ascii");
  });
});

describe("report rendering", () => {
  const summary: SecuritySummary = {
    generatedAt: now, windowDays: 30, scope: { clientGroupName: null, restrictedToGroups: false },
    assets: { total: 2, verified: 1, unverified: 1, lapsedOrRevoked: 0 },
    findings: { openTotal: 1, open: { critical: 0, high: 1, medium: 0, low: 0, info: 0 }, untriagedCritical: 0, overdue: 0, resolvedVerifiedInWindow: 0 },
    verification: { verified: 0, partiallyVerified: 0, failed: 1, unverified: 1, notRun: 0 },
    assessments: { completed: 1, completedWithErrors: 1, failed: 0, lastCompletedAt: now },
    topOpen: [{ severity: "high", title: "=HYPERLINK(\"x\")", host: "a.example", status: "open", dueAt: null }],
    failedVerifications: [{ title: "TLS", host: "a.example", outcome: "failed", finishedAt: now }],
    incompleteAssessments: [],
    acceptedRisks: [],
  } as unknown as SecuritySummary;

  it("neutralizes spreadsheet formulas and quotes cells", () => {
    expect(csvCell("=1+1")).toBe(`"'=1+1"`);
    expect(csvCell("-2")).toBe(`"'-2"`);
    expect(csvCell('a"b')).toBe(`"a""b"`);
    expect(csvCell(null)).toBe(`""`);
    expect(reportCsv(summary, "Acme")).toContain(`"'=HYPERLINK(""x"")"`);
  });

  it("always states it is not a certification and lists limitations and failed re-tests", () => {
    const lines = reportLines(summary, "Acme");
    expect(lines).toContain(NOT_A_CERTIFICATION);
    for (const l of LIMITATIONS) expect(lines).toContain(`  - ${l}`);
    expect(lines.join("\n")).toContain("TLS - a.example - failed");
    expect(reportCsv(summary, "Acme")).toContain(NOT_A_CERTIFICATION);
  });
});

describe("notification kinds", () => {
  it("marks failures, regressions, support access and deletion as security-critical", () => {
    for (const k of ["verification_failed", "regression", "regression_not_run", "killswitch", "break_glass", "org_deletion", "risk_expired"]) {
      expect(isSecurityCritical(k)).toBe(true);
    }
    expect(isSecurityCritical("assigned")).toBe(false);
    expect(isSecurityCritical("nonexistent")).toBe(false);
    expect(Object.keys(NOTIFY_KINDS).length).toBeGreaterThan(5);
  });
});
