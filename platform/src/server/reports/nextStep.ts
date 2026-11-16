import type { SecuritySummary } from "./summary";
import type { AreaRow } from "./insights";

export type NextStepTone = "bad" | "warn" | "violet" | "ok";
export interface NextStep { tone: NextStepTone; title: string; detail: string; href: string; cta: string }

/**
 * The single most useful thing to do next, in priority order:
 * onboarding gaps, untriaged criticals, failed re-tests, overdue findings, no recent assessment, areas that never ran, open findings.
 * It never says "all clear": the last fallback still asks for regular re-assessment.
 */
export function nextStep(s: SecuritySummary, areas: readonly AreaRow[]): NextStep {
  const o = s.onboarding;
  if (!o.hasAsset) return { tone: "violet", title: "Add your first asset", detail: "Add a domain or repository you own or are authorized to test. Nothing is scanned until you do.", href: "/assets", cta: "Add an asset" };
  if (!o.hasVerifiedAsset) return { tone: "violet", title: "Verify that you own the asset", detail: "We only scan verified assets. Add the DNS record or file shown on the asset page.", href: "/assets", cta: "Verify ownership" };
  if (!o.hasAssessment) return { tone: "violet", title: "Run your first assessment", detail: "It takes a few minutes and only runs safe, non-intrusive checks.", href: "/assessments", cta: "Run an assessment" };
  if (!o.hasCompletedAssessment) return { tone: "violet", title: "Wait for the first assessment to finish", detail: "Results appear here as soon as it completes. Until then, nothing here means \"all clear\".", href: "/assessments", cta: "See progress" };

  const plural = (k: number, w: string) => `${k} ${w}${k === 1 ? "" : "s"}`;
  const f = s.findings;
  if (f.untriagedCritical > 0) return { tone: "bad", title: `Triage ${plural(f.untriagedCritical, "critical finding")}`, detail: "Critical issues are the most likely way in. Confirm each one and assign an owner today.", href: "/findings?status=new&severity=critical", cta: "Review criticals" };
  if (s.verification.failed > 0) return { tone: "bad", title: `${plural(s.verification.failed, "fix")} did not pass re-testing`, detail: "The issue is still present after the fix was marked done. Reopen it and try again.", href: "#failed-retests", cta: "See failed re-tests" };
  if (f.overdue > 0) return { tone: "warn", title: `${plural(f.overdue, "finding")} past the due date`, detail: "Fix them or record an accepted risk with a justification and an expiry date.", href: "/findings?status=open", cta: "Review open findings" };
  if (s.assessments.total === 0) return { tone: "warn", title: `No assessment in the last ${s.windowDays} days`, detail: "Results go stale quickly: new CVEs are published every day. Run a fresh assessment.", href: "/assessments", cta: "Run an assessment" };

  const notRun = areas.filter((a) => a.covered && a.assetsChecked === 0 && a.open === 0);
  if (notRun.length > 0) return { tone: "warn", title: `${plural(notRun.length, "security area")} never checked`, detail: `${notRun.slice(0, 3).map((a) => a.label).join(", ")}${notRun.length > 3 ? " and more" : ""}. Connect a repository or run a full assessment to cover them.`, href: "/assessments", cta: "Close the gaps" };
  if (f.openTotal > 0) return { tone: "warn", title: `Work through ${plural(f.openTotal, "open finding")}`, detail: "Start with the highest severity. Each verified fix raises your exposure score.", href: "/findings?status=open", cta: "Open findings" };
  return { tone: "ok", title: "Keep assessing regularly", detail: "No open findings from the checks that ran. That is not a guarantee: re-run assessments as your code and the CVE feeds change.", href: "/assessments", cta: "Schedule assessments" };
}

/** One plain-English state per area. Covered but never ran is "not run yet", never "clean". */
export function areaState(a: AreaRow): { cls: string; text: string } {
  if (!a.covered) return { cls: "off", text: "Not scanned by RuyaShield yet" };
  if (a.open > 0) return { cls: `sev-${a.worst}`, text: `${a.open} open · worst ${a.worst}` };
  if (a.assetsChecked === 0) return { cls: "notrun", text: "Not run yet: no result" };
  return { cls: "clean", text: `No open findings · ${a.assetsChecked} asset${a.assetsChecked === 1 ? "" : "s"} checked` };
}
