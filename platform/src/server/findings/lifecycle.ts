import type { FindingStatus } from "../db/schema";
import type { Action } from "../policy/matrix";

/** Statuses that still need work (RS-FIND-004). */
export const OPEN_STATUSES: readonly FindingStatus[] = ["new", "triaged", "confirmed", "in_remediation", "fix_pending_verification", "reopened"];
export const ALL_STATUSES: readonly FindingStatus[] = [
  "new", "triaged", "confirmed", "false_positive", "accepted_risk", "in_remediation",
  "fix_pending_verification", "resolved_verified", "reopened", "stale",
];

export type UserTransition = { from: readonly FindingStatus[]; to: FindingStatus; action: Action; kind: string };

/**
 * Transitions a person may request. Anything not listed is refused with 422 transition_not_allowed.
 * resolved_verified, reopened and stale are never user-settable: only the system sets them, and
 * resolved_verified only after a verification re-test (P6).
 */
export const USER_TRANSITIONS: readonly UserTransition[] = [
  { kind: "triage", from: ["new"], to: "triaged", action: "finding.triage" },
  { kind: "confirm", from: ["triaged"], to: "confirmed", action: "finding.triage" },
  { kind: "false_positive", from: ["new", "triaged"], to: "false_positive", action: "finding.false_positive" },
  { kind: "reopen_false_positive", from: ["false_positive"], to: "triaged", action: "finding.false_positive" },
  { kind: "accept_risk", from: ["triaged", "confirmed"], to: "accepted_risk", action: "finding.accept_risk" },
  { kind: "revoke_risk", from: ["accepted_risk"], to: "triaged", action: "finding.accept_risk" },
  { kind: "start_remediation", from: ["confirmed", "reopened"], to: "in_remediation", action: "finding.triage" },
  { kind: "mark_fix_applied", from: ["in_remediation"], to: "fix_pending_verification", action: "remediation.mark_applied" },
];

export type SystemReason = "verified_fixed" | "verification_failed" | "redetected" | "risk_expired" | "fp_new_evidence" | "not_seen" | "seen_again"
  | "remediation_proposed" | "remediation_applied" | "regression";

const SYSTEM_TRANSITIONS: ReadonlyArray<[readonly FindingStatus[], FindingStatus, SystemReason]> = [
  [["fix_pending_verification"], "resolved_verified", "verified_fixed"],
  [["fix_pending_verification"], "reopened", "verification_failed"],
  [["fix_pending_verification", "resolved_verified"], "reopened", "redetected"],
  [["accepted_risk"], "triaged", "risk_expired"],
  [["false_positive"], "triaged", "fp_new_evidence"],
  [["new"], "stale", "not_seen"],
  [["stale"], "new", "seen_again"],
  // P5: a submitted plan starts remediation; an approved change applied (merged or by the customer) awaits re-test.
  [["confirmed", "triaged", "reopened"], "in_remediation", "remediation_proposed"],
  [["in_remediation"], "fix_pending_verification", "remediation_applied"],
  // P7: a scheduled regression re-test found a verified fix no longer holds (RS-FIXP-006).
  [["resolved_verified"], "reopened", "regression"],
];

export function userTransition(kind: string, from: FindingStatus): UserTransition | null {
  const t = USER_TRANSITIONS.find((x) => x.kind === kind);
  return t && t.from.includes(from) ? t : null;
}

export function userTransitionsFrom(from: FindingStatus): UserTransition[] {
  return USER_TRANSITIONS.filter((t) => t.from.includes(from));
}

export function systemTransitionAllowed(from: FindingStatus, to: FindingStatus, reason: SystemReason): boolean {
  return SYSTEM_TRANSITIONS.some(([f, t, r]) => f.includes(from) && t === to && r === reason);
}

export const isOpen = (s: FindingStatus) => OPEN_STATUSES.includes(s);
