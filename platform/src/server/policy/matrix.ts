// Permission matrix from PRD v2.0 §Roles & permissions (Confirmed from existing PRD).
// Y = allowed; S = only within assigned client groups / own items; A = needs a second person;
// A* = org_admin may approve only when not the requester; Sys = service identity only; N = denied.
export type Grant = "Y" | "S" | "A" | "A*" | "Sys" | "N";
export const ROLES = ["org_admin", "security_lead", "analyst", "developer", "approver", "viewer", "service"] as const;
export type Role = (typeof ROLES)[number];

type Row = readonly [Grant, Grant, Grant, Grant, Grant, Grant, Grant];

const M = {
  "org.settings.edit":        ["Y", "N", "N", "N", "N", "N", "N"],
  "members.manage":           ["Y", "N", "N", "N", "N", "N", "N"],
  "asset.edit":               ["Y", "Y", "S", "N", "N", "N", "N"],
  "asset.verify":             ["Y", "Y", "S", "N", "N", "N", "Sys"],
  "asset.attest":             ["Y", "Y", "N", "N", "N", "N", "N"],
  "asset.view":               ["Y", "Y", "S", "S", "S", "S", "Sys"],
  "scope.edit":               ["Y", "Y", "S", "N", "N", "N", "N"],
  "scope.enable_a2":          ["A", "A", "N", "N", "N", "N", "N"],
  "assessment.launch":        ["Y", "Y", "S", "N", "N", "N", "Sys"],
  "assessment.cancel":        ["Y", "Y", "S", "N", "N", "N", "Sys"],
  "finding.view":             ["Y", "Y", "S", "S", "S", "S", "Sys"],
  "finding.triage":           ["Y", "Y", "S", "N", "N", "N", "N"],
  "finding.false_positive":   ["Y", "Y", "S", "N", "N", "N", "N"],
  "finding.accept_risk":      ["Y", "Y", "N", "N", "N", "N", "N"],
  "finding.assign":           ["Y", "Y", "S", "N", "N", "N", "N"],
  "finding.comment":          ["Y", "Y", "S", "S", "S", "N", "N"],
  "evidence.download_raw":    ["Y", "Y", "S", "S", "N", "N", "Sys"],
  "ai.request":               ["Y", "Y", "S", "S", "N", "N", "N"],
  "ai.configure":             ["Y", "Y", "N", "N", "N", "N", "N"],
  "remediation.edit":         ["Y", "Y", "S", "S", "N", "N", "Sys"],
  "remediation.sandbox":      ["Y", "Y", "S", "S", "N", "N", "Sys"],
  "remediation.request_approval": ["Y", "Y", "S", "S", "N", "N", "N"],
  "approval.decide":          ["A*", "Y", "N", "N", "Y", "N", "N"],
  "approval.policy":          ["Y", "N", "N", "N", "N", "N", "N"],
  "remediation.open_pr":      ["N", "N", "N", "N", "N", "N", "Sys"],
  "remediation.mark_applied": ["Y", "Y", "S", "S", "N", "N", "N"],
  "verification.request":     ["Y", "Y", "S", "S", "N", "N", "Sys"],
  "verification.set_result":  ["N", "N", "N", "N", "N", "N", "Sys"],
  "fixproof.view":            ["Y", "Y", "S", "S", "S", "S", "N"],
  "report.generate":          ["Y", "Y", "S", "N", "S", "S", "N"],
  "integration.manage":       ["Y", "Y", "N", "N", "N", "N", "N"],
  "audit.view":               ["Y", "Y", "N", "N", "N", "N", "N"],
  "killswitch.manage":        ["Y", "Y", "N", "N", "N", "N", "N"],
  "referral.consent":         ["Y", "Y", "N", "N", "N", "N", "N"],
  // P8 (FR-050..059). Dashboard and notification preferences follow finding visibility.
  "dashboard.view":           ["Y", "Y", "S", "S", "S", "S", "N"],
  "notification.prefs":       ["Y", "Y", "Y", "Y", "Y", "Y", "N"],
  "audit.export":             ["Y", "Y", "N", "N", "N", "N", "N"],
  "token.manage":             ["Y", "Y", "N", "N", "N", "N", "N"],
  "org.delete":               ["Y", "N", "N", "N", "N", "N", "N"],
  "retention.manage":         ["Y", "N", "N", "N", "N", "N", "N"],
} as const satisfies Record<string, Row>;

export type Action = keyof typeof M;
export const ACTIONS = Object.keys(M) as Action[];

export function grantFor(role: Role, action: Action): Grant {
  return M[action][ROLES.indexOf(role)];
}

/** Actions that need a fresh authentication (auth_time ≤ 15 min) even when the role allows them. */
export const STEP_UP_ACTIONS: ReadonlySet<Action> = new Set<Action>([
  "asset.attest", "approval.decide", "approval.policy", "killswitch.manage", "members.manage",
  "scope.enable_a2", "finding.accept_risk", "integration.manage", "org.settings.edit",
  "token.manage", "org.delete", "retention.manage", "audit.export",
]);

/** Roles that must have authenticated with MFA (RS-IAM-005). */
export const MFA_REQUIRED_ROLES: ReadonlySet<Role> = new Set<Role>(["org_admin", "security_lead", "approver"]);

/** Actions blocked while the org scanning kill switch is engaged. */
export const KILL_SCANNING_ACTIONS: ReadonlySet<Action> = new Set<Action>(["assessment.launch", "verification.request"]);
export const KILL_AI_ACTIONS: ReadonlySet<Action> = new Set<Action>(["ai.request"]);

/** What each API token scope permits (FR-058). Tokens never carry write or admin actions. */
export const TOKEN_SCOPE_ACTIONS = {
  "findings:read": ["finding.view", "fixproof.view", "dashboard.view"],
  "assets:read": ["asset.view"],
  "reports:generate": ["report.generate"],
} as const satisfies Record<string, readonly Action[]>;
export type TokenScope = keyof typeof TOKEN_SCOPE_ACTIONS;
export const TOKEN_SCOPES = Object.keys(TOKEN_SCOPE_ACTIONS) as TokenScope[];

/** Operator break-glass support access is read-only (RS-PLAT-007). */
export const BREAK_GLASS_ACTIONS: ReadonlySet<Action> = new Set<Action>([
  "asset.view", "finding.view", "fixproof.view", "dashboard.view", "audit.view",
]);
