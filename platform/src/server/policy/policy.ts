import { withOrg } from "../db/client";
import { audit } from "../audit/audit";
import { AppError } from "../errors";
import {
  BREAK_GLASS_ACTIONS, grantFor, KILL_AI_ACTIONS, KILL_SCANNING_ACTIONS, MFA_REQUIRED_ROLES, STEP_UP_ACTIONS, TOKEN_SCOPE_ACTIONS,
  type Action, type Role, type TokenScope,
} from "./matrix";

export const STEP_UP_MAX_AGE_MS = 15 * 60 * 1000;

/** Who is acting, loaded fresh from the database on every request. */
export interface Principal {
  userId: string;
  orgId: string;
  role: Role;
  /** Restricted members see only their assigned client groups for "S" grants. */
  restricted: boolean;
  clientGroupIds: readonly string[];
  mfa: boolean;
  authTime: Date;
  ip?: string | null;
  requestId?: string | null;
  /** Set when the request authenticated with an API token: the token can do no more than these scopes allow. */
  tokenScopes?: readonly TokenScope[];
  /** Set for an operator's time-boxed support session: read-only, never a member (RS-PLAT-007). */
  breakGlassId?: string;
}

export interface OrgFlags {
  killScanning: boolean;
  killAi: boolean;
}

export interface Resource {
  type?: string;
  id?: string;
  clientGroupId?: string | null;
  ownerId?: string | null;
  /** For approvals: the person who asked; nobody may approve their own request. */
  requesterId?: string | null;
}

export type Decision =
  | { allow: true; needsSecondPerson: boolean }
  | { allow: false; status: 401 | 403 | 409 | 423; code: string };

const deny = (status: 401 | 403 | 409 | 423, code: string): Decision => ({ allow: false, status, code });

/** Pure decision function: deny by default (RS-IAM-004). */
export function decide(p: Principal, action: Action, r: Resource, org: OrgFlags, now = new Date()): Decision {
  if (p.breakGlassId) {
    if (!p.mfa) return deny(401, "step_up_required");
    return BREAK_GLASS_ACTIONS.has(action) ? { allow: true, needsSecondPerson: false } : deny(403, "break_glass_read_only");
  }
  if (p.tokenScopes && !p.tokenScopes.some((s) => (TOKEN_SCOPE_ACTIONS[s] as readonly Action[]).includes(action))) {
    return deny(403, "insufficient_scope");
  }
  if (MFA_REQUIRED_ROLES.has(p.role) && !p.mfa) return deny(401, "step_up_required");

  const grant = grantFor(p.role, action);
  if (grant === "N" || grant === "Sys") return deny(403, "forbidden");

  if (grant === "S") {
    const owns = r.ownerId != null && r.ownerId === p.userId;
    const inGroup = !p.restricted || (r.clientGroupId != null && p.clientGroupIds.includes(r.clientGroupId));
    if (!owns && !inGroup) return deny(403, "forbidden");
  }

  if (action === "approval.decide" && r.requesterId != null && r.requesterId === p.userId) {
    return deny(403, "self_approval");
  }

  if (org.killScanning && KILL_SCANNING_ACTIONS.has(action)) return deny(423, "kill_switch_engaged");
  if (org.killAi && KILL_AI_ACTIONS.has(action)) return deny(423, "kill_switch_engaged");

  if (STEP_UP_ACTIONS.has(action) && now.getTime() - p.authTime.getTime() > STEP_UP_MAX_AGE_MS) {
    return deny(401, "step_up_required");
  }

  return { allow: true, needsSecondPerson: grant === "A" };
}

/**
 * Enforces a decision. Denials are audited as authz.denied in their own transaction, so the record
 * survives the caller's transaction rolling back when the AppError propagates.
 */
export async function authorize(p: Principal, action: Action, r: Resource, org: OrgFlags): Promise<{ needsSecondPerson: boolean }> {
  const d = decide(p, action, r, org);
  if (d.allow && p.breakGlassId) {
    // Every read during operator support access is recorded in the tenant's own chain (RS-PLAT-007).
    await withOrg(p.orgId, (tx) => audit(tx, {
      actor: { type: "user", id: p.userId, ip: p.ip }, action: "operator.action",
      target: r.type && r.id ? { type: r.type, id: r.id } : null, requestId: p.requestId,
      details: { attempted: action, session: p.breakGlassId },
    }));
  }
  if (d.allow) return { needsSecondPerson: d.needsSecondPerson };
  await withOrg(p.orgId, (tx) => audit(tx, {
    actor: { type: "user", id: p.userId, ip: p.ip },
    action: "authz.denied",
    target: r.type && r.id ? { type: r.type, id: r.id } : null,
    outcome: "denied",
    reason: d.code,
    requestId: p.requestId,
    details: { attempted: action, role: p.role, ...(p.tokenScopes ? { via: "api_token" } : {}), ...(p.breakGlassId ? { via: "break_glass", session: p.breakGlassId } : {}) },
  }));
  throw new AppError(d.status, d.code);
}
