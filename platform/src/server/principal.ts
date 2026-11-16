import { and, eq, gt, isNull } from "drizzle-orm";
import { withOrg, isUuid } from "./db/client";
import { breakGlassSessions, memberClientGroups, memberships, orgs } from "./db/schema";
import type { OrgFlags, Principal } from "./policy/policy";
import type { Role } from "./policy/matrix";
import type { SessionInfo } from "./auth/session";

export interface LoadedPrincipal {
  principal: Principal;
  org: OrgFlags & {
    id: string; name: string; slug: string; aiEnabled: boolean; approverMustDiffer: boolean;
    legalHold: boolean; deletionRequestedAt: Date | null;
  };
}

type OrgRow = typeof orgs.$inferSelect;
function orgView(o: OrgRow): LoadedPrincipal["org"] {
  return {
    id: o.id, name: o.name, slug: o.slug, killScanning: o.killScanning, killAi: o.killAi, plan: o.plan,
    aiEnabled: o.aiEnabled, approverMustDiffer: o.approverMustDiffer,
    legalHold: o.legalHold, deletionRequestedAt: o.deletionRequestedAt,
  };
}

/** Loads role, client-group scope and org flags fresh from the DB (never cached). Null when not a member. */
export async function loadPrincipal(
  s: SessionInfo, orgId: string, meta: { ip?: string | null; requestId?: string | null } = {},
): Promise<LoadedPrincipal | null> {
  if (!isUuid(orgId)) return null;
  return withOrg(orgId, async (tx) => {
    const m = await tx.select().from(memberships)
      .where(and(eq(memberships.orgId, orgId), eq(memberships.userId, s.userId))).limit(1);
    if (!m[0]) return null;
    const o = await tx.select().from(orgs).where(eq(orgs.id, orgId)).limit(1);
    if (!o[0] || o[0].deletedAt) return null; // a finalized deletion ends all access (FR-059)
    const groups = await tx.select({ id: memberClientGroups.clientGroupId }).from(memberClientGroups)
      .where(and(eq(memberClientGroups.orgId, orgId), eq(memberClientGroups.userId, s.userId)));
    return {
      principal: {
        userId: s.userId, orgId, role: m[0].role as Role, restricted: m[0].restricted,
        clientGroupIds: groups.map((g) => g.id), mfa: s.mfa, authTime: s.authTime,
        ip: meta.ip ?? null, requestId: meta.requestId ?? null,
      },
      org: orgView(o[0]),
    };
  });
}

/**
 * An operator's live break-glass session for this org (RS-PLAT-007). The operator is not a member:
 * the principal is read-only (decide() allows only BREAK_GLASS_ACTIONS) and expires with the session.
 */
export async function loadBreakGlassPrincipal(
  s: SessionInfo, orgId: string, meta: { ip?: string | null; requestId?: string | null } = {}, now = new Date(),
): Promise<LoadedPrincipal | null> {
  if (!isUuid(orgId)) return null;
  return withOrg(orgId, async (tx) => {
    const bg = await tx.select().from(breakGlassSessions).where(and(
      eq(breakGlassSessions.orgId, orgId), eq(breakGlassSessions.operatorUserId, s.userId),
      isNull(breakGlassSessions.endedAt), gt(breakGlassSessions.expiresAt, now),
    )).limit(1);
    if (!bg[0]) return null;
    const o = await tx.select().from(orgs).where(eq(orgs.id, orgId)).limit(1);
    if (!o[0] || o[0].deletedAt) return null;
    return {
      principal: {
        userId: s.userId, orgId, role: "viewer", restricted: false, clientGroupIds: [],
        mfa: s.mfa, authTime: s.authTime, ip: meta.ip ?? null, requestId: meta.requestId ?? null,
        breakGlassId: bg[0].id,
      },
      org: orgView(o[0]),
    };
  });
}
