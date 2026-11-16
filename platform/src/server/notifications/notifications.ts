import { and, desc, eq, inArray, isNull, sql } from "drizzle-orm";
import { z } from "zod";
import { withOrg, isUuid, type Tx } from "../db/client";
import { memberships, notificationPrefs, notifications } from "../db/schema";
import { AppError } from "../errors";
import { authorize, type OrgFlags, type Principal } from "../policy/policy";

type Ctx = { principal: Principal; org: OrgFlags & { id: string } };

/**
 * FR-056 notification kinds. Security-critical kinds are always delivered in-app and by email:
 * a preference cannot turn them off, so nobody misses a failed fix, a regression or a support access.
 */
export const NOTIFY_KINDS = {
  assigned: { label: "Finding assigned to you", securityCritical: false },
  mentioned: { label: "Mentioned on a finding", securityCritical: false },
  retriage: { label: "Finding needs another look", securityCritical: false },
  approval_requested: { label: "Approval requested", securityCritical: false },
  approval_decided: { label: "Approval decided", securityCritical: false },
  regression_inconclusive: { label: "Regression re-test inconclusive", securityCritical: false },
  assessment_complete: { label: "Assessment you started finished", securityCritical: false },
  new_critical_finding: { label: "New critical or high finding", securityCritical: true },
  risk_expired: { label: "Risk acceptance expired", securityCritical: true },
  verification_failed: { label: "Fix verification failed", securityCritical: true },
  regression: { label: "Verified fix regressed", securityCritical: true },
  regression_not_run: { label: "Regression re-test could not run", securityCritical: true },
  killswitch: { label: "Kill switch changed", securityCritical: true },
  break_glass: { label: "Operator support access", securityCritical: true },
  org_deletion: { label: "Organization deletion requested or cancelled", securityCritical: true },
  attack_spike: { label: "Attack spike on an asset", securityCritical: true },
} as const satisfies Record<string, { label: string; securityCritical: boolean }>;
export type NotifyKindAll = keyof typeof NOTIFY_KINDS;

export const isSecurityCritical = (kind: string) => (NOTIFY_KINDS as Record<string, { securityCritical: boolean }>)[kind]?.securityCritical ?? false;

/** Delivery channels for one user and kind; security-critical kinds ignore preferences. */
export async function channelsFor(tx: Tx, orgId: string, userId: string, kind: string): Promise<{ email: boolean; inApp: boolean }> {
  if (isSecurityCritical(kind)) return { email: true, inApp: true };
  const p = (await tx.select().from(notificationPrefs).where(and(
    eq(notificationPrefs.orgId, orgId), eq(notificationPrefs.userId, userId), eq(notificationPrefs.kind, kind),
  )).limit(1))[0];
  return { email: p?.email ?? true, inApp: p?.inApp ?? true };
}

/** Writes an in-app notification unless the user turned it off. Idempotent per (sourceId, user). */
export async function addInApp(tx: Tx, n: { orgId: string; userId: string; kind: NotifyKindAll; title: string; link?: string | null; sourceId?: string | null }) {
  const ch = await channelsFor(tx, n.orgId, n.userId, n.kind);
  if (!ch.inApp) return false;
  await tx.insert(notifications).values({
    orgId: n.orgId, userId: n.userId, kind: n.kind, title: n.title.slice(0, 300), link: n.link ?? null,
    securityCritical: isSecurityCritical(n.kind), sourceId: n.sourceId ?? null,
  }).onConflictDoNothing();
  return true;
}

/** Notifies every org admin and security lead in-app (kill switch, break-glass, deletion). */
export async function notifyAdmins(tx: Tx, orgId: string, n: { kind: NotifyKindAll; title: string; link?: string | null; sourceId: string }) {
  const admins = await tx.select({ id: memberships.userId }).from(memberships)
    .where(and(eq(memberships.orgId, orgId), inArray(memberships.role, ["org_admin", "security_lead"])));
  for (const a of admins) await addInApp(tx, { orgId, userId: a.id, ...n });
  return admins.length;
}

export async function listNotifications(c: Ctx, opts: { unreadOnly?: boolean } = {}) {
  await authorize(c.principal, "notification.prefs", { type: "org", id: c.org.id }, c.org);
  return withOrg(c.org.id, (tx) => tx.select().from(notifications).where(and(
    eq(notifications.orgId, c.org.id), eq(notifications.userId, c.principal.userId),
    opts.unreadOnly ? isNull(notifications.readAt) : undefined,
  )).orderBy(desc(notifications.createdAt)).limit(100));
}

export async function unreadCount(c: Ctx): Promise<number> {
  return withOrg(c.org.id, async (tx) => Number((await tx.select({ n: sql<string>`count(*)` }).from(notifications).where(and(
    eq(notifications.orgId, c.org.id), eq(notifications.userId, c.principal.userId), isNull(notifications.readAt),
  )))[0]?.n ?? 0));
}

/** Marks one notification (or all of the caller's) as read. Only the recipient can do this. */
export async function markRead(c: Ctx, id: string | "all") {
  if (id !== "all" && !isUuid(id)) throw new AppError(404, "not_found");
  await authorize(c.principal, "notification.prefs", { type: "org", id: c.org.id }, c.org);
  await withOrg(c.org.id, (tx) => tx.update(notifications).set({ readAt: new Date() }).where(and(
    eq(notifications.orgId, c.org.id), eq(notifications.userId, c.principal.userId), isNull(notifications.readAt),
    id === "all" ? undefined : eq(notifications.id, id),
  )));
}

export async function getPrefs(c: Ctx) {
  await authorize(c.principal, "notification.prefs", { type: "org", id: c.org.id }, c.org);
  const rows = await withOrg(c.org.id, (tx) => tx.select().from(notificationPrefs)
    .where(and(eq(notificationPrefs.orgId, c.org.id), eq(notificationPrefs.userId, c.principal.userId))));
  const by = new Map(rows.map((r) => [r.kind, r]));
  return (Object.entries(NOTIFY_KINDS) as [NotifyKindAll, (typeof NOTIFY_KINDS)[NotifyKindAll]][]).map(([kind, k]) => ({
    kind, label: k.label, securityCritical: k.securityCritical,
    email: k.securityCritical ? true : by.get(kind)?.email ?? true,
    inApp: k.securityCritical ? true : by.get(kind)?.inApp ?? true,
  }));
}

const prefInput = z.object({ kind: z.string(), email: z.boolean(), inApp: z.boolean() });

export async function setPref(c: Ctx, input: unknown) {
  await authorize(c.principal, "notification.prefs", { type: "org", id: c.org.id }, c.org);
  const v = prefInput.safeParse(input);
  if (!v.success || !(v.data.kind in NOTIFY_KINDS)) throw new AppError(422, "validation_failed", "Unknown notification kind.");
  if (isSecurityCritical(v.data.kind) && (!v.data.email || !v.data.inApp)) {
    throw new AppError(422, "security_critical", "Security-critical notifications cannot be turned off.");
  }
  await withOrg(c.org.id, (tx) => tx.insert(notificationPrefs)
    .values({ orgId: c.org.id, userId: c.principal.userId, kind: v.data.kind, email: v.data.email, inApp: v.data.inApp })
    .onConflictDoUpdate({ target: [notificationPrefs.orgId, notificationPrefs.userId, notificationPrefs.kind], set: { email: v.data.email, inApp: v.data.inApp } }));
}
