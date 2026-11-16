import { and, desc, eq, gt, isNull, sql } from "drizzle-orm";
import { z } from "zod";
import { db, withOrg } from "../db/client";
import { breakGlassSessions } from "../db/schema";
import { audit } from "../audit/audit";
import { AppError } from "../errors";
import { setActiveOrg, type SessionInfo } from "../auth/session";
import { notifyAdmins } from "../notifications/notifications";

export const BREAK_GLASS_MAX_MINUTES = 240;
const FRESH_AUTH_MS = 15 * 60 * 1000;

/** Operators are named by email in RUYA_OPERATOR_EMAILS (comma-separated). Empty means no operator access at all. */
export function isOperator(email: string, env = process.env.RUYA_OPERATOR_EMAILS): boolean {
  const list = (env ?? "").split(",").map((e) => e.trim().toLowerCase()).filter(Boolean);
  return list.includes(email.trim().toLowerCase());
}

export function requireOperator(s: SessionInfo, now = new Date()) {
  if (!isOperator(s.email)) throw new AppError(403, "forbidden");
  if (!s.mfa || now.getTime() - s.authTime.getTime() > FRESH_AUTH_MS) throw new AppError(401, "step_up_required", "Sign in again with MFA to start support access.");
}

const startInput = z.object({
  orgSlug: z.string().trim().min(1).max(80),
  reason: z.string().trim().min(10, "Give a reason (at least 10 characters), e.g. the support ticket.").max(500),
  minutes: z.number().int().min(5, "Use 5 to 240 minutes.").max(BREAK_GLASS_MAX_MINUTES, "Use 5 to 240 minutes."),
});

/**
 * RS-PLAT-007: time-boxed, read-only support access to one tenant. Requires an operator with fresh MFA and a
 * reason; it is written to the tenant's audit chain and announced in-app to the tenant's admins.
 */
export async function startBreakGlass(s: SessionInfo, input: unknown, meta: { ip?: string | null; requestId?: string | null } = {}, now = new Date()) {
  requireOperator(s, now);
  const v = startInput.safeParse(input);
  if (!v.success) throw new AppError(422, "validation_failed", v.error.issues[0].message);
  const o = (await db.execute<{ id: string; name: string }>(sql`SELECT id, name FROM operator_org_lookup(${v.data.orgSlug})`)).rows[0];
  if (!o) throw new AppError(404, "not_found", "No organization with that slug.");
  const expiresAt = new Date(now.getTime() + v.data.minutes * 60_000);
  const id = await withOrg(o.id, async (tx) => {
    const live = await tx.select({ id: breakGlassSessions.id }).from(breakGlassSessions).where(and(
      eq(breakGlassSessions.orgId, o.id), eq(breakGlassSessions.operatorUserId, s.userId),
      isNull(breakGlassSessions.endedAt), gt(breakGlassSessions.expiresAt, now),
    ));
    if (live[0]) throw new AppError(409, "already_active", "You already have support access to this organization.");
    const [row] = await tx.insert(breakGlassSessions).values({
      orgId: o.id, operatorUserId: s.userId, reason: v.data.reason, startedAt: now, expiresAt,
    }).returning({ id: breakGlassSessions.id });
    await audit(tx, {
      actor: { type: "user", id: s.userId, ip: meta.ip }, action: "operator.break_glass_started",
      target: { type: "break_glass", id: row.id }, reason: v.data.reason, requestId: meta.requestId,
      details: { expiresAt: expiresAt.toISOString(), minutes: v.data.minutes },
    });
    await notifyAdmins(tx, o.id, {
      kind: "break_glass", title: `RuyaShield support started read-only access until ${expiresAt.toISOString().slice(0, 16).replace("T", " ")} UTC: ${v.data.reason}`,
      link: "/audit", sourceId: row.id,
    });
    return row.id;
  });
  await setActiveOrg(s.idHash, o.id);
  return { id, orgId: o.id, orgName: o.name, expiresAt };
}

export async function endBreakGlass(s: SessionInfo, orgId: string, meta: { ip?: string | null; requestId?: string | null } = {}) {
  if (!isOperator(s.email)) throw new AppError(403, "forbidden");
  await withOrg(orgId, async (tx) => {
    const r = await tx.update(breakGlassSessions).set({ endedAt: new Date() }).where(and(
      eq(breakGlassSessions.orgId, orgId), eq(breakGlassSessions.operatorUserId, s.userId), isNull(breakGlassSessions.endedAt),
    )).returning({ id: breakGlassSessions.id });
    for (const row of r) {
      await audit(tx, { actor: { type: "user", id: s.userId, ip: meta.ip }, action: "operator.break_glass_ended", target: { type: "break_glass", id: row.id }, requestId: meta.requestId });
    }
  });
  await setActiveOrg(s.idHash, null);
}

/** The operator's own sessions in one org, newest first (for the operator page). */
export async function listBreakGlass(s: SessionInfo, orgId: string) {
  if (!isOperator(s.email)) throw new AppError(403, "forbidden");
  return withOrg(orgId, (tx) => tx.select().from(breakGlassSessions)
    .where(and(eq(breakGlassSessions.orgId, orgId), eq(breakGlassSessions.operatorUserId, s.userId)))
    .orderBy(desc(breakGlassSessions.startedAt)).limit(20));
}
