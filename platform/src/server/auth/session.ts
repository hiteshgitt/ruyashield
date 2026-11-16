import { createHash, randomBytes } from "node:crypto";
import { and, eq, isNull, sql } from "drizzle-orm";
import { db } from "../db/client";
import { sessions, users } from "../db/schema";

export const SESSION_ABSOLUTE_MS = 12 * 60 * 60 * 1000;
export const SESSION_IDLE_MS = 30 * 60 * 1000;
const TOUCH_EVERY_MS = 60 * 1000;

export const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");
export const randomToken = (bytes = 32) => randomBytes(bytes).toString("base64url");

/** Cookie name: __Host- prefix requires Secure, so it is used only when the app is served over https. */
export function sessionCookieName(): string {
  return secureCookies() ? "__Host-ruya_sid" : "ruya_sid";
}
export function secureCookies(): boolean {
  return (process.env.APP_URL ?? "").startsWith("https://");
}

export interface NewSession {
  userId: string;
  mfa: boolean;
  amr: string[];
  authTime: Date;
  ip?: string | null;
  userAgent?: string | null;
}

/** Creates a fresh session (new id on every login, RS-IAM-007) and returns the raw cookie token. */
export async function createSession(s: NewSession): Promise<{ token: string; expiresAt: Date }> {
  const token = randomToken();
  const expiresAt = new Date(Date.now() + SESSION_ABSOLUTE_MS);
  await db.insert(sessions).values({
    idHash: sha256(token), userId: s.userId, mfa: s.mfa, amr: s.amr, authTime: s.authTime,
    expiresAt, ip: s.ip ?? null, userAgent: s.userAgent?.slice(0, 300) ?? null,
  });
  return { token, expiresAt };
}

export interface SessionInfo {
  idHash: string;
  userId: string;
  email: string;
  displayName: string;
  activeOrgId: string | null;
  mfa: boolean;
  amr: string[];
  authTime: Date;
}

/** Returns the live session for a cookie token, or null if missing, revoked, expired, idle or the user is disabled. */
export async function readSession(token: string | undefined | null, now = new Date()): Promise<SessionInfo | null> {
  if (!token || token.length > 200) return null;
  const idHash = sha256(token);
  const rows = await db
    .select({ s: sessions, email: users.email, displayName: users.displayName, disabledAt: users.disabledAt })
    .from(sessions).innerJoin(users, eq(users.id, sessions.userId))
    .where(and(eq(sessions.idHash, idHash), isNull(sessions.revokedAt)))
    .limit(1);
  const row = rows[0];
  if (!row || row.disabledAt) return null;
  const s = row.s;
  if (s.expiresAt <= now || now.getTime() - s.lastSeenAt.getTime() > SESSION_IDLE_MS) {
    await db.update(sessions).set({ revokedAt: now }).where(eq(sessions.idHash, idHash));
    return null;
  }
  if (now.getTime() - s.lastSeenAt.getTime() > TOUCH_EVERY_MS) {
    await db.update(sessions).set({ lastSeenAt: now }).where(eq(sessions.idHash, idHash));
  }
  return {
    idHash, userId: s.userId, email: row.email, displayName: row.displayName,
    activeOrgId: s.activeOrgId, mfa: s.mfa, amr: s.amr, authTime: s.authTime,
  };
}

export async function setActiveOrg(idHash: string, orgId: string | null) {
  await db.update(sessions).set({ activeOrgId: orgId }).where(eq(sessions.idHash, idHash));
}

export async function revokeSessionByToken(token: string) {
  await db.update(sessions).set({ revokedAt: new Date() })
    .where(and(eq(sessions.idHash, sha256(token)), isNull(sessions.revokedAt)));
}

/** Revokes every live session of a user (member removal, account disable). Returns the count. */
export async function revokeUserSessions(userId: string): Promise<number> {
  const res = await db.update(sessions).set({ revokedAt: sql`now()` })
    .where(and(eq(sessions.userId, userId), isNull(sessions.revokedAt)))
    .returning({ id: sessions.idHash });
  return res.length;
}
