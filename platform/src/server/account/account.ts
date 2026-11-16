import { and, count, desc, eq, gt, isNull, like, ne } from "drizzle-orm";
import { z } from "zod";
import { db, withOrg } from "../db/client";
import { apiTokens, memberClientGroups, memberships, mfaRecoveryCodes, passwordCredentials, sessions, userMfa, users } from "../db/schema";
import { audit } from "../audit/audit";
import { AppError } from "../errors";
import type { SessionInfo } from "../auth/session";
import { issueRecoveryReveal, remainingRecoveryCodes, resetMfa, stepUp } from "../auth/mfa";
import { hashPassword, passwordProblem, PASSWORD_ISSUER, verifyPassword } from "../auth/password";
import { listUserOrgs } from "../orgs/orgs";

// The signed-in person's own account: profile, password, two-step verification, sessions and deletion.
// Sensitive changes need the current authenticator code (or a recovery code), never just the session.

type Meta = { ip: string | null; userAgent: string | null };

/** "Chrome on Windows"-style label from a user agent; rough on purpose. */
export function deviceLabel(ua: string | null): string {
  if (!ua) return "Unknown device";
  const browser = /Edg\//.test(ua) ? "Edge" : /OPR\//.test(ua) ? "Opera" : /Firefox\//.test(ua) ? "Firefox" : /Chrome\//.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : "Browser";
  const os = /Android/.test(ua) ? "Android" : /iPhone|iPad/.test(ua) ? "iOS" : /Windows/.test(ua) ? "Windows" : /Mac OS X/.test(ua) ? "macOS" : /Linux/.test(ua) ? "Linux" : "";
  return os ? `${browser} on ${os}` : browser;
}

/** Sessions are identified to the page by a short prefix of their hash, never the hash itself. */
const sessionKey = (idHash: string) => idHash.slice(0, 16);

export async function getAccount(s: SessionInfo, now = new Date()) {
  const u = (await db.select().from(users).where(eq(users.id, s.userId)))[0];
  if (!u) throw new AppError(404, "not_found");
  const mfa = (await db.select({ enabledAt: userMfa.enabledAt }).from(userMfa).where(eq(userMfa.userId, s.userId)))[0];
  const live = await db.select().from(sessions)
    .where(and(eq(sessions.userId, s.userId), isNull(sessions.revokedAt), gt(sessions.expiresAt, now)))
    .orderBy(desc(sessions.lastSeenAt)).limit(30);
  return {
    email: u.email, displayName: u.displayName, createdAt: u.createdAt,
    method: u.idpIssuer === PASSWORD_ISSUER ? "password" as const : "google" as const,
    mfaEnabled: !!mfa?.enabledAt, recoveryLeft: mfa?.enabledAt ? await remainingRecoveryCodes(s.userId) : 0,
    sessions: live.map((x) => ({
      key: sessionKey(x.idHash), current: x.idHash === s.idHash, device: deviceLabel(x.userAgent),
      ip: x.ip, createdAt: x.createdAt, lastSeenAt: x.lastSeenAt,
    })),
  };
}

const nameInput = z.object({ displayName: z.string().trim().min(1, "Enter your name.").max(80, "Use at most 80 characters.") });

export async function updateProfile(s: SessionInfo, input: unknown, meta: Meta) {
  const v = nameInput.safeParse(input);
  if (!v.success) throw new AppError(422, "validation_failed", v.error.issues[0].message);
  await db.update(users).set({ displayName: v.data.displayName }).where(eq(users.id, s.userId));
  await withOrg(null, (tx) => audit(tx, { actor: { type: "user", id: s.userId, ip: meta.ip }, action: "account.profile_updated" }));
}

export async function changePassword(s: SessionInfo, input: { current: unknown; next: unknown }, meta: Meta) {
  const row = (await db.select({ hash: passwordCredentials.hash }).from(passwordCredentials).where(eq(passwordCredentials.userId, s.userId)))[0];
  if (!row) throw new AppError(409, "no_password", "This account signs in with Google, so it has no password.");
  const current = typeof input.current === "string" ? input.current : "";
  const next = typeof input.next === "string" ? input.next : "";
  if (!(await verifyPassword(current, row.hash))) throw new AppError(401, "bad_credentials", "Your current password is not right.");
  const problem = passwordProblem(next, s.email);
  if (problem) throw new AppError(422, "weak_password", problem);
  if (current === next) throw new AppError(422, "weak_password", "Choose a password different from the current one.");
  await db.update(passwordCredentials).set({ hash: await hashPassword(next), updatedAt: new Date() }).where(eq(passwordCredentials.userId, s.userId));
  // Other devices sign in again with the new password; this one stays signed in.
  await db.update(sessions).set({ revokedAt: new Date() }).where(and(eq(sessions.userId, s.userId), isNull(sessions.revokedAt), ne(sessions.idHash, s.idHash)));
  await withOrg(null, (tx) => audit(tx, { actor: { type: "user", id: s.userId, ip: meta.ip }, action: "account.password_changed" }));
}

/** New recovery codes after a fresh code; they are shown once on /auth/mfa. */
export async function newRecoveryCodes(s: SessionInfo, code: unknown, meta: Meta) {
  await stepUp(s, String(code ?? ""), meta);
  await issueRecoveryReveal(s.userId, "/account");
  await withOrg(null, (tx) => audit(tx, { actor: { type: "user", id: s.userId, ip: meta.ip }, action: "account.recovery_codes_regenerated" }));
}

/** Moving to a new phone: after a fresh code (or a recovery code), forget the authenticator and sign out everywhere. */
export async function resetAuthenticator(s: SessionInfo, code: unknown, meta: Meta) {
  await stepUp(s, String(code ?? ""), meta);
  await resetMfa(s.userId);
  await withOrg(null, (tx) => audit(tx, { actor: { type: "user", id: s.userId, ip: meta.ip }, action: "account.authenticator_reset" }));
}

export async function signOutSession(s: SessionInfo, key: unknown, meta: Meta) {
  if (typeof key !== "string" || !/^[0-9a-f]{16}$/.test(key)) throw new AppError(422, "validation_failed");
  if (key === sessionKey(s.idHash)) throw new AppError(409, "current_session", "Use Sign out for this device.");
  const r = await db.update(sessions).set({ revokedAt: new Date() })
    .where(and(eq(sessions.userId, s.userId), like(sessions.idHash, `${key}%`), isNull(sessions.revokedAt))).returning({ id: sessions.idHash });
  if (!r.length) throw new AppError(404, "not_found", "That session has already ended.");
  await withOrg(null, (tx) => audit(tx, { actor: { type: "user", id: s.userId, ip: meta.ip }, action: "account.session_revoked" }));
}

export async function signOutOtherSessions(s: SessionInfo, meta: Meta) {
  const r = await db.update(sessions).set({ revokedAt: new Date() })
    .where(and(eq(sessions.userId, s.userId), isNull(sessions.revokedAt), ne(sessions.idHash, s.idHash))).returning({ id: sessions.idHash });
  await withOrg(null, (tx) => audit(tx, { actor: { type: "user", id: s.userId, ip: meta.ip }, action: "account.other_sessions_revoked", details: { count: r.length } }));
  return r.length;
}

/** Organizations where this person is the only org admin; deletion waits until they hand over or delete them. */
export async function soleAdminOrgs(userId: string) {
  const orgs = await listUserOrgs(userId);
  const out: { id: string; name: string }[] = [];
  for (const o of orgs.filter((x) => x.role === "org_admin")) {
    const [r] = await withOrg(o.id, (tx) => tx.select({ n: count() }).from(memberships).where(eq(memberships.role, "org_admin")));
    if (r.n <= 1) out.push({ id: o.id, name: o.name });
  }
  return out;
}

/**
 * Deletes the account: leaves every organization, revokes its API tokens, and removes sign-in details. The user
 * row stays (anonymised and disabled) because audit records and findings history refer to it.
 */
export async function deleteAccount(s: SessionInfo, input: { confirm: unknown; code: unknown }, meta: Meta) {
  if (typeof input.confirm !== "string" || input.confirm.trim().toLowerCase() !== s.email.toLowerCase()) {
    throw new AppError(422, "validation_failed", "Type your email address exactly to confirm.");
  }
  await stepUp(s, String(input.code ?? ""), meta);
  const blocking = await soleAdminOrgs(s.userId);
  if (blocking.length) {
    throw new AppError(409, "last_admin", `You are the only org admin of ${blocking.map((o) => o.name).join(", ")}. Make someone else an admin or delete the organization first.`);
  }
  for (const o of await listUserOrgs(s.userId)) {
    await withOrg(o.id, async (tx) => {
      await tx.update(apiTokens).set({ revokedAt: new Date() }).where(and(eq(apiTokens.userId, s.userId), isNull(apiTokens.revokedAt)));
      await tx.delete(memberClientGroups).where(eq(memberClientGroups.userId, s.userId));
      await tx.delete(memberships).where(eq(memberships.userId, s.userId));
      await audit(tx, { actor: { type: "user", id: s.userId, ip: meta.ip }, action: "member.left", target: { type: "user", id: s.userId }, details: { reason: "account_deleted" } });
    });
  }
  await db.transaction(async (tx) => {
    await tx.delete(passwordCredentials).where(eq(passwordCredentials.userId, s.userId));
    await tx.delete(mfaRecoveryCodes).where(eq(mfaRecoveryCodes.userId, s.userId));
    await tx.delete(userMfa).where(eq(userMfa.userId, s.userId));
    await tx.update(sessions).set({ revokedAt: new Date() }).where(and(eq(sessions.userId, s.userId), isNull(sessions.revokedAt)));
    const gone = `deleted-${s.userId}`;
    await tx.update(users).set({ email: `${gone}@deleted.invalid`, displayName: "Deleted user", idpIssuer: "deleted", idpSubject: gone, disabledAt: new Date() }).where(eq(users.id, s.userId));
  });
  await withOrg(null, (tx) => audit(tx, { actor: { type: "user", id: s.userId, ip: meta.ip }, action: "account.deleted" }));
}
