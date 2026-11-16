import { createHash, randomBytes } from "node:crypto";
import { and, count, eq, gt, isNull, lt, sql } from "drizzle-orm";
import QRCode from "qrcode";
import { db, withOrg } from "../db/client";
import { loginAttempts, mfaRecoveryCodes, pendingLogins, sessions, userMfa, users } from "../db/schema";
import { audit } from "../audit/audit";
import { AppError } from "../errors";
import { open, seal } from "../attacks/secretbox";
import { createSession, randomToken, sha256, type SessionInfo } from "./session";
import { base32Encode, newTotpSecret, otpauthUri, verifyTotp } from "./totp";

// Built-in MFA (0023_totp_mfa.sql). An OIDC sign-in (Google) only proves who the person is; the session is
// created after they also enter a code from their authenticator app, or a one-time recovery code.

export const PENDING_LOGIN_TTL_MS = 10 * 60 * 1000;
export const PENDING_COOKIE = "ruya_mfa_pending";
export const PENDING_MAX_ATTEMPTS = 5;
export const RECOVERY_CODE_COUNT = 10;
const MFA_RATE_WINDOW_MS = 15 * 60 * 1000;
const MFA_RATE_MAX = 10;

const aad = (userId: string) => `user_mfa:${userId}`;
const normalizeRecovery = (c: string) => c.replace(/[\s-]/g, "").toUpperCase();
const hashRecovery = (c: string) => createHash("sha256").update(normalizeRecovery(c)).digest("hex");
const MFA_AMR = ["otp", "mfa"];

export interface RequestMeta { ip: string | null; userAgent: string | null }

// ---------- pending logins ----------

/** Called by completeLogin for OIDC: no session yet, just a short-lived pending login. */
export async function createPendingLogin(p: { userId: string; amr: string[]; issuer: string; returnTo: string }): Promise<string> {
  const token = randomToken(32);
  await db.insert(pendingLogins).values({ tokenHash: sha256(token), userId: p.userId, amr: p.amr, issuer: p.issuer, returnTo: p.returnTo });
  await db.delete(pendingLogins).where(lt(pendingLogins.createdAt, new Date(Date.now() - PENDING_LOGIN_TTL_MS)));
  return token;
}

async function pendingFor(token: string | undefined | null, now = new Date()) {
  if (!token || token.length > 200) return null;
  const rows = await db.select({ p: pendingLogins, email: users.email, disabledAt: users.disabledAt })
    .from(pendingLogins).innerJoin(users, eq(users.id, pendingLogins.userId))
    .where(and(eq(pendingLogins.tokenHash, sha256(token)), gt(pendingLogins.createdAt, new Date(now.getTime() - PENDING_LOGIN_TTL_MS))))
    .limit(1);
  const r = rows[0];
  return r && !r.disabledAt ? { ...r.p, email: r.email } : null;
}

const enrolled = async (userId: string) =>
  !!(await db.select({ e: userMfa.enabledAt }).from(userMfa).where(eq(userMfa.userId, userId)))[0]?.e;

export type MfaChallenge =
  | { kind: "verify"; email: string }
  | { kind: "enroll"; email: string; secret: string; qrSvg: string };

/**
 * What the /auth/mfa page shows for a pending login: a code prompt, or (first time) an enrollment QR code.
 * The unconfirmed secret is kept across reloads, so a code scanned earlier keeps working.
 */
export async function challengeFor(token: string | undefined | null): Promise<MfaChallenge | null> {
  const p = await pendingFor(token);
  if (!p) return null;
  if (await enrolled(p.userId)) return { kind: "verify", email: p.email };
  const existing = (await db.select().from(userMfa).where(eq(userMfa.userId, p.userId)))[0];
  let secret: string;
  if (existing) {
    secret = open(existing.secret, aad(p.userId));
  } else {
    secret = newTotpSecret();
    await db.insert(userMfa).values({ userId: p.userId, secret: seal(secret, aad(p.userId)) }).onConflictDoNothing();
    // A concurrent request may have won the insert; use whatever is stored.
    secret = open((await db.select().from(userMfa).where(eq(userMfa.userId, p.userId)))[0].secret, aad(p.userId));
  }
  const qrSvg = await QRCode.toString(otpauthUri(secret, p.email), { type: "svg", margin: 1, errorCorrectionLevel: "M" });
  return { kind: "enroll", email: p.email, secret, qrSvg };
}

// ---------- verification ----------

async function mfaRateLimited(userId: string): Promise<boolean> {
  const [r] = await db.select({ n: count() }).from(loginAttempts)
    .where(and(eq(loginAttempts.key, `mfa:${userId}`), gt(loginAttempts.createdAt, new Date(Date.now() - MFA_RATE_WINDOW_MS))));
  return (r?.n ?? 0) >= MFA_RATE_MAX;
}

async function recordMfaFailure(userId: string, meta: RequestMeta, reason: string) {
  await db.insert(loginAttempts).values({ key: `mfa:${userId}` });
  await withOrg(null, (tx) => audit(tx, { actor: { type: "user", id: userId, ip: meta.ip }, action: "auth.mfa_failed", outcome: "denied", reason }));
}

/** Checks an authenticator code (consuming its time step) or a recovery code (consuming the code). */
async function checkCode(userId: string, code: string, opts: { allowUnconfirmed: boolean }): Promise<"totp" | "recovery" | null> {
  const m = (await db.select().from(userMfa).where(eq(userMfa.userId, userId)))[0];
  if (!m || (!m.enabledAt && !opts.allowUnconfirmed)) return null;
  const step = verifyTotp(open(m.secret, aad(userId)), code, m.lastStep);
  if (step !== null) {
    // Conditional update: two requests with the same code cannot both succeed.
    const won = await db.update(userMfa).set({ lastStep: step })
      .where(and(eq(userMfa.userId, userId), lt(userMfa.lastStep, step))).returning({ u: userMfa.userId });
    return won.length ? "totp" : null;
  }
  if (!m.enabledAt) return null;
  const n = normalizeRecovery(code);
  if (!/^[A-Z2-7]{10}$/.test(n)) return null;
  const used = await db.update(mfaRecoveryCodes).set({ usedAt: new Date() })
    .where(and(eq(mfaRecoveryCodes.userId, userId), eq(mfaRecoveryCodes.codeHash, hashRecovery(n)), isNull(mfaRecoveryCodes.usedAt)))
    .returning({ u: mfaRecoveryCodes.userId });
  return used.length ? "recovery" : null;
}

/** Replaces the user's recovery codes; returns them in display form (XXXXX-XXXXX). Only hashes are stored. */
export async function regenerateRecoveryCodes(userId: string): Promise<string[]> {
  const codes = Array.from({ length: RECOVERY_CODE_COUNT }, () => base32Encode(randomBytes(7)).slice(0, 10));
  await db.transaction(async (tx) => {
    await tx.delete(mfaRecoveryCodes).where(eq(mfaRecoveryCodes.userId, userId));
    await tx.insert(mfaRecoveryCodes).values(codes.map((c) => ({ userId, codeHash: hashRecovery(c) })));
  });
  return codes.map((c) => `${c.slice(0, 5)}-${c.slice(5)}`);
}

export type MfaLoginResult = { token: string; expiresAt: Date; returnTo: string; recoveryCodes: string[] | null; usedRecovery: boolean };

/** Finishes a pending login with a code. First-time users confirm enrollment and get their recovery codes. */
export async function completeMfaLogin(pendingToken: string | undefined | null, code: string, meta: RequestMeta): Promise<MfaLoginResult> {
  const p = await pendingFor(pendingToken);
  if (!p) throw new AppError(410, "mfa_login_expired", "This sign-in has expired. Please sign in again.");
  if (await mfaRateLimited(p.userId)) throw new AppError(429, "rate_limited", "Too many wrong codes. Try again in 15 minutes.");

  const wasEnrolled = await enrolled(p.userId);
  const how = await checkCode(p.userId, code, { allowUnconfirmed: !wasEnrolled });
  if (!how) {
    await recordMfaFailure(p.userId, meta, "bad_code");
    const [r] = await db.update(pendingLogins).set({ attempts: sql`${pendingLogins.attempts} + 1` })
      .where(eq(pendingLogins.tokenHash, p.tokenHash)).returning({ attempts: pendingLogins.attempts });
    if (!r || r.attempts >= PENDING_MAX_ATTEMPTS) {
      await db.delete(pendingLogins).where(eq(pendingLogins.tokenHash, p.tokenHash));
      throw new AppError(410, "mfa_login_expired", "Too many wrong codes. Please sign in again.");
    }
    throw new AppError(401, "mfa_code_invalid", "That code is not valid. Check the time on your phone and try the newest code.");
  }

  // One use per pending login, even if two submissions race.
  const claimed = await db.delete(pendingLogins).where(eq(pendingLogins.tokenHash, p.tokenHash)).returning({ t: pendingLogins.tokenHash });
  if (!claimed.length) throw new AppError(410, "mfa_login_expired", "This sign-in has expired. Please sign in again.");

  let recoveryCodes: string[] | null = null;
  if (!wasEnrolled) {
    await db.update(userMfa).set({ enabledAt: new Date() }).where(eq(userMfa.userId, p.userId));
    recoveryCodes = await regenerateRecoveryCodes(p.userId);
  }
  const amr = [...new Set([...p.amr, ...MFA_AMR])];
  const s = await createSession({ userId: p.userId, mfa: true, amr, authTime: new Date(), ip: meta.ip, userAgent: meta.userAgent });
  await withOrg(null, async (tx) => {
    if (!wasEnrolled) await audit(tx, { actor: { type: "user", id: p.userId, ip: meta.ip }, action: "auth.mfa_enrolled" });
    await audit(tx, { actor: { type: "user", id: p.userId, ip: meta.ip }, action: "auth.login", details: { mfa: true, amr, provider: p.issuer, method: how } });
  });
  return { ...s, returnTo: p.returnTo, recoveryCodes, usedRecovery: how === "recovery" };
}

/** Step-up for sensitive actions: a fresh code renews the session's authentication time. */
export async function stepUp(session: SessionInfo, code: string, meta: RequestMeta): Promise<void> {
  if (await mfaRateLimited(session.userId)) throw new AppError(429, "rate_limited", "Too many wrong codes. Try again in 15 minutes.");
  if (!(await enrolled(session.userId))) throw new AppError(409, "mfa_not_enrolled", "Set up an authenticator app first: sign out and sign in again.");
  const how = await checkCode(session.userId, code, { allowUnconfirmed: false });
  if (!how) {
    await recordMfaFailure(session.userId, meta, "bad_code_step_up");
    throw new AppError(401, "mfa_code_invalid", "That code is not valid. Check the time on your phone and try the newest code.");
  }
  const amr = [...new Set([...session.amr, ...MFA_AMR])];
  await db.update(sessions).set({ authTime: new Date(), mfa: true, amr }).where(eq(sessions.idHash, session.idHash));
  await withOrg(null, (tx) => audit(tx, { actor: { type: "user", id: session.userId, ip: meta.ip }, action: "auth.step_up", details: { method: how } }));
}

export async function remainingRecoveryCodes(userId: string): Promise<number> {
  const [r] = await db.select({ n: count() }).from(mfaRecoveryCodes).where(and(eq(mfaRecoveryCodes.userId, userId), isNull(mfaRecoveryCodes.usedAt)));
  return r?.n ?? 0;
}
