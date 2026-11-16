import { randomBytes, scrypt as scryptCb, timingSafeEqual, type ScryptOptions } from "node:crypto";
import { and, count, eq, gt, isNull } from "drizzle-orm";
import { z } from "zod";
import { db, withOrg } from "../db/client";
import { emailTokens, loginAttempts, passwordCredentials, users } from "../db/schema";
import { audit } from "../audit/audit";
import { AppError, isUniqueViolation } from "../errors";
import { appLink, brandedEmail, sendMail } from "../mail/mail";
import { randomToken, revokeUserSessions, sha256 } from "./session";
import { createPendingLogin } from "./mfa";
import { rateLimited, recordFailure, safeReturnTo, type RequestMeta } from "./login";

// Email + password accounts, next to Google sign-in. The address must be verified by email before the account
// can sign in, and every sign-in continues to the authenticator-code step (mfa.ts), like Google sign-ins.
// Responses never reveal whether an address has an account.

export const PASSWORD_ISSUER = "password";
export const MIN_PASSWORD = 10;
const VERIFY_TTL_MS = 24 * 60 * 60 * 1000;
const RESET_TTL_MS = 30 * 60 * 1000;
const MAIL_WINDOW_MS = 15 * 60 * 1000;
const MAIL_MAX = 5;

// ---------- hashing (scrypt, parameters stored with the hash) ----------

const SCRYPT = { N: 1 << 15, r: 8, p: 1 };
const KEYLEN = 32;
const scrypt = (pw: string, salt: Buffer, o: ScryptOptions) =>
  new Promise<Buffer>((resolve, reject) => scryptCb(pw.normalize("NFKC"), salt, KEYLEN, { ...o, maxmem: 128 * o.N! * o.r! * 2 }, (e, k) => (e ? reject(e) : resolve(k))));

export async function hashPassword(pw: string): Promise<string> {
  const salt = randomBytes(16);
  const key = await scrypt(pw, salt, SCRYPT);
  return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString("base64")}$${key.toString("base64")}`;
}

export async function verifyPassword(pw: string, stored: string): Promise<boolean> {
  const [kind, n, r, p, salt, hash] = stored.split("$");
  if (kind !== "scrypt" || !salt || !hash) return false;
  const expected = Buffer.from(hash, "base64");
  const key = await scrypt(pw, Buffer.from(salt, "base64"), { N: Number(n), r: Number(r), p: Number(p) });
  return key.length === expected.length && timingSafeEqual(key, expected);
}

// A hash of nothing, so a sign-in for an unknown address takes as long as a real one.
let dummyHash: Promise<string> | undefined;
const dummy = () => (dummyHash ??= hashPassword(randomToken(16)));

const COMMON = new Set(["password", "password1", "password123", "1234567890", "12345678910", "qwertyuiop", "iloveyou12", "letmein123", "welcome123", "admin12345", "abc1234567", "passw0rd12"]);

export function passwordProblem(pw: string, email = ""): string | null {
  if (pw.length < MIN_PASSWORD) return `Use at least ${MIN_PASSWORD} characters.`;
  if (pw.length > 200) return "That password is too long.";
  const lower = pw.toLowerCase();
  if (COMMON.has(lower) || /^(.)\1+$/.test(pw)) return "That password is too common. Choose another.";
  const local = email.split("@")[0]?.toLowerCase();
  if (local && local.length >= 4 && lower.includes(local)) return "Do not use your email address in the password.";
  return null;
}

const emailSchema = z.string().trim().toLowerCase().max(200).regex(/^[^\s@]+@[^\s@]+\.[^\s@]+$/, "Enter a valid email address.");
const normEmail = (raw: unknown) => {
  const v = emailSchema.safeParse(raw);
  if (!v.success) throw new AppError(422, "invalid_email", "Enter a valid email address.");
  return v.data;
};

// ---------- rate limit for emails we send ----------

async function mailLimited(keys: string[]) {
  const since = new Date(Date.now() - MAIL_WINDOW_MS);
  for (const key of keys) {
    const [r] = await db.select({ n: count() }).from(loginAttempts).where(and(eq(loginAttempts.key, key), gt(loginAttempts.createdAt, since)));
    if (r.n >= MAIL_MAX) return true;
  }
  await db.insert(loginAttempts).values(keys.map((key) => ({ key })));
  return false;
}
const mailKeys = (email: string, meta: RequestMeta) => [`mail:${email}`, ...(meta.ip ? [`mail-ip:${meta.ip}`] : [])];

async function issueToken(userId: string, purpose: "verify" | "reset", ttl: number) {
  const token = randomToken(32);
  // A new link replaces older unused ones for the same purpose.
  await db.update(emailTokens).set({ usedAt: new Date() }).where(and(eq(emailTokens.userId, userId), eq(emailTokens.purpose, purpose), isNull(emailTokens.usedAt)));
  await db.insert(emailTokens).values({ tokenHash: sha256(token), userId, purpose, expiresAt: new Date(Date.now() + ttl) });
  return token;
}

async function consumeToken(token: string, purpose: "verify" | "reset") {
  if (!token || token.length > 200) return null;
  const rows = await db.update(emailTokens).set({ usedAt: new Date() })
    .where(and(eq(emailTokens.tokenHash, sha256(token)), eq(emailTokens.purpose, purpose), isNull(emailTokens.usedAt), gt(emailTokens.expiresAt, new Date())))
    .returning({ userId: emailTokens.userId });
  return rows[0]?.userId ?? null;
}

async function sendVerify(userId: string, email: string, name: string) {
  const link = appLink(`/auth/verify?token=${await issueToken(userId, "verify", VERIFY_TTL_MS)}`);
  await sendMail({
    to: email, subject: "Verify your email for RuyaShield",
    text: `Hi ${name},\n\nConfirm this address to finish creating your RuyaShield account (the link works for 24 hours):\n${link}\n\nIf you did not sign up, ignore this email.`,
    html: brandedEmail({
      preheader: "Confirm your email to finish creating your RuyaShield account.",
      title: "Verify your email", paragraphs: [`Hi ${name},`, "Confirm this address to finish creating your RuyaShield account. Then you set up your authenticator app and create or join an organization."],
      button: { label: "Verify email", href: link }, footnote: "The link works for 24 hours. If you did not sign up for RuyaShield, ignore this email.",
    }),
  });
}

// ---------- sign up ----------

const signUpInput = z.object({ name: z.string().trim().min(1, "Enter your name.").max(80), email: z.unknown(), password: z.string() });

export async function signUp(input: unknown, meta: RequestMeta) {
  const v = signUpInput.safeParse(input);
  if (!v.success) throw new AppError(422, "validation_failed", v.error.issues[0].message);
  const email = normEmail(v.data.email);
  const problem = passwordProblem(v.data.password, email);
  if (problem) throw new AppError(422, "weak_password", problem);
  if (await mailLimited(mailKeys(email, meta))) throw new AppError(429, "rate_limited", "Too many emails were requested. Try again in 15 minutes.");

  const existing = (await db.select().from(users).where(eq(users.email, email)).limit(1))[0];
  if (existing) {
    // Same answer as a new sign-up; the owner of the address learns what happened by email.
    if (existing.idpIssuer === PASSWORD_ISSUER && !existing.emailVerifiedAt) await sendVerify(existing.id, email, existing.displayName);
    else {
      const how = existing.idpIssuer === PASSWORD_ISSUER ? "your email and password" : "Google";
      await sendMail({
        to: email, subject: "You already have a RuyaShield account",
        text: `Someone tried to create a RuyaShield account with this address, which already has one. Sign in with ${how}: ${appLink("/auth/signin")}\nForgot your password? ${appLink("/auth/forgot")}`,
        html: brandedEmail({
          preheader: "This address already has a RuyaShield account.", title: "You already have an account",
          paragraphs: [`Someone tried to create a RuyaShield account with this address, which already has one. Sign in with ${how}.`, "If this was not you, you can ignore this email; nothing was changed."],
          button: { label: "Sign in", href: appLink("/auth/signin") },
        }),
      });
    }
    return;
  }
  const hash = await hashPassword(v.data.password);
  const user = await db.transaction(async (tx) => {
    const [u] = await tx.insert(users).values({ email, displayName: v.data.name, idpIssuer: PASSWORD_ISSUER, idpSubject: email }).returning();
    await tx.insert(passwordCredentials).values({ userId: u.id, hash });
    return u;
  }).catch((e: unknown) => { if (isUniqueViolation(e)) return null; throw e; });
  if (!user) return;
  await withOrg(null, (tx) => audit(tx, { actor: { type: "user", id: user.id, ip: meta.ip }, action: "auth.signup", details: { method: "password" } }));
  await sendVerify(user.id, email, user.displayName);
}

export async function resendVerification(rawEmail: unknown, meta: RequestMeta) {
  const email = normEmail(rawEmail);
  if (await mailLimited(mailKeys(email, meta))) throw new AppError(429, "rate_limited", "Too many emails were requested. Try again in 15 minutes.");
  const u = (await db.select().from(users).where(and(eq(users.email, email), eq(users.idpIssuer, PASSWORD_ISSUER))).limit(1))[0];
  if (u && !u.emailVerifiedAt && !u.disabledAt) await sendVerify(u.id, email, u.displayName);
}

export async function verifyEmail(token: string): Promise<boolean> {
  const userId = await consumeToken(token, "verify");
  if (!userId) return false;
  await db.update(users).set({ emailVerifiedAt: new Date() }).where(and(eq(users.id, userId), isNull(users.emailVerifiedAt)));
  await withOrg(null, (tx) => audit(tx, { actor: { type: "user", id: userId }, action: "auth.email_verified" }));
  return true;
}

// ---------- sign in ----------

/** Checks email + password and returns a pending-login token for the authenticator-code step. */
export async function passwordSignIn(input: { email: unknown; password: unknown; returnTo?: unknown }, meta: RequestMeta): Promise<string> {
  const ipKey = meta.ip ? [`ip:${meta.ip}`] : [];
  if (await rateLimited(ipKey)) throw new AppError(429, "rate_limited", "Too many failed sign-in attempts. Try again later.");
  const email = normEmail(input.email);
  const password = typeof input.password === "string" ? input.password : "";
  const acctKey = `acct:${email}`;
  if (await rateLimited([acctKey])) throw new AppError(429, "rate_limited", "Too many failed sign-in attempts. Try again later.");

  const row = (await db.select({ u: users, hash: passwordCredentials.hash }).from(users)
    .innerJoin(passwordCredentials, eq(passwordCredentials.userId, users.id))
    .where(and(eq(users.email, email), eq(users.idpIssuer, PASSWORD_ISSUER))).limit(1))[0];
  const ok = await verifyPassword(password, row?.hash ?? (await dummy()));
  if (!row || !ok) {
    await recordFailure([...ipKey, acctKey], meta, "bad_password", email);
    throw new AppError(401, "bad_credentials", "That email and password do not match.");
  }
  if (row.u.disabledAt) throw new AppError(403, "user_disabled", "This account is disabled.");
  if (!row.u.emailVerifiedAt) throw new AppError(403, "email_not_verified", "Verify your email first. Check your inbox for the link, or send a new one.");
  return createPendingLogin({ userId: row.u.id, amr: ["pwd"], issuer: PASSWORD_ISSUER, returnTo: safeReturnTo(input.returnTo) });
}

// ---------- forgot / reset ----------

export async function requestPasswordReset(rawEmail: unknown, meta: RequestMeta) {
  const email = normEmail(rawEmail);
  if (await mailLimited(mailKeys(email, meta))) throw new AppError(429, "rate_limited", "Too many emails were requested. Try again in 15 minutes.");
  const u = (await db.select().from(users).where(and(eq(users.email, email), eq(users.idpIssuer, PASSWORD_ISSUER))).limit(1))[0];
  if (!u || u.disabledAt) return;
  const link = appLink(`/auth/reset?token=${await issueToken(u.id, "reset", RESET_TTL_MS)}`);
  await sendMail({
    to: email, subject: "Reset your RuyaShield password",
    text: `Choose a new password (the link works for 30 minutes):\n${link}\n\nSigning in still needs your authenticator code. If you did not ask for this, ignore this email.`,
    html: brandedEmail({
      preheader: "Choose a new RuyaShield password.", title: "Reset your password",
      paragraphs: ["Use the button to choose a new password. Signing in afterwards still needs your authenticator code."],
      button: { label: "Choose a new password", href: link },
      footnote: "The link works for 30 minutes and only once. If you did not ask for this, ignore this email; your password is unchanged.",
    }),
  });
  await withOrg(null, (tx) => audit(tx, { actor: { type: "anonymous", ip: meta.ip }, action: "auth.password_reset_requested", target: { type: "user", id: u.id } }));
}

export async function resetPassword(token: string, password: unknown, meta: RequestMeta) {
  const pw = typeof password === "string" ? password : "";
  const userId = await (async () => {
    const rows = await db.select({ userId: emailTokens.userId, email: users.email }).from(emailTokens).innerJoin(users, eq(users.id, emailTokens.userId))
      .where(and(eq(emailTokens.tokenHash, sha256(token || "")), eq(emailTokens.purpose, "reset"), isNull(emailTokens.usedAt), gt(emailTokens.expiresAt, new Date()))).limit(1);
    if (!rows[0]) return null;
    const problem = passwordProblem(pw, rows[0].email);
    if (problem) throw new AppError(422, "weak_password", problem);
    return consumeToken(token, "reset");
  })();
  if (!userId) throw new AppError(410, "link_expired", "This link has expired or was already used. Ask for a new one.");
  await db.update(passwordCredentials).set({ hash: await hashPassword(pw), updatedAt: new Date() }).where(eq(passwordCredentials.userId, userId));
  // Resetting proves the address, and signs out every other session.
  await db.update(users).set({ emailVerifiedAt: new Date() }).where(and(eq(users.id, userId), isNull(users.emailVerifiedAt)));
  await revokeUserSessions(userId);
  await withOrg(null, (tx) => audit(tx, { actor: { type: "user", id: userId, ip: meta.ip }, action: "auth.password_reset" }));
}
