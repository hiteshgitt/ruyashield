import { and, count, eq, gt, inArray, lt } from "drizzle-orm";
import * as oidc from "openid-client";
import { db, withOrg } from "../db/client";
import { loginAttempts, loginStates, users } from "../db/schema";
import { audit } from "../audit/audit";
import { AppError, isUniqueViolation } from "../errors";
import { createSession, randomToken } from "./session";
import { createPendingLogin } from "./mfa";

const LOGIN_STATE_TTL_MS = 10 * 60 * 1000;
const RATE_WINDOW_MS = 15 * 60 * 1000;
const RATE_MAX_FAILURES = 10;
const MFA_AMR = new Set(["mfa", "otp", "hwk", "swk"]);

export type ProviderKind = "dev" | "oidc";

export function providerKind(): ProviderKind {
  const p = process.env.AUTH_PROVIDER ?? "oidc";
  if (p === "dev") {
    if (process.env.NODE_ENV === "production") throw new Error("AUTH_PROVIDER=dev is refused in production");
    return "dev";
  }
  return "oidc";
}

/** Only same-origin relative paths are allowed as post-login destinations (open-redirect guard). */
export function safeReturnTo(v: unknown): string {
  if (typeof v !== "string" || !v.startsWith("/") || v.startsWith("//") || v.startsWith("/\\") || v.length > 500) return "/";
  return v;
}

/** amr without an MFA method, or missing amr, means no MFA (fail closed). */
export const amrHasMfa = (amr: readonly string[] | undefined) => !!amr?.some((m) => MFA_AMR.has(m));

/** "oidc" is the original provider (Google); "ruyalab" is the shared Ruya Lab account (accounts.ruyalab.com). */
export type Idp = "oidc" | "ruyalab";

/** Ruya Lab sign-in is offered when its client is configured. */
export const ruyaLabEnabled = () => Boolean(process.env.RUYALAB_ISSUER && process.env.RUYALAB_CLIENT_ID && process.env.RUYALAB_CLIENT_SECRET);

const oidcConfigs = new Map<Idp, Promise<oidc.Configuration>>();
function getOidcConfig(idp: Idp = "oidc"): Promise<oidc.Configuration> {
  const env = idp === "ruyalab"
    ? { issuer: process.env.RUYALAB_ISSUER, id: process.env.RUYALAB_CLIENT_ID, secret: process.env.RUYALAB_CLIENT_SECRET }
    : { issuer: process.env.OIDC_ISSUER, id: process.env.OIDC_CLIENT_ID, secret: process.env.OIDC_CLIENT_SECRET };
  if (!env.issuer || !env.id) throw new AppError(503, "auth_not_configured", "OIDC is not configured");
  let p = oidcConfigs.get(idp);
  if (!p) {
    // Plain-HTTP issuers only for local testing (never in production).
    const opts = env.issuer.startsWith("http://") && process.env.NODE_ENV !== "production" ? { execute: [oidc.allowInsecureRequests] } : undefined;
    p = oidc.discovery(new URL(env.issuer), env.id, env.secret || undefined, undefined, opts).catch((e) => {
      oidcConfigs.delete(idp);
      throw e;
    });
    oidcConfigs.set(idp, p);
  }
  return p;
}

const callbackUrl = (idp: Idp = "oidc") => new URL(idp === "ruyalab" ? "/auth/ruyalab/callback" : "/auth/callback", process.env.APP_URL ?? "http://localhost:3200").toString();

export const LOGIN_STATE_COOKIE = "ruya_login_state";
export const LOGIN_STATE_TTL_S = LOGIN_STATE_TTL_MS / 1000;

/**
 * Starts a login: stores one-shot state/nonce/PKCE and returns where to send the browser.
 * The caller must also set `state` in a browser cookie; the callback requires both to match (login CSRF).
 */
export async function startLogin(opts: { returnTo?: string; stepUp?: boolean; idp?: Idp }): Promise<{ url: string; state: string }> {
  const idp: Idp = opts.idp === "ruyalab" ? "ruyalab" : "oidc";
  if (idp === "ruyalab" && !ruyaLabEnabled()) throw new AppError(503, "auth_not_configured", "Ruya Lab sign-in is not configured");
  const state = randomToken(24), nonce = randomToken(24), codeVerifier = oidc.randomPKCECodeVerifier();
  await db.insert(loginStates).values({ state, nonce, codeVerifier, returnTo: safeReturnTo(opts.returnTo), provider: idp });
  await db.delete(loginStates).where(lt(loginStates.createdAt, new Date(Date.now() - LOGIN_STATE_TTL_MS)));

  if (idp === "oidc" && providerKind() === "dev") return { url: `/auth/dev?state=${encodeURIComponent(state)}`, state };

  const config = await getOidcConfig(idp);
  const params: Record<string, string> = {
    redirect_uri: callbackUrl(idp), scope: "openid email profile", state, nonce,
    code_challenge: await oidc.calculatePKCECodeChallenge(codeVerifier), code_challenge_method: "S256",
  };
  // Always show the provider's account chooser, so after signing out a different (or new) account can be used
  // instead of silently reusing the one the browser is signed in to.
  // Ruya Lab is single sign-on across Ruya Lab products: an existing Ruya Lab session is reused.
  if (idp === "oidc") Object.assign(params, opts.stepUp ? { prompt: "login", max_age: "0" } : { prompt: "select_account" });
  else if (opts.stepUp) Object.assign(params, { prompt: "login", max_age: "0" });
  return { url: oidc.buildAuthorizationUrl(config, params).toString(), state };
}

interface Identity { issuer: string; subject: string; email: string; name: string; amr: string[]; authTime: Date }

export type CallbackInput =
  | { kind: "dev"; state: string; email: string; name: string; mfa: boolean }
  | { kind: "oidc"; currentUrl: URL; idp?: Idp };

export interface RequestMeta { ip: string | null; userAgent: string | null }

export async function rateLimited(keys: string[]): Promise<boolean> {
  const since = new Date(Date.now() - RATE_WINDOW_MS);
  const rows = await db.select({ key: loginAttempts.key, n: count() }).from(loginAttempts)
    .where(and(inArray(loginAttempts.key, keys), gt(loginAttempts.createdAt, since)))
    .groupBy(loginAttempts.key);
  return rows.some((r) => r.n >= RATE_MAX_FAILURES);
}

export async function recordFailure(keys: string[], meta: RequestMeta, reason: string, email?: string) {
  if (keys.length) await db.insert(loginAttempts).values(keys.map((key) => ({ key })));
  await withOrg(null, (tx) => audit(tx, {
    actor: { type: "anonymous", ip: meta.ip }, action: "auth.login_failed", outcome: "denied", reason,
    details: email ? { email } : {},
  }));
}

/** Completes a login and returns a new session token plus the post-login destination. */
export type LoginResult =
  | { kind: "session"; token: string; expiresAt: Date; returnTo: string }
  /** OIDC: identity proven, now the person must enter their authenticator code (see mfa.ts). */
  | { kind: "mfa"; pendingToken: string };

export async function completeLogin(input: CallbackInput, meta: RequestMeta & { browserState?: string | null }): Promise<LoginResult> {
  const ipKey = meta.ip ? [`ip:${meta.ip}`] : [];
  if (await rateLimited(ipKey)) throw new AppError(429, "rate_limited", "Too many failed sign-in attempts. Try again later.");

  const state = input.kind === "dev" ? input.state : input.currentUrl.searchParams.get("state") ?? "";
  if (!state || state !== meta.browserState) {
    await recordFailure(ipKey, meta, "state_mismatch");
    throw new AppError(400, "invalid_state", "Sign-in link expired or was opened in a different browser. Please start again.");
  }
  const consumed = await db.delete(loginStates)
    .where(and(eq(loginStates.state, state), gt(loginStates.createdAt, new Date(Date.now() - LOGIN_STATE_TTL_MS))))
    .returning();
  const ls = consumed[0];
  if (!ls) {
    await recordFailure(ipKey, meta, "invalid_state");
    throw new AppError(400, "invalid_state", "Sign-in link expired or already used. Please start again.");
  }

  let id: Identity;
  try {
    if (input.kind === "oidc" && (input.idp ?? "oidc") !== ls.provider) throw new AppError(400, "provider_mismatch");
    id = input.kind === "dev" ? devIdentity(input) : await oidcIdentity(input.currentUrl, ls);
  } catch (e) {
    await recordFailure(ipKey, meta, e instanceof AppError ? e.code : "idp_error");
    throw e instanceof AppError ? e : new AppError(400, "idp_error", "Sign-in with the identity provider failed.");
  }

  const acctKey = `acct:${id.email}`;
  if (await rateLimited([acctKey])) throw new AppError(429, "rate_limited", "Too many failed sign-in attempts. Try again later.");

  const user = ls.provider === "ruyalab" ? await linkRuyaLabUser(id) : await upsertUser(id);
  if (user.disabledAt) {
    await recordFailure([...ipKey, acctKey], meta, "user_disabled", id.email);
    throw new AppError(403, "user_disabled", "This account is disabled.");
  }
  // Real identity providers (Google) do not report 2-step verification, so every OIDC sign-in continues
  // to RuyaShield's own authenticator-code step; the session is created only after that.
  if (input.kind === "oidc") {
    const pendingToken = await createPendingLogin({ userId: user.id, amr: id.amr, issuer: id.issuer, returnTo: ls.returnTo });
    return { kind: "mfa", pendingToken };
  }
  const mfa = amrHasMfa(id.amr);
  const s = await createSession({ userId: user.id, mfa, amr: id.amr, authTime: id.authTime, ip: meta.ip, userAgent: meta.userAgent });
  await withOrg(null, (tx) => audit(tx, {
    actor: { type: "user", id: user.id, ip: meta.ip }, action: "auth.login", details: { mfa, amr: id.amr, provider: id.issuer },
  }));
  return { kind: "session", ...s, returnTo: ls.returnTo };
}

function devIdentity(i: Extract<CallbackInput, { kind: "dev" }>): Identity {
  if (providerKind() !== "dev") throw new AppError(400, "provider_mismatch");
  const email = i.email.trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 200) throw new AppError(400, "invalid_email", "Enter a valid email.");
  const name = i.name.trim().slice(0, 80) || email.split("@")[0];
  return { issuer: "dev", subject: `dev:${email}`, email, name, amr: i.mfa ? ["pwd", "mfa"] : ["pwd"], authTime: new Date() };
}

async function oidcIdentity(currentUrl: URL, ls: typeof loginStates.$inferSelect): Promise<Identity> {
  if (ls.provider === "oidc" && providerKind() !== "oidc") throw new AppError(400, "provider_mismatch");
  const config = await getOidcConfig(ls.provider);
  const tokens = await oidc.authorizationCodeGrant(config, currentUrl, {
    pkceCodeVerifier: ls.codeVerifier, expectedState: ls.state, expectedNonce: ls.nonce, idTokenExpected: true,
  });
  const c = tokens.claims();
  if (!c) throw new AppError(400, "idp_error");
  const email = typeof c.email === "string" ? c.email.toLowerCase() : "";
  if (!email || c.email_verified === false) throw new AppError(403, "email_unverified", "Your identity provider did not supply a verified email.");
  // Ruya Lab always states it; anything but an explicit true is not a verified address.
  if (ls.provider === "ruyalab" && c.email_verified !== true) throw new AppError(403, "email_unverified", "Confirm your email in your Ruya Lab account first.");
  const amr = Array.isArray(c.amr) ? c.amr.filter((x): x is string => typeof x === "string") : [];
  const authTime = typeof c.auth_time === "number" ? new Date(c.auth_time * 1000) : new Date(0); // unknown => never fresh
  return { issuer: c.iss, subject: c.sub, email, name: typeof c.name === "string" ? c.name : email, amr, authTime };
}

async function upsertUser(id: Identity) {
  const rows = await db.insert(users)
    .values({ email: id.email, displayName: id.name, idpIssuer: id.issuer, idpSubject: id.subject, emailVerifiedAt: new Date() })
    .onConflictDoUpdate({ target: [users.idpIssuer, users.idpSubject], set: { email: id.email, displayName: id.name } })
    .returning()
    .catch((e: unknown) => {
      if (isUniqueViolation(e)) throw new AppError(409, "account_conflict", "This email already has a RuyaShield account that signs in with email and password. Sign in with your email instead.");
      throw e;
    });
  return rows[0];
}

/**
 * A Ruya Lab identity: the user already linked to it, else the RuyaShield user with the same (verified) email, which
 * gets linked, else a new user. Signing in still needs RuyaShield's authenticator code afterwards.
 */
async function linkRuyaLabUser(id: Identity) {
  const linked = (await db.select().from(users).where(eq(users.ruyalabSub, id.subject)).limit(1))[0];
  if (linked) return linked;
  const byEmail = (await db.select().from(users).where(eq(users.email, id.email)).limit(1))[0];
  if (byEmail) {
    if (byEmail.ruyalabSub && byEmail.ruyalabSub !== id.subject) throw new AppError(409, "account_conflict", "This RuyaShield account is linked to a different Ruya Lab account.");
    const [u] = await db.update(users).set({ ruyalabSub: id.subject, emailVerifiedAt: byEmail.emailVerifiedAt ?? new Date() }).where(eq(users.id, byEmail.id)).returning();
    await withOrg(null, (tx) => audit(tx, { actor: { type: "user", id: u.id }, action: "auth.ruyalab_linked", details: { issuer: id.issuer } }));
    return u;
  }
  const [u] = await db.insert(users).values({
    email: id.email, displayName: id.name, idpIssuer: id.issuer, idpSubject: id.subject, ruyalabSub: id.subject, emailVerifiedAt: new Date(),
  }).returning();
  return u;
}

export async function auditLogout(userId: string, ip: string | null) {
  await withOrg(null, (tx) => audit(tx, { actor: { type: "user", id: userId, ip }, action: "auth.logout" }));
}
