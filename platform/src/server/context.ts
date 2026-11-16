import "server-only";
import { randomUUID } from "node:crypto";
import { cookies, headers } from "next/headers";
import { connection } from "next/server";
import { readSession, sessionCookieName, setActiveOrg, type SessionInfo } from "./auth/session";
import { loadBreakGlassPrincipal, loadPrincipal, type LoadedPrincipal } from "./principal";
import { AppError } from "./errors";

export async function requestMeta() {
  const h = await headers();
  const fwd = h.get("x-forwarded-for")?.split(",")[0]?.trim();
  return { ip: fwd || h.get("x-real-ip") || null, userAgent: h.get("user-agent"), requestId: h.get("x-request-id") || randomUUID() };
}

/** Current session or null. Never cached: auth state must be read per request. */
export async function getSession(): Promise<SessionInfo | null> {
  await connection(); // session expiry depends on the current time; never prerender it
  const token = (await cookies()).get(sessionCookieName())?.value;
  return readSession(token);
}

export async function requireSession(): Promise<SessionInfo> {
  const s = await getSession();
  if (!s) throw new AppError(401, "unauthenticated");
  return s;
}

/** Session + principal for the active org. Returns null org context if none selected or membership is gone. */
export async function getContext(): Promise<{ session: SessionInfo; ctx: LoadedPrincipal | null } | null> {
  const session = await getSession();
  if (!session) return null;
  if (!session.activeOrgId) return { session, ctx: null };
  const meta = await requestMeta();
  // Members first; an operator without membership only gets in through a live break-glass session (RS-PLAT-007).
  const ctx = (await loadPrincipal(session, session.activeOrgId, meta))
    ?? (await loadBreakGlassPrincipal(session, session.activeOrgId, meta));
  if (!ctx) await setActiveOrg(session.idHash, null);
  return { session, ctx };
}

/** For server actions: re-checks auth on every call (RS-IAM-004). */
export async function requireOrgContext(): Promise<{ session: SessionInfo } & LoadedPrincipal> {
  const c = await getContext();
  if (!c) throw new AppError(401, "unauthenticated");
  if (!c.ctx) throw new AppError(409, "no_active_org");
  return { session: c.session, ...c.ctx };
}

/** `Authorization: Bearer rs_...` for API clients. Undefined when no bearer header was sent; null when it is invalid. */
export async function getBearerContext(): Promise<LoadedPrincipal | null | undefined> {
  await connection();
  const auth = (await headers()).get("authorization");
  if (!auth) return undefined;
  const m = /^Bearer\s+(\S+)$/i.exec(auth);
  if (!m) return null;
  const { resolveApiToken } = await import("./tokens/tokens");
  return resolveApiToken(m[1], await requestMeta());
}
