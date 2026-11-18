"use server";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { getSession, requestMeta } from "@/server/context";
import { completeMfaLogin, dismissReveal, PENDING_COOKIE, stepUp } from "@/server/auth/mfa";
import { safeReturnTo } from "@/server/auth/login";
import { secureCookies, sessionCookieName } from "@/server/auth/session";
import { isAppError } from "@/server/errors";
import { log } from "@/server/log";
import { messageFor } from "../../_lib/messages";

export type MfaState = { error?: string; expired?: boolean } | null;

const fail = (e: unknown): MfaState => {
  if (isAppError(e)) return { error: messageFor(e.code, e.message), expired: e.code === "mfa_login_expired" };
  log.error("mfa action failed", { err: e instanceof Error ? e.message : String(e) });
  return { error: messageFor("internal") };
};
const codeOf = (f: FormData) => String(f.get("code") ?? "").slice(0, 40);

// Setting cookies in a server action makes Next.js re-render the page, so success always ends in a redirect:
// to the destination, or (after enrolling) back to /auth/mfa, which shows the new recovery codes from the server.

/** Sign-in: the pending-login cookie plus a code becomes a real session. */
export async function verifyLoginCode(_prev: MfaState, f: FormData): Promise<MfaState> {
  let next: string;
  try {
    const jar = await cookies();
    const r = await completeMfaLogin(jar.get(PENDING_COOKIE)?.value, codeOf(f), await requestMeta(), { remember: f.get("remember") === "on" });
    jar.set(sessionCookieName(), r.token, { httpOnly: true, sameSite: "lax", secure: secureCookies(), path: "/", expires: r.expiresAt });
    jar.delete({ name: PENDING_COOKIE, path: "/auth" });
    next = r.enrolled ? "/auth/mfa?saved=0" : safeReturnTo(r.returnTo);
  } catch (e) {
    return fail(e);
  }
  redirect(next);
}

/** Step-up: a fresh code on the current session, for sensitive actions. */
export async function verifyStepUpCode(_prev: MfaState, f: FormData): Promise<MfaState> {
  try {
    const session = await getSession();
    if (!session) return { error: messageFor("unauthenticated"), expired: true };
    await stepUp(session, codeOf(f), await requestMeta());
  } catch (e) {
    return fail(e);
  }
  redirect(safeReturnTo(f.get("returnTo")));
}

/** "I have saved them": forget the displayed recovery codes and continue. */
export async function confirmRecoverySaved(): Promise<void> {
  const session = await getSession();
  const to = session ? await dismissReveal(session.userId) : "/auth/login";
  redirect(safeReturnTo(to));
}
