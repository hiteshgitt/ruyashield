"use server";
import { cookies } from "next/headers";
import { getSession, requestMeta } from "@/server/context";
import { completeMfaLogin, PENDING_COOKIE, stepUp } from "@/server/auth/mfa";
import { safeReturnTo } from "@/server/auth/login";
import { secureCookies, sessionCookieName } from "@/server/auth/session";
import { isAppError } from "@/server/errors";
import { log } from "@/server/log";
import { messageFor } from "../../_lib/messages";

export type MfaState = { error?: string; expired?: boolean; done?: { returnTo: string; recoveryCodes: string[] | null; usedRecovery: boolean } } | null;

const fail = (e: unknown): MfaState => {
  if (isAppError(e)) return { error: messageFor(e.code, e.message), expired: e.code === "mfa_login_expired" };
  log.error("mfa action failed", { err: e instanceof Error ? e.message : String(e) });
  return { error: messageFor("internal") };
};
const codeOf = (f: FormData) => String(f.get("code") ?? "").slice(0, 40);

/** Sign-in: the pending-login cookie plus a code becomes a real session. */
export async function verifyLoginCode(_prev: MfaState, f: FormData): Promise<MfaState> {
  try {
    const jar = await cookies();
    const meta = await requestMeta();
    const r = await completeMfaLogin(jar.get(PENDING_COOKIE)?.value, codeOf(f), meta);
    jar.set(sessionCookieName(), r.token, { httpOnly: true, sameSite: "lax", secure: secureCookies(), path: "/", expires: r.expiresAt });
    jar.delete({ name: PENDING_COOKIE, path: "/auth" });
    return { done: { returnTo: r.returnTo, recoveryCodes: r.recoveryCodes, usedRecovery: r.usedRecovery } };
  } catch (e) {
    return fail(e);
  }
}

/** Step-up: a fresh code on the current session, for sensitive actions. */
export async function verifyStepUpCode(_prev: MfaState, f: FormData): Promise<MfaState> {
  try {
    const session = await getSession();
    if (!session) return { error: messageFor("unauthenticated"), expired: true };
    await stepUp(session, codeOf(f), await requestMeta());
    return { done: { returnTo: safeReturnTo(f.get("returnTo")), recoveryCodes: null, usedRecovery: false } };
  } catch (e) {
    return fail(e);
  }
}
