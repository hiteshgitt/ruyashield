import { NextResponse, type NextRequest } from "next/server";
import { completeLogin, LOGIN_STATE_COOKIE, type CallbackInput } from "@/server/auth/login";
import { PENDING_COOKIE, PENDING_LOGIN_TTL_MS } from "@/server/auth/mfa";
import { secureCookies, sessionCookieName } from "@/server/auth/session";
import { isAppError } from "@/server/errors";
import { log } from "@/server/log";
import { publicUrl } from "@/server/http/public-url";

// Shared end of every sign-in (Google, Ruya Lab, local dev): the authenticator step or the session.
function meta(request: NextRequest) {
  const fwd = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim();
  return {
    ip: fwd || request.headers.get("x-real-ip") || null,
    userAgent: request.headers.get("user-agent"),
    browserState: request.cookies.get(LOGIN_STATE_COOKIE)?.value ?? null,
  };
}

export async function finish(request: NextRequest, input: CallbackInput) {
  try {
    const s = await completeLogin(input, meta(request));
    if (s.kind === "mfa") {
      const res = NextResponse.redirect(publicUrl("/auth/mfa"), 303);
      res.cookies.set(PENDING_COOKIE, s.pendingToken, { httpOnly: true, sameSite: "lax", secure: secureCookies(), path: "/auth", maxAge: PENDING_LOGIN_TTL_MS / 1000 });
      res.cookies.delete({ name: LOGIN_STATE_COOKIE, path: "/auth" });
      return res;
    }
    const res = NextResponse.redirect(publicUrl(s.returnTo), 303);
    res.cookies.set(sessionCookieName(), s.token, { httpOnly: true, sameSite: "lax", secure: secureCookies(), path: "/", expires: s.expiresAt });
    res.cookies.delete({ name: LOGIN_STATE_COOKIE, path: "/auth" });
    return res;
  } catch (e) {
    if (!isAppError(e)) log.error("login callback failed", { err: String(e) });
    const code = isAppError(e) ? e.code : "login_failed";
    return NextResponse.redirect(publicUrl(`/auth/error?code=${encodeURIComponent(code)}`), 303);
  }
}

