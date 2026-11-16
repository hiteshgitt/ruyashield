import { NextResponse, type NextRequest } from "next/server";
import { completeLogin, LOGIN_STATE_COOKIE, type CallbackInput } from "@/server/auth/login";
import { secureCookies, sessionCookieName } from "@/server/auth/session";
import { isAppError } from "@/server/errors";
import { log } from "@/server/log";
import { publicRequestUrl, publicUrl } from "@/server/http/public-url";

function meta(request: NextRequest) {
  const fwd = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim();
  return {
    ip: fwd || request.headers.get("x-real-ip") || null,
    userAgent: request.headers.get("user-agent"),
    browserState: request.cookies.get(LOGIN_STATE_COOKIE)?.value ?? null,
  };
}

async function finish(request: NextRequest, input: CallbackInput) {
  try {
    const s = await completeLogin(input, meta(request));
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

/** OIDC authorization-code redirect. */
export async function GET(request: NextRequest) {
  return finish(request, { kind: "oidc", currentUrl: publicRequestUrl(request.nextUrl) });
}

/** Local dev sign-in form (AUTH_PROVIDER=dev only; completeLogin refuses it otherwise). */
export async function POST(request: NextRequest) {
  const f = await request.formData();
  const str = (k: string) => (typeof f.get(k) === "string" ? (f.get(k) as string) : "");
  return finish(request, { kind: "dev", state: str("state"), email: str("email"), name: str("name"), mfa: f.get("mfa") === "on" });
}
