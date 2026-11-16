import { NextResponse, type NextRequest } from "next/server";
import { LOGIN_STATE_COOKIE, LOGIN_STATE_TTL_S, startLogin } from "@/server/auth/login";
import { secureCookies } from "@/server/auth/session";
import { isAppError } from "@/server/errors";

export async function GET(request: NextRequest) {
  const sp = request.nextUrl.searchParams;
  try {
    const { url, state } = await startLogin({ returnTo: sp.get("returnTo") ?? "/", stepUp: sp.get("stepUp") === "1" });
    const res = NextResponse.redirect(new URL(url, request.nextUrl));
    res.cookies.set(LOGIN_STATE_COOKIE, state, { httpOnly: true, sameSite: "lax", secure: secureCookies(), path: "/auth", maxAge: LOGIN_STATE_TTL_S });
    return res;
  } catch (e) {
    const code = isAppError(e) ? e.code : "login_unavailable";
    return NextResponse.redirect(new URL(`/auth/error?code=${encodeURIComponent(code)}`, request.nextUrl), 303);
  }
}
