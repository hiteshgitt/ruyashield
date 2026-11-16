import { NextResponse, type NextRequest } from "next/server";
import { LOGIN_STATE_COOKIE, LOGIN_STATE_TTL_S, providerKind, safeReturnTo, startLogin } from "@/server/auth/login";
import { secureCookies } from "@/server/auth/session";
import { isAppError } from "@/server/errors";
import { publicUrl } from "@/server/http/public-url";

export async function GET(request: NextRequest) {
  const sp = request.nextUrl.searchParams;
  // With OIDC, step-up means entering a fresh authenticator code (the /auth/mfa page needs a live session).
  let oidc = false;
  try { oidc = providerKind() === "oidc"; } catch { /* misconfigured provider: fall through to the error below */ }
  if (sp.get("stepUp") === "1" && oidc) {
    const q = new URLSearchParams({ stepUp: "1", returnTo: safeReturnTo(sp.get("returnTo")) });
    return NextResponse.redirect(publicUrl(`/auth/mfa?${q}`), 303);
  }
  try {
    const { url, state } = await startLogin({ returnTo: sp.get("returnTo") ?? "/", stepUp: sp.get("stepUp") === "1" });
    const res = NextResponse.redirect(publicUrl(url));
    res.cookies.set(LOGIN_STATE_COOKIE, state, { httpOnly: true, sameSite: "lax", secure: secureCookies(), path: "/auth", maxAge: LOGIN_STATE_TTL_S });
    return res;
  } catch (e) {
    const code = isAppError(e) ? e.code : "login_unavailable";
    return NextResponse.redirect(publicUrl(`/auth/error?code=${encodeURIComponent(code)}`), 303);
  }
}
