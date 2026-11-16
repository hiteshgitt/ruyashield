import { NextResponse, type NextRequest } from "next/server";

/** Optimistic check only: redirects visitors with no session cookie. Real authorization happens server-side per request. */
export function proxy(request: NextRequest) {
  if (request.cookies.has("__Host-ruya_sid") || request.cookies.has("ruya_sid")) return NextResponse.next();
  const url = new URL("/auth/login", request.url);
  url.searchParams.set("returnTo", request.nextUrl.pathname + request.nextUrl.search);
  return NextResponse.redirect(url);
}

export const config = { matcher: ["/assets/:path*", "/settings/:path*", "/audit/:path*", "/orgs/:path*", "/approvals/:path*", "/referrals/:path*", "/attacks/:path*"] };
