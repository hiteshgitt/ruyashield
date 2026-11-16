import { NextResponse, type NextRequest } from "next/server";
import { verifyEmail } from "@/server/auth/password";
import { publicUrl } from "@/server/http/public-url";

/** The link in the verification email. */
export async function GET(request: NextRequest) {
  const ok = await verifyEmail(request.nextUrl.searchParams.get("token") ?? "");
  return NextResponse.redirect(publicUrl(ok ? "/auth/signin?verified=1" : "/auth/signin?error=link_expired&msg=This+verification+link+has+expired+or+was+already+used.+Sign+in+to+get+a+new+one."), 303);
}
