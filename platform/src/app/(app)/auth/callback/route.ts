import type { NextRequest } from "next/server";
import { publicRequestUrl } from "@/server/http/public-url";
import { finish } from "../_lib/finish";

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
