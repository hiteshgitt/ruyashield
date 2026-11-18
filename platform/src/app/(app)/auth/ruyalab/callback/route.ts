import type { NextRequest } from "next/server";
import { publicRequestUrl } from "@/server/http/public-url";
import { finish } from "../../_lib/finish";

/** Ruya Lab (accounts.ruyalab.com) authorization-code redirect. The authenticator-code step follows. */
export async function GET(request: NextRequest) {
  return finish(request, { kind: "oidc", idp: "ruyalab", currentUrl: publicRequestUrl(request.nextUrl) });
}
