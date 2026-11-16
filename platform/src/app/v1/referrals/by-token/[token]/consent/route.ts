import { decideReferral } from "@/server/webmonitor/referrals";
import { api, jsonBody } from "../../../../_lib/api";

/** Body: { decision: "consent" | "decline" | "delete", textVersion, acceptCharges?, shareStatus? }. Uses the token once. */
export async function POST(req: Request, ctx: RouteContext<"/v1/referrals/by-token/[token]/consent">) {
  const { token } = await ctx.params;
  return api(async (c) => decideReferral(c, token, await jsonBody(req)));
}
