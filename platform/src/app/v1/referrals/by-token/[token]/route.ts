import { getReferralByToken } from "@/server/webmonitor/referrals";
import { api } from "../../../_lib/api";

/** What a referral link may show: minimal, untrusted context and the consent text version. */
export async function GET(_: Request, ctx: RouteContext<"/v1/referrals/by-token/[token]">) {
  const { token } = await ctx.params;
  return api((c) => getReferralByToken(c, token));
}
