import { deleteReferral } from "@/server/webmonitor/referrals";
import { api } from "../../_lib/api";

/** Deletes a claimed referral's context and stops any further link-back (FR-041). */
export async function DELETE(_: Request, ctx: RouteContext<"/v1/referrals/[id]">) {
  const { id } = await ctx.params;
  return api((c) => deleteReferral(c, id));
}
