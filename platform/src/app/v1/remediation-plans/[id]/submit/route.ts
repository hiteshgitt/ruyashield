import { submitPlan } from "@/server/remediation/plans";
import { api } from "../../../_lib/api";

/** Moves a draft to proposed. */
export async function POST(_: Request, ctx: RouteContext<"/v1/remediation-plans/[id]/submit">) {
  const { id } = await ctx.params;
  return api((c) => submitPlan(c, id));
}
