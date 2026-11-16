import { markApplied } from "@/server/remediation/approvals";
import { api, jsonBody } from "../../../_lib/api";

/** Body: { note }. Records that the customer applied an approved guided plan; verification decides whether it worked. */
export async function POST(req: Request, ctx: RouteContext<"/v1/remediation-plans/[id]/applied">) {
  const { id } = await ctx.params;
  return api(async (c) => markApplied(c, id, await jsonBody(req)));
}
