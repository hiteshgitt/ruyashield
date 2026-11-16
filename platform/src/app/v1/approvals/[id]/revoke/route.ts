import { revokeApproval } from "@/server/remediation/approvals";
import { api, jsonBody } from "../../../_lib/api";

/** Body: { reason }. Withdraws a pending request or revokes an approval that has not been used yet. */
export async function POST(req: Request, ctx: RouteContext<"/v1/approvals/[id]/revoke">) {
  const { id } = await ctx.params;
  return api(async (c) => revokeApproval(c, id, await jsonBody(req)));
}
