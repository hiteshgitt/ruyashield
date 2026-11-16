import { requestApproval } from "@/server/remediation/approvals";
import { api, jsonBody } from "../../../_lib/api";

/** Body: { idempotencyKey, note?, untestedOverride? }. Asks an eligible approver to review this exact plan content (RS-REMED-005). */
export async function POST(req: Request, ctx: RouteContext<"/v1/remediation-plans/[id]/approval-requests">) {
  const { id } = await ctx.params;
  return api(async (c) => requestApproval(c, id, await jsonBody(req)));
}
