import { getSession } from "@/server/context";
import { decideApproval } from "@/server/remediation/approvals";
import { api, jsonBody } from "../../../_lib/api";

/** Body: { decision: "approve"|"reject", reason?, subjectSha256 }. Requires step-up; the requester cannot decide (RS-REMED-005). */
export async function POST(req: Request, ctx: RouteContext<"/v1/approvals/[id]/decision">) {
  const { id } = await ctx.params;
  return api(async (c) => {
    const session = await getSession();
    return decideApproval(c, id, await jsonBody(req), { ref: session?.idHash.slice(0, 16) ?? null });
  });
}
