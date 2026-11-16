import { requestSandbox } from "@/server/remediation/plans";
import { api, jsonBody } from "../../../_lib/api";

/** Body: { idempotencyKey }. Queues the repository's test commands against the patched checkout (RS-REMED-002). */
export async function POST(req: Request, ctx: RouteContext<"/v1/remediation-plans/[id]/sandbox-runs">) {
  const { id } = await ctx.params;
  return api(async (c) => requestSandbox(c, id, await jsonBody(req)));
}
