import { createPlan, createPlanFromAi, listPlansForFinding } from "@/server/remediation/plans";
import { api, jsonBody } from "../../../_lib/api";

/** Remediation plans for a finding, newest first (RS-REMED-001). */
export async function GET(_: Request, ctx: RouteContext<"/v1/findings/[id]/remediation-plans">) {
  const { id } = await ctx.params;
  return api(async (c) => ({ plans: await listPlansForFinding(c, id) }));
}

/**
 * Body: { idempotencyKey, type: "guided"|"patch", title, description, ... } for a hand-written plan, or
 * { idempotencyKey, claimId } to start a draft from an AI recommendation. Either way the plan starts as a draft.
 */
export async function POST(req: Request, ctx: RouteContext<"/v1/findings/[id]/remediation-plans">) {
  const { id } = await ctx.params;
  return api(async (c) => {
    const body = await jsonBody(req);
    const fromAi = !!body && typeof body === "object" && "claimId" in body;
    return fromAi ? createPlanFromAi(c, id, body) : createPlan(c, id, body);
  });
}
