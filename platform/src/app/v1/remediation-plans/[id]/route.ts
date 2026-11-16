import { editPlan, getPlan } from "@/server/remediation/plans";
import { api, jsonBody } from "../../_lib/api";

/** Plan with its history, sandbox runs, approvals and code changes. */
export async function GET(_: Request, ctx: RouteContext<"/v1/remediation-plans/[id]">) {
  const { id } = await ctx.params;
  return api((c) => getPlan(c, id));
}

/** Body: { version, ...changed fields }. Editing content invalidates any open approval for the old content. */
export async function PATCH(req: Request, ctx: RouteContext<"/v1/remediation-plans/[id]">) {
  const { id } = await ctx.params;
  return api(async (c) => editPlan(c, id, await jsonBody(req)));
}
