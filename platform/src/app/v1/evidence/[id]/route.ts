import { getEvidence } from "@/server/findings/findings";
import { api } from "../../_lib/api";

/** Redacted evidence with its integrity status. A failed integrity check returns body: null. */
export async function GET(_: Request, ctx: RouteContext<"/v1/evidence/[id]">) {
  const { id } = await ctx.params;
  return api((c) => getEvidence(c, id));
}
