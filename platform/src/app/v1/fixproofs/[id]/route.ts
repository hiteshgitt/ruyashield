import { getFixProof } from "@/server/verification/verification";
import { api } from "../../_lib/api";

/** A FixProof record with its integrity status; content is withheld when integrity fails (RS-FIXP-002). */
export async function GET(_: Request, ctx: RouteContext<"/v1/fixproofs/[id]">) {
  const { id } = await ctx.params;
  return api((c) => getFixProof(c, id));
}
