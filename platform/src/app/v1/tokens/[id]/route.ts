import { revokeApiToken } from "@/server/tokens/tokens";
import { api } from "../../_lib/api";

export async function DELETE(_: Request, ctx: RouteContext<"/v1/tokens/[id]">) {
  const { id } = await ctx.params;
  return api(async (c) => { await revokeApiToken(c, id); return { revoked: true }; });
}
