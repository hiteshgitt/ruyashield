import { disableSource } from "@/server/attacks/attacks";
import { api } from "../../../_lib/api";

export async function DELETE(_: Request, ctx: RouteContext<"/v1/attacks/sources/[id]">) {
  const { id } = await ctx.params;
  return api(async (c) => { await disableSource(c, id); return { disabled: true }; });
}
