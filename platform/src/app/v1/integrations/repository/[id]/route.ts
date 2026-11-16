import { disableIntegration } from "@/server/remediation/integrations";
import { api } from "../../../_lib/api";

/** Disables the integration; existing records stay for audit. */
export async function DELETE(_: Request, ctx: RouteContext<"/v1/integrations/repository/[id]">) {
  const { id } = await ctx.params;
  return api((c) => disableIntegration(c, id));
}
