import { transition } from "@/server/findings/findings";
import { AppError } from "@/server/errors";
import { api } from "../../../_lib/api";

/** Body: { kind, justification?, controls?, expiresAt?, reason? }. Same rules as the UI. */
export async function POST(req: Request, ctx: RouteContext<"/v1/findings/[id]/transitions">) {
  const { id } = await ctx.params;
  return api(async (c) => {
    if (!req.headers.get("content-type")?.startsWith("application/json")) throw new AppError(422, "unsupported_media_type", "Send application/json.");
    const body = (await req.json().catch(() => null)) as Record<string, unknown> | null;
    if (!body || typeof body.kind !== "string") throw new AppError(422, "transition_not_allowed", "kind is required.");
    return transition(c, id, body.kind, body);
  });
}
