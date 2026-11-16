import { listAnalyses, requestAnalysis } from "@/server/ai/gateway";
import { AppError } from "@/server/errors";
import { api } from "../../../_lib/api";

/** Recent AI analyses of a finding, with their validated claims. Advisory only. */
export async function GET(_: Request, ctx: RouteContext<"/v1/findings/[id]/ai-analyses">) {
  const { id } = await ctx.params;
  return api(async (c) => ({ analyses: await listAnalyses(c, id) }));
}

/** Body: { useCase: "explain" | "remediation", idempotencyKey }. Never changes the finding (RS-AI-001). */
export async function POST(req: Request, ctx: RouteContext<"/v1/findings/[id]/ai-analyses">) {
  const { id } = await ctx.params;
  return api(async (c) => {
    if (!req.headers.get("content-type")?.startsWith("application/json")) throw new AppError(422, "unsupported_media_type", "Send application/json.");
    return requestAnalysis(c, id, await req.json().catch(() => null));
  });
}
