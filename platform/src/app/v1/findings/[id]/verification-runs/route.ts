import { listVerifications, requestVerification } from "@/server/verification/verification";
import { AppError } from "@/server/errors";
import { api } from "../../../_lib/api";

/** Run history for a finding (RS-VERIF-004). */
export async function GET(_: Request, ctx: RouteContext<"/v1/findings/[id]/verification-runs">) {
  const { id } = await ctx.params;
  return api(async (c) => {
    const v = await listVerifications(c, id);
    return { runs: v.runs, fixproofId: v.active?.id ?? null, supportedChecks: v.supported };
  });
}

/** Body: { idempotencyKey }. Queues a re-test of the checks that produced the finding (RS-VERIF-001). */
export async function POST(req: Request, ctx: RouteContext<"/v1/findings/[id]/verification-runs">) {
  const { id } = await ctx.params;
  return api(async (c) => {
    if (!req.headers.get("content-type")?.startsWith("application/json")) throw new AppError(422, "unsupported_media_type", "Send application/json.");
    return requestVerification(c, id, await req.json().catch(() => null));
  });
}
