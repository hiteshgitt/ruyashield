import { exportFixProof } from "@/server/verification/verification";
import { api } from "../../../_lib/api";

/** ?format=json|pdf. Refused when the record fails its integrity check; every export is audited (RS-FIXP-003). */
export async function GET(req: Request, ctx: RouteContext<"/v1/fixproofs/[id]/export">) {
  const { id } = await ctx.params;
  const format = new URL(req.url).searchParams.get("format") ?? "json";
  return api(async (c) => {
    const x = await exportFixProof(c, id, format);
    return new Response(new Uint8Array(Buffer.from(x.body)), {
      headers: {
        "Content-Type": x.contentType, "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store",
        "Content-Disposition": `attachment; filename="${x.filename}"`,
      },
    });
  });
}
