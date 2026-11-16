import { getRawEvidence } from "@/server/findings/findings";
import { api } from "../../../_lib/api";

/** Stored evidence as an attachment. Requires evidence.download_raw; every download is audited. */
export async function GET(_: Request, ctx: RouteContext<"/v1/evidence/[id]/raw">) {
  const { id } = await ctx.params;
  return api(async (c) => {
    const e = await getRawEvidence(c, id);
    // Always text/plain: captured content is untrusted and must never render as HTML in our origin.
    return new Response(e.body, {
      headers: {
        "Content-Type": "text/plain; charset=utf-8", "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store",
        "Content-Disposition": `attachment; filename="evidence-${e.id}.txt"`, "X-Evidence-SHA256": e.sha256,
        "Content-Security-Policy": "default-src 'none'; sandbox",
      },
    });
  });
}
