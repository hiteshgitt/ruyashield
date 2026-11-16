import { getReport } from "@/server/reports/reports";
import { api } from "../../_lib/api";

/** The stored report file, byte-for-byte as generated; X-Report-SHA256 lets the recipient check it. Downloads are audited. */
export async function GET(_: Request, ctx: RouteContext<"/v1/reports/[id]">) {
  const { id } = await ctx.params;
  return api(async (c) => {
    const r = await getReport(c, id);
    return new Response(new Uint8Array(r.content), {
      headers: {
        "Content-Type": r.format === "pdf" ? "application/pdf" : "text/csv; charset=utf-8",
        "Content-Disposition": `attachment; filename="ruyashield-report-${r.createdAt.toISOString().slice(0, 10)}-${r.id.slice(0, 8)}.${r.format}"`,
        "X-Report-SHA256": r.sha256, "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store",
        "Content-Security-Policy": "default-src 'none'; sandbox",
      },
    });
  });
}
