import { exportAuditEvents } from "@/server/audit/view";
import { AppError } from "@/server/errors";
import { api } from "../../_lib/api";

/**
 * GET /v1/audit/export?format=csv|json&action=&outcome=&actorId=&from=YYYY-MM-DD&to=YYYY-MM-DD
 * Needs audit.export with a recent MFA sign-in, so API tokens cannot use it. Cross-site requests are refused
 * so another site cannot make a signed-in admin's browser produce (and audit) an export.
 */
export async function GET(req: Request) {
  const site = req.headers.get("sec-fetch-site");
  if (site && site !== "same-origin" && site !== "none") {
    return Response.json({ error: { code: "forbidden" } }, { status: 403, headers: { "Cache-Control": "no-store" } });
  }
  const q = new URL(req.url).searchParams;
  const format = q.get("format") ?? "csv";
  return api(async (c) => {
    if (format !== "csv" && format !== "json") throw new AppError(422, "validation_failed", "Use csv or json.");
    const f = {
      action: q.get("action") || undefined, outcome: q.get("outcome") || undefined, actorId: q.get("actorId") || undefined,
      from: q.get("from") || undefined, to: q.get("to") || undefined,
    };
    const r = await exportAuditEvents(c, format, f);
    return new Response(r.body, {
      headers: {
        "Content-Type": format === "json" ? "application/json; charset=utf-8" : "text/csv; charset=utf-8",
        "Content-Disposition": `attachment; filename="ruyashield-audit-${new Date().toISOString().slice(0, 10)}.${format}"`,
        "X-Audit-Rows": String(r.rows), "X-Audit-Truncated": String(r.truncated),
        "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store", "Content-Security-Policy": "default-src 'none'; sandbox",
      },
    });
  });
}
