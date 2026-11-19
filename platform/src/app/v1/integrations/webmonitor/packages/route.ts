import { NextResponse } from "next/server";
import { MAX_PACKAGE_REPORT_BYTES, receivePackageReport } from "@/server/webmonitor/packages";
import { log } from "@/server/log";

const NO_STORE = { "Cache-Control": "no-store" };

/**
 * Signed WebMonitor package report: vulnerable npm / Composer packages installed on one host (same HMAC as the
 * referral handoff). Stored by host; the webmonitor.packages check uses it only for verified assets.
 */
export async function POST(req: Request) {
  const len = Number(req.headers.get("content-length") ?? 0);
  if (len > MAX_PACKAGE_REPORT_BYTES) return NextResponse.json({ error: { code: "too_large" } }, { status: 413, headers: NO_STORE });
  const body = await req.text();
  if (body.length > MAX_PACKAGE_REPORT_BYTES) return NextResponse.json({ error: { code: "too_large" } }, { status: 413, headers: NO_STORE });
  try {
    const r = await receivePackageReport({ timestamp: req.headers.get("x-webmonitor-timestamp"), signature: req.headers.get("x-webmonitor-signature") }, body);
    return NextResponse.json(r.body, { status: r.status, headers: NO_STORE });
  } catch (e) {
    log.error("webmonitor.package_report_error", { error: e instanceof Error ? e.message : String(e) });
    return NextResponse.json({ error: { code: "internal" } }, { status: 500, headers: NO_STORE });
  }
}
