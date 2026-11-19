import { NextResponse } from "next/server";
import { MAX_FILE_REPORT_BYTES, receiveFileReport } from "@/server/webmonitor/files";
import { log } from "@/server/log";

const NO_STORE = { "Cache-Control": "no-store" };

/**
 * Signed WebMonitor file-scan report: suspicious files found by the read-only in-site scanner (same HMAC as the
 * referral handoff). Stored by host; the webmonitor.files check uses it only for verified assets.
 */
export async function POST(req: Request) {
  const len = Number(req.headers.get("content-length") ?? 0);
  if (len > MAX_FILE_REPORT_BYTES) return NextResponse.json({ error: { code: "too_large" } }, { status: 413, headers: NO_STORE });
  const body = await req.text();
  if (body.length > MAX_FILE_REPORT_BYTES) return NextResponse.json({ error: { code: "too_large" } }, { status: 413, headers: NO_STORE });
  try {
    const r = await receiveFileReport({ timestamp: req.headers.get("x-webmonitor-timestamp"), signature: req.headers.get("x-webmonitor-signature") }, body);
    return NextResponse.json(r.body, { status: r.status, headers: NO_STORE });
  } catch (e) {
    log.error("webmonitor.file_report_error", { error: e instanceof Error ? e.message : String(e) });
    return NextResponse.json({ error: { code: "internal" } }, { status: 500, headers: NO_STORE });
  }
}
