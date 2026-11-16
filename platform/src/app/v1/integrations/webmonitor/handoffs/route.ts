import { NextResponse } from "next/server";
import { MAX_HANDOFF_BYTES, receiveHandoff } from "@/server/webmonitor/referrals";
import { log } from "@/server/log";

const NO_STORE = { "Cache-Control": "no-store" };

/**
 * Signed WebMonitor referral handoff (RS-WMON-001; provisional adapter, D-14). Stores minimal context and returns a
 * single-use link for the person to review. It never starts an assessment: consent and asset verification come first.
 */
export async function POST(req: Request) {
  const len = Number(req.headers.get("content-length") ?? 0);
  if (len > MAX_HANDOFF_BYTES) return NextResponse.json({ error: { code: "too_large" } }, { status: 413, headers: NO_STORE });
  const body = await req.text();
  if (body.length > MAX_HANDOFF_BYTES) return NextResponse.json({ error: { code: "too_large" } }, { status: 413, headers: NO_STORE });
  try {
    const r = await receiveHandoff({ timestamp: req.headers.get("x-webmonitor-timestamp"), signature: req.headers.get("x-webmonitor-signature") }, body);
    return NextResponse.json(r.body, { status: r.status, headers: NO_STORE });
  } catch (e) {
    log.error("webmonitor.handoff_error", { error: e instanceof Error ? e.message : String(e) });
    return NextResponse.json({ error: { code: "internal" } }, { status: 500, headers: NO_STORE });
  }
}
