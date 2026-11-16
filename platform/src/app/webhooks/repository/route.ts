import { NextResponse } from "next/server";
import { acceptWebhook } from "@/server/remediation/integrations";
import { observeOpenChanges } from "@/server/remediation/approvals";
import { log } from "@/server/log";

const MAX_BODY = 64 * 1024;
const NO_STORE = { "Cache-Control": "no-store" };

/**
 * Signed, replay-protected repository notification. It is only a hint to look: the change state is re-read from the
 * repository itself, so a forged or reordered event cannot mark anything merged.
 */
export async function POST(req: Request) {
  const len = Number(req.headers.get("content-length") ?? 0);
  if (len > MAX_BODY) return NextResponse.json({ error: { code: "too_large" } }, { status: 413, headers: NO_STORE });
  const body = await req.text();
  if (body.length > MAX_BODY) return NextResponse.json({ error: { code: "too_large" } }, { status: 413, headers: NO_STORE });
  const h = req.headers;
  try {
    const r = await acceptWebhook({
      integration: h.get("x-ruya-integration"), delivery: h.get("x-ruya-delivery"), event: h.get("x-ruya-event"),
      timestamp: h.get("x-ruya-timestamp"), signature: h.get("x-ruya-signature"),
    }, body);
    if (r.code === "accepted") {
      const observed = await observeOpenChanges({ orgId: r.orgId, integrationId: r.integrationId });
      return NextResponse.json({ status: "accepted", observed }, { status: 202, headers: NO_STORE });
    }
    return NextResponse.json(r.status < 300 ? { status: r.code } : { error: { code: r.code } }, { status: r.status, headers: NO_STORE });
  } catch (e) {
    log.error("webhook.error", { error: e instanceof Error ? e.message : String(e) });
    return NextResponse.json({ error: { code: "internal" } }, { status: 500, headers: NO_STORE });
  }
}
