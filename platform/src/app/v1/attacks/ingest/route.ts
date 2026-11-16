import { NextResponse } from "next/server";
import { ingest } from "@/server/attacks/attacks";
import { MAX_LINES_PER_BATCH } from "@/server/attacks/logparse";
import { isAppError } from "@/server/errors";
import { log } from "@/server/log";

/**
 * Log-agent ingest: POST text/plain (one access-log line per line), Authorization: Bearer rs_…
 * The ingest token is not a user API token and grants nothing else. Bodies are capped at 1 MB / 5000 lines.
 * Only suspicious lines are kept (path without query string); everything else is discarded.
 */
const NO_STORE = { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" };
const MAX_BYTES = 1024 * 1024;
const err = (status: number, code: string, message?: string) => NextResponse.json({ error: { code, message } }, { status, headers: NO_STORE });

export async function POST(req: Request) {
  const m = /^Bearer (rs_[A-Za-z0-9_-]{20,100})$/.exec(req.headers.get("authorization") ?? "");
  if (!m) return NextResponse.json({ error: { code: "invalid_token" } }, { status: 401, headers: { ...NO_STORE, "WWW-Authenticate": "Bearer" } });
  if (!(req.headers.get("content-type") ?? "").startsWith("text/plain")) return err(415, "unsupported_media_type", "Send text/plain, one log line per line.");
  const len = Number(req.headers.get("content-length") ?? "0");
  if (len > MAX_BYTES) return err(413, "too_large", "Send at most 1 MB per batch.");
  let text: string;
  try {
    const buf = await req.arrayBuffer();
    if (buf.byteLength > MAX_BYTES) return err(413, "too_large", "Send at most 1 MB per batch.");
    text = new TextDecoder("utf-8", { fatal: false }).decode(buf);
  } catch { return err(400, "bad_body"); }
  const lines = text.split(/\r?\n/);
  if (lines.length > MAX_LINES_PER_BATCH + 1) return err(413, "too_many_lines", `Send at most ${MAX_LINES_PER_BATCH} lines per batch.`);
  try {
    return NextResponse.json(await ingest(m[1], lines), { status: 202, headers: NO_STORE });
  } catch (e) {
    if (isAppError(e)) return err(e.status, e.code, e.message);
    log.error("attacks.ingest_error", { error: e instanceof Error ? e.message : String(e) });
    return err(500, "internal");
  }
}
