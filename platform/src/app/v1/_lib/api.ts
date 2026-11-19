import { NextResponse } from "next/server";
import { unstable_rethrow } from "next/navigation";
import { getBearerContext, getContext } from "@/server/context";
import { AppError, isAppError } from "@/server/errors";
import { log } from "@/server/log";

const NO_STORE = { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" };

/** Runs a handler with the caller's org context and maps AppErrors to JSON error bodies. */
export async function api(fn: (c: NonNullable<Awaited<ReturnType<typeof getContext>>>["ctx"] & object) => Promise<Response | unknown>) {
  try {
    // A bearer header is authoritative: a bad token is a 401 even if a cookie session is also present.
    const bearer = await getBearerContext();
    if (bearer === null) return NextResponse.json({ error: { code: "invalid_token" } }, { status: 401, headers: { ...NO_STORE, "WWW-Authenticate": "Bearer" } });
    let ctx = bearer;
    if (!ctx) {
      const c = await getContext();
      if (!c) return NextResponse.json({ error: { code: "unauthenticated" } }, { status: 401, headers: NO_STORE });
      if (!c.ctx) return NextResponse.json({ error: { code: "no_org" } }, { status: 403, headers: NO_STORE });
      ctx = c.ctx;
    }
    const out = await fn(ctx);
    return out instanceof Response ? out : NextResponse.json(out, { headers: NO_STORE });
  } catch (e) {
    // Next's own control flow (prerender bail-out, redirects) must reach Next, not become a 500 or an error log.
    unstable_rethrow(e);
    if (isAppError(e)) return NextResponse.json({ error: { code: e.code, message: e.message } }, { status: e.status, headers: NO_STORE });
    log.error("api.error", { error: e instanceof Error ? e.message : String(e) });
    return NextResponse.json({ error: { code: "internal" } }, { status: 500, headers: NO_STORE });
  }
}

/** Parses a JSON request body; anything else is refused before it reaches a handler. */
export async function jsonBody(req: Request): Promise<unknown> {
  if (!req.headers.get("content-type")?.startsWith("application/json")) throw new AppError(422, "unsupported_media_type", "Send application/json.");
  return req.json().catch(() => null);
}
