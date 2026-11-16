import { createCloudflareSource, createLogAgentSource, listSources } from "@/server/attacks/attacks";
import { AppError } from "@/server/errors";
import { api, jsonBody } from "../../_lib/api";

const NO_STORE = { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" };

export async function GET() {
  return api(async (c) => ({ sources: await listSources(c) }));
}

/** POST {kind:"cloudflare", assetId, name, zoneId, token} or {kind:"log_agent", assetId, name}. An agent token is in this response only. */
export async function POST(req: Request) {
  return api(async (c) => {
    const body = (await jsonBody(req)) as { kind?: unknown } | null;
    if (body?.kind === "cloudflare") return Response.json(await createCloudflareSource(c, body), { status: 201, headers: NO_STORE });
    if (body?.kind === "log_agent") return Response.json(await createLogAgentSource(c, body), { status: 201, headers: NO_STORE });
    throw new AppError(422, "invalid_request", "kind must be cloudflare or log_agent.");
  });
}
