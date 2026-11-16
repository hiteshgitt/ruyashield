import { createApiToken, listApiTokens } from "@/server/tokens/tokens";
import { api, jsonBody } from "../_lib/api";

/** Token management needs token.manage, which no API token carries; a token cannot mint or list tokens. */
export async function GET() {
  return api(async (c) => ({ tokens: await listApiTokens(c) }));
}

/** POST {name, scopes[], days}; the secret is in this response only. */
export async function POST(req: Request) {
  return api(async (c) => {
    const r = await createApiToken(c, await jsonBody(req));
    return Response.json(r, { status: 201, headers: { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" } });
  });
}
