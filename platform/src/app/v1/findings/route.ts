import { listFindings } from "@/server/findings/findings";
import { api } from "../_lib/api";

/** GET /v1/findings?assetId=&severity=&confidence=&status=&owner=&cursor=&limit= — usable with a findings:read token. */
export async function GET(req: Request) {
  const q = Object.fromEntries(new URL(req.url).searchParams);
  return api((c) => listFindings(c, q));
}
