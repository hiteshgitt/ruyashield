import { getStats } from "@/server/attacks/attacks";
import { api } from "../_lib/api";

/** GET ?asset=<uuid>&days=1|7|30|90. coverage "none" means no active source: zero events is "no data", not "no attacks". */
export async function GET(req: Request) {
  const u = new URL(req.url);
  return api(async (c) => getStats(c, { assetId: u.searchParams.get("asset"), days: Number(u.searchParams.get("days") ?? 7) }));
}
