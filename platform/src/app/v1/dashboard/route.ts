import { securitySummary } from "@/server/reports/summary";
import { api } from "../_lib/api";

/** Security overview for the caller's scope; ?clientGroupId= narrows it to one client group. */
export async function GET(req: Request) {
  const clientGroupId = new URL(req.url).searchParams.get("clientGroupId");
  return api(async (c) => ({ summary: await securitySummary(c, { clientGroupId }) }));
}
