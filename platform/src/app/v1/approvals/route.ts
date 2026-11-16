import { listApprovals } from "@/server/remediation/approvals";
import { api } from "../_lib/api";

/** Approvals in this organization; ?state=pending narrows the list. */
export async function GET(req: Request) {
  const state = new URL(req.url).searchParams.get("state") ?? undefined;
  return api(async (c) => ({ approvals: await listApprovals(c, { state }) }));
}
