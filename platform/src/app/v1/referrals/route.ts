import { listReferrals } from "@/server/webmonitor/referrals";
import { api } from "../_lib/api";

/** Claimed referrals in the active org (RS-WMON-002). */
export async function GET() {
  return api(async (c) => ({ referrals: await listReferrals(c) }));
}
