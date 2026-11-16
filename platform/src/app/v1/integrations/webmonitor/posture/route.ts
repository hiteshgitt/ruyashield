import { hostPosture, parseHostList } from "@/server/webmonitor/posture";
import { api } from "../../../_lib/api";

/**
 * GET /v1/integrations/webmonitor/posture?hosts=a.com,b.com — per-host security status for WebMonitor's
 * "Connect RuyaShield" integration. Use a read-only token with assets:read (and findings:read for counts).
 * With no hosts it returns only the org name, so WebMonitor can test a token when it is first connected.
 */
export async function GET(req: Request) {
  return api(async (c) => hostPosture(c, parseHostList(new URL(req.url).searchParams.get("hosts"))));
}
