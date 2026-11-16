import { createIntegration, listIntegrations } from "@/server/remediation/integrations";
import { api, jsonBody } from "../../_lib/api";

export async function GET() {
  return api(async (c) => ({ integrations: await listIntegrations(c) }));
}

/** Body: { name, externalId, defaultBranch?, testCommands? }. Requires step-up (RS-REMED-004). */
export async function POST(req: Request) {
  return api(async (c) => createIntegration(c, await jsonBody(req)));
}
