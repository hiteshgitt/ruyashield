import { generateReport, listReports } from "@/server/reports/reports";
import { api, jsonBody } from "../_lib/api";

/** Reports this caller may download (restricted members: only their own). */
export async function GET() {
  return api(async (c) => ({ reports: await listReports(c) }));
}

/** Generates and stores a report: {"format":"csv"|"pdf","clientGroupId"?:uuid}. Download it from /v1/reports/{id}. */
export async function POST(req: Request) {
  return api(async (c) => {
    const body = await jsonBody(req);
    return Response.json({ report: await generateReport(c, body) }, { status: 201, headers: { "Cache-Control": "no-store" } });
  });
}
