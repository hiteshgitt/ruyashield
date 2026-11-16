import { markRead } from "@/server/notifications/notifications";
import { AppError } from "@/server/errors";
import { api, jsonBody } from "../../_lib/api";

/** Marks {"id": uuid} or {"id": "all"} as read. */
export async function POST(req: Request) {
  return api(async (c) => {
    const body = (await jsonBody(req)) as { id?: unknown } | null;
    if (typeof body?.id !== "string") throw new AppError(422, "validation_failed", "Send an id or \"all\".");
    await markRead(c, body.id);
    return { ok: true };
  });
}
