import { listNotifications, unreadCount } from "@/server/notifications/notifications";
import { api } from "../_lib/api";

/** The caller's own notifications in this organization; ?unread=1 returns only unread ones. */
export async function GET(req: Request) {
  const unreadOnly = new URL(req.url).searchParams.get("unread") === "1";
  return api(async (c) => ({ notifications: await listNotifications(c, { unreadOnly }), unread: await unreadCount(c) }));
}
