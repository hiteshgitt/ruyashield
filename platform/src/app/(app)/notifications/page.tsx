import { Suspense } from "react";
import Link from "next/link";
import { getPrefs, listNotifications } from "@/server/notifications/notifications";
import { isAppError } from "@/server/errors";
import { ActionForm } from "../_components/ActionForm";
import { markReadAction, setNotificationPrefAction } from "../actions";
import { messageFor } from "../_lib/messages";
import { fmt, pageOrg } from "../_lib/page";
import { Empty, Loading, PageHeader, SectionHead } from "../_components/Page";

/** Only same-origin paths written by our own code are linked; anything else is shown as text. */
const safeLink = (l: string | null) => (l && l.startsWith("/") && !l.startsWith("//") ? l : null);

export default function NotificationsPage() {
  return (
    <>
      <PageHeader title="Notifications" />
      <Suspense fallback={<Loading />}><Notifications /></Suspense>
    </>
  );
}

async function Notifications() {
  const c = await pageOrg("/notifications");
  let items, prefs;
  try {
    [items, prefs] = await Promise.all([listNotifications(c), getPrefs(c)]);
  } catch (e) {
    if (isAppError(e) && e.status < 500) return <div className="notice bad">{messageFor(e.code, e.message)}</div>;
    throw e;
  }
  const unread = items.filter((n) => !n.readAt).length;
  return (
    <>
      <div className="toolbar card notif-bar">
        <p className="small"><strong>{unread}</strong> unread · {items.length} total</p>
        {unread > 0 && <div className="toolbar-end"><ActionForm action={markReadAction} submit="Mark all as read" variant="secondary" className="row inline-form"><input type="hidden" name="id" value="all" /></ActionForm></div>}
      </div>
      {items.length === 0 ? <Empty>No notifications.</Empty> : (
        <ul className="notif-list card">
          {items.map((n) => {
            const href = safeLink(n.link);
            return (
              <li key={n.id} className={n.readAt ? "read" : "unread"}>
                <span className="notif-dot" aria-hidden="true" />
                <div className="notif-body">
                  <span className="notif-title">{href ? <Link href={href}>{n.title}</Link> : n.title}</span>
                  <span className="muted small mono">{fmt(n.createdAt)} · {n.readAt ? "Read" : <strong>Unread</strong>}</span>
                </div>
                {!n.readAt && <ActionForm action={markReadAction} submit="Mark read" variant="secondary" className="row inline-form"><input type="hidden" name="id" value={n.id} /></ActionForm>}
              </li>
            );
          })}
        </ul>
      )}

      <SectionHead title="Delivery preferences" />
      <p className="muted small">Security-critical notifications (failed verification, regressions, risk expiry, kill switch, operator support access, organization deletion) are always sent in-app and by email.</p>
      <ul className="pref-list card">
        {prefs.map((p) => (
          <li key={p.kind}>
            <span className="pref-kind">{p.label}{p.securityCritical && <span className="badge warn">always on</span>}</span>
            {p.securityCritical ? <span className="small muted">In-app and email</span> : (
              <ActionForm action={setNotificationPrefAction} submit="Save" variant="secondary" className="row inline-form pref-form">
                <input type="hidden" name="kind" value={p.kind} />
                <label className="check small"><input type="checkbox" name="inApp" defaultChecked={p.inApp} /> In-app</label>
                <label className="check small"><input type="checkbox" name="email" defaultChecked={p.email} /> Email</label>
              </ActionForm>
            )}
          </li>
        ))}
      </ul>
    </>
  );
}
