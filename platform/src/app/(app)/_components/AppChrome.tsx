import Link from "next/link";
import { getContext } from "@/server/context";
import { grantFor } from "@/server/policy/matrix";
import { unreadCount } from "@/server/notifications/notifications";
import { listUserOrgs } from "@/server/orgs/orgs";
import { logoutAction, selectOrgAction } from "../actions";
import { Icon } from "./Icon";
import { NavList, type NavGroup } from "./NavList";

const roleLabel = (r: string) => r.replace("_", " ");

/**
 * Sidebar + top bar. Rendered as siblings of <main> so the frame grid places them; one context load per request.
 * Navigation entries follow the same permission checks as before; the server still authorizes every page and action.
 */
export async function AppChrome() {
  const c = await getContext();
  if (!c) {
    return (
      <header className="topbar">
        <Link href="/" className="brand">RuyaShield</Link>
        <div className="topbar-end"><Link href="/auth/login" className="button secondary">Sign in</Link></div>
      </header>
    );
  }

  const role = c.ctx?.principal.role;
  const breakGlass = c.ctx?.principal.breakGlassId;
  const can = (perm: Parameters<typeof grantFor>[1]) => !!role && grantFor(role, perm) !== "N";
  const [unread, orgs] = await Promise.all([
    c.ctx && !breakGlass ? unreadCount(c.ctx) : Promise.resolve(0),
    listUserOrgs(c.session.userId),
  ]);

  const groups: NavGroup[] = c.ctx ? [
    { label: "Security", items: [
      ...(can("dashboard.view") ? [{ href: "/dashboard", label: "Overview", icon: "overview" as const }] : []),
      { href: "/assets", label: "Assets", icon: "assets" as const },
      { href: "/assessments", label: "Assessments", icon: "assessments" as const },
      ...(can("finding.view") ? [{ href: "/findings", label: "Findings", icon: "findings" as const }] : []),
      ...(can("dashboard.view") ? [{ href: "/attacks", label: "Attacks", icon: "radar" as const }] : []),
      ...(can("remediation.request_approval") || can("approval.decide") ? [{ href: "/approvals", label: "Approvals", icon: "approvals" as const }] : []),
      ...(can("report.generate") ? [{ href: "/reports", label: "Reports", icon: "reports" as const }] : []),
    ] },
    { label: "Administration", items: [
      ...(can("members.manage") ? [{ href: "/settings/members", label: "Members", icon: "members" as const }] : []),
      ...(can("integration.manage") ? [{ href: "/settings/integrations", label: "Repositories", icon: "repos" as const }] : []),
      ...(can("token.manage") ? [{ href: "/settings/tokens", label: "API tokens", icon: "tokens" as const }] : []),
      ...(can("retention.manage") ? [{ href: "/settings/organization", label: "Organization", icon: "org" as const }] : []),
      ...(can("killswitch.manage") ? [{ href: "/settings/safety", label: "Safety", icon: "safety" as const }] : []),
      ...(can("audit.view") ? [{ href: "/audit", label: "Audit log", icon: "audit" as const }] : []),
    ] },
  ].filter((g) => g.items.length > 0) : [];

  const name = c.session.displayName || c.session.email;
  const initials = name.split(/[\s@.]+/).filter(Boolean).slice(0, 2).map((p) => p[0]!.toUpperCase()).join("");

  return (
    <>
      {groups.length > 0 && (
        <aside className="sidebar" aria-label="Main">
          <Link href="/" className="brand">RuyaShield</Link>
          <nav aria-label="Main navigation"><NavList groups={groups} /></nav>
        </aside>
      )}

      <header className="topbar">
        {groups.length > 0 && (
          <details className="menu navmenu">
            <summary aria-label="Open navigation"><Icon name="menu" /><span>Menu</span></summary>
            <div className="menu-panel">
              <nav aria-label="Main navigation (mobile)"><NavList groups={groups} /></nav>
            </div>
          </details>
        )}
        <Link href="/" className="brand">RuyaShield</Link>

        <details className="menu orgmenu">
          <summary>
            <span className="org-mark" aria-hidden="true">{(c.ctx?.org.name ?? "?").slice(0, 1).toUpperCase()}</span>
            <span className="org-text">
              <span className="org-name">{c.ctx ? c.ctx.org.name : "Choose organization"}</span>
              {role && <span className="org-role">{breakGlass ? "Support access · read-only" : roleLabel(role)}</span>}
            </span>
            <Icon name="chevron" className="chev" />
          </summary>
          <div className="menu-panel">
            <p className="menu-label">Your organizations</p>
            {orgs.length === 0 && <p className="muted small">You are not a member of any organization yet.</p>}
            <ul className="menu-list">
              {orgs.map((o) => (
                <li key={o.id}>
                  {c.ctx?.org.id === o.id ? (
                    <span className="menu-item current" aria-current="true">
                      <span className="org-mark" aria-hidden="true">{o.name.slice(0, 1).toUpperCase()}</span>
                      <span className="org-text"><span className="org-name">{o.name}</span><span className="org-role">{roleLabel(o.role)}</span></span>
                      <span className="badge ok">Active</span>
                    </span>
                  ) : (
                    <form action={selectOrgAction}>
                      <input type="hidden" name="orgId" value={o.id} />
                      <button type="submit" className="menu-item">
                        <span className="org-mark" aria-hidden="true">{o.name.slice(0, 1).toUpperCase()}</span>
                        <span className="org-text"><span className="org-name">{o.name}</span><span className="org-role">{roleLabel(o.role)}</span></span>
                      </button>
                    </form>
                  )}
                </li>
              ))}
            </ul>
            <Link href="/orgs" className="menu-item menu-footer"><Icon name="plus" />Manage or create organizations</Link>
          </div>
        </details>

        <div className="topbar-end">
          {c.ctx && !breakGlass && (
            <Link href="/notifications" className="iconbtn" aria-label={unread ? `Notifications, ${unread} unread` : "Notifications, none unread"} title="Notifications">
              <Icon name="bell" />
              {unread > 0 && <span className="count" aria-hidden="true">{unread > 99 ? "99+" : unread}</span>}
            </Link>
          )}

          <details className="menu usermenu">
            <summary>
              <span className="avatar" aria-hidden="true">{initials || "?"}</span>
              <span className="sr-only">Account: </span>
              <span className="user-name">{name}</span>
              {!c.session.mfa && <span className="badge warn user-mfa">No MFA</span>}
              <Icon name="chevron" className="chev" />
            </summary>
            <div className="menu-panel align-end">
              <p className="user-head"><strong>{c.session.displayName || "Signed in"}</strong><span className="muted small">{c.session.email}</span></p>
              <p className="small">{c.session.mfa
                ? <span className="badge ok">MFA on</span>
                : <span className="badge warn">No MFA on this session</span>}</p>
              <form action={logoutAction}><button type="submit" className="menu-item"><Icon name="logout" />Sign out</button></form>
            </div>
          </details>
        </div>

        {breakGlass && (
          <p className="notice bad" role="status">Operator support access (read-only) to {c.ctx!.org.name}. This session is audited and the organization&apos;s admins were notified. <Link href="/operator">End access</Link></p>
        )}
      </header>
    </>
  );
}
