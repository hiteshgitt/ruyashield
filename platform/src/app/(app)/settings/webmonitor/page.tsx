import { Suspense } from "react";
import Link from "next/link";
import { grantFor } from "@/server/policy/matrix";
import { webmonitorConnections, webmonitorCoverage, webmonitorAddSiteUrl, webmonitorUrl, WATCH_FRESH_DAYS } from "@/server/webmonitor/watch";
import { createWebMonitorTokenAction, revokeTokenAction } from "../../actions";
import { ActionForm } from "../../_components/ActionForm";
import { StatusBadge } from "../../_components/StatusBadge";
import { fmt, pageOrg } from "../../_lib/page";
import { Empty, Loading, MetaChips, PageHeader } from "../../_components/Page";
import { TableWrap } from "../../_components/TableWrap";
import { WebMonitorTokenForm } from "./TokenForm";

export default function WebMonitorPage() {
  return (
    <>
      <PageHeader title="WebMonitor" lead={<>WebMonitor watches your sites for downtime, slow responses and site health issues. Connected, it shows each site&apos;s RuyaShield findings next to its uptime, alerts on new critical and high findings, and can ask RuyaShield to scan a site.</>} />
      <Suspense fallback={<Loading />}><WebMonitor /></Suspense>
    </>
  );
}

async function WebMonitor() {
  const c = await pageOrg("/settings/webmonitor");
  if (grantFor(c.principal.role, "token.manage") === "N") return <p className="notice warn">Only org admins can connect WebMonitor.</p>;
  const [connections, coverage] = await Promise.all([webmonitorConnections(c), webmonitorCoverage(c)]);
  const watched = coverage.assets.filter((a) => a.watched).length;
  const connectUrl = `${webmonitorUrl("/app")}?connect=ruyashield`;

  return (
    <div className="split">
      <div className="split-main stack">
        <MetaChips label="Summary">
          <li>{connections.length ? `Connected (${connections.length} token${connections.length === 1 ? "" : "s"})` : "Not connected"}</li>
          <li>{watched} of {coverage.assets.length} domain asset{coverage.assets.length === 1 ? "" : "s"} watched for uptime</li>
          {coverage.notInRuyaShield.length > 0 && <li>{coverage.notInRuyaShield.length} WebMonitor site{coverage.notInRuyaShield.length === 1 ? "" : "s"} not in RuyaShield</li>}
        </MetaChips>

        {connections.length > 0 && (
          <TableWrap className="card">
            <table><thead><tr><th>Token</th><th>Sites reported</th><th>Last checked in</th><th>Expires</th><th><span className="sr-only">Actions</span></th></tr></thead><tbody>
              {connections.map((t) => (
                <tr key={t.id}>
                  <td>{t.name} <code className="nowrap small">{t.prefix}…</code></td>
                  <td>{t.sites}</td>
                  <td className="small nowrap">{fmt(t.lastSeenAt)}</td>
                  <td className="small nowrap">{fmt(t.expiresAt)}</td>
                  <td>
                    <ActionForm action={revokeTokenAction} submit="Disconnect" variant="danger" className="row inline-form">
                      <input type="hidden" name="tokenId" value={t.id} />
                    </ActionForm>
                  </td>
                </tr>
              ))}
            </tbody></table>
          </TableWrap>
        )}

        <h2>Uptime coverage</h2>
        {coverage.assets.length === 0 ? <Empty>No domain assets yet. <Link href="/assets">Add one</Link>.</Empty> : (
          <TableWrap className="card">
            <table><thead><tr><th>Asset</th><th>Ownership</th><th>Uptime monitoring</th></tr></thead><tbody>
              {coverage.assets.map((a) => (
                <tr key={a.id}>
                  <td><Link href={`/assets/${a.id}`}>{a.name}</Link><div className="mono small muted">{a.host}</div></td>
                  <td><StatusBadge status={a.status} /></td>
                  <td>{a.watched
                    ? <span className="badge ok">Watched by WebMonitor</span>
                    : <a href={webmonitorAddSiteUrl(a.host)} target="_blank" rel="noopener noreferrer">Watch in WebMonitor →</a>}</td>
                </tr>
              ))}
            </tbody></table>
          </TableWrap>
        )}
        <p className="muted small">A site counts as watched when a connected WebMonitor account reported it in the last {WATCH_FRESH_DAYS} days. WebMonitor sends only the host names of the sites it monitors.</p>

        {coverage.notInRuyaShield.length > 0 && <>
          <h2>Monitored by WebMonitor, not scanned by RuyaShield</h2>
          <TableWrap className="card">
            <table><thead><tr><th>Site</th><th><span className="sr-only">Actions</span></th></tr></thead><tbody>
              {coverage.notInRuyaShield.map((h) => (
                <tr key={h}><td className="mono">{h}</td><td><Link href={`/assets?host=${encodeURIComponent(h)}`}>Add as asset →</Link></td></tr>
              ))}
            </tbody></table>
          </TableWrap>
        </>}
      </div>

      <aside className="split-side">
        <div className="card stack">
          <h2>{connections.length ? "Connect another account" : "Connect WebMonitor"}</h2>
          <ol className="steps small">
            <li>Create a read-only token here. It has only the <code>assets:read</code> and <code>findings:read</code> scopes and lasts a year.</li>
            <li>In WebMonitor, open the account menu → <strong>RuyaShield</strong> and paste it.</li>
          </ol>
          <WebMonitorTokenForm action={createWebMonitorTokenAction} connectUrl={connectUrl} />
          <p className="muted small">The token can never start a scan, approve or change anything. Scan requests from WebMonitor arrive as referrals that a member must accept here.</p>
        </div>
        <div className="card stack">
          <h2>No WebMonitor account?</h2>
          <p className="small">Uptime and response time checked every minute, downtime incidents, SSL and plugin health and SEO checks, with alerts on the web and the Android app. Works with WordPress, Laravel, Next.js and PHP sites. Free to start.</p>
          <a className="button secondary" href={webmonitorUrl("/")} target="_blank" rel="noopener noreferrer">Try WebMonitor →</a>
        </div>
      </aside>
    </div>
  );
}
