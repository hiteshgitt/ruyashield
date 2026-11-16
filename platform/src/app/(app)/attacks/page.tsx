import { Suspense } from "react";
import { getStats, listSources, STATS_DAYS, type AttackStats, type SourceView } from "@/server/attacks/attacks";
import { listAssets } from "@/server/assets/assets";
import { isAppError } from "@/server/errors";
import { grantFor } from "@/server/policy/matrix";
import { ActionForm } from "../_components/ActionForm";
import { StatCard } from "../_components/Charts";
import { Empty, Loading, PageHeader, ProGate } from "../_components/Page";
import { isProOrg } from "@/server/policy/policy";
import { StatusBadge } from "../_components/StatusBadge";
import { TableWrap } from "../_components/TableWrap";
import { createCloudflareSourceAction, createLogAgentSourceAction, disableAttackSourceAction } from "../actions";
import { messageFor } from "../_lib/messages";
import { fmt, pageOrg } from "../_lib/page";

export default function AttacksPage({ searchParams }: PageProps<"/attacks">) {
  return (
    <>
      <PageHeader title="Attacks" lead="Where hostile traffic against your verified websites comes from: IP, country, network and attack type. Read-only and passive — RuyaShield never sends anything back to these addresses." />
      <Suspense fallback={<Loading />}><Attacks searchParams={searchParams} /></Suspense>
    </>
  );
}

const SOURCE_ERRORS: Record<string, string> = {
  cloudflare_not_authorized: "Cloudflare rejected the token. It needs Zone → Analytics → Read on this zone.",
  cloudflare_zone_not_found: "Cloudflare could not find this zone ID for the token.",
  cloudflare_zone_not_visible: "This token cannot see that zone. Check the Zone ID (not the Account ID) and that the token is scoped to this zone.",
  cloudflare_rate_limited: "Cloudflare rate-limited the request; it will retry automatically.",
  cloudflare_unreachable: "Cloudflare could not be reached; it will retry automatically.",
  cloudflare_malformed_response: "Cloudflare returned an unexpected response.",
  cloudflare_response_too_large: "Cloudflare returned too much data in one poll.",
  secrets_key_not_configured: "RUYA_SECRETS_KEY is missing or changed on the server, so the token cannot be decrypted.",
  asset_not_verified: "The asset is no longer verified, so collection is paused.",
};
const sourceError = (e: string) => SOURCE_ERRORS[e] ?? e.replace(/_/g, " ");

let regionNames: Intl.DisplayNames | null = null;
function countryName(cc: string | null): string {
  if (!cc) return "Unknown";
  try { regionNames ??= new Intl.DisplayNames(["en"], { type: "region" }); return regionNames.of(cc) ?? cc; } catch { return cc; }
}

async function Attacks({ searchParams }: { searchParams: PageProps<"/attacks">["searchParams"] }) {
  const sp = await searchParams;
  const assetId = typeof sp.assetId === "string" ? sp.assetId : "";
  const daysRaw = Number(typeof sp.days === "string" ? sp.days : 7);
  const days = (STATS_DAYS as readonly number[]).includes(daysRaw) ? daysRaw : 7;
  const c = await pageOrg("/attacks");
  if (!isProOrg(c.org)) {
    return (
      <ProGate title="Attack monitoring" rows={7}>
        Connect Cloudflare or a log agent and see where hostile traffic against your verified sites comes from: IP, country, network and attack type, with spike alerts.
      </ProGate>
    );
  }
  const canManage = grantFor(c.principal.role, "integration.manage") !== "N";

  let stats: AttackStats, sources: SourceView[];
  try {
    [stats, sources] = await Promise.all([getStats(c, { assetId: assetId || null, days }), listSources(c)]);
  } catch (e) {
    if (isAppError(e) && e.status < 500) return <div className="notice bad">{messageFor(e.code, e.message)}</div>;
    throw e;
  }
  let domains: { id: string; host: string }[] = [];
  try {
    domains = (await listAssets(c)).filter((a) => a.kind === "domain" && a.status === "verified").map((a) => ({ id: a.id, host: a.host }));
  } catch (e) {
    if (!(isAppError(e) && e.status < 500)) throw e;
  }
  const hostFilter = new Map(sources.map((s) => [s.assetId, s.assetHost]));
  for (const d of domains) hostFilter.set(d.id, d.host);
  const appUrl = (process.env.APP_URL ?? "http://localhost:3200").replace(/\/$/, "");
  const empty = stats.total === 0;

  return (
    <div className="split">
      <div className="split-main stack">
        <form method="get" className="card toolbar small">
          <label>Website
            <select name="assetId" defaultValue={assetId}>
              <option value="">All monitored websites</option>
              {[...hostFilter].map(([id, host]) => <option key={id} value={id}>{host}</option>)}
            </select>
          </label>
          <label>Period
            <select name="days" defaultValue={String(days)}>
              {STATS_DAYS.map((d) => <option key={d} value={d}>{d === 1 ? "Last 24 hours" : `Last ${d} days`}</option>)}
            </select>
          </label>
          <button type="submit" className="secondary">Apply</button>
        </form>

        <Coverage stats={stats} />

        {(!stats.geoip.country || !stats.geoip.asn) && (
          <div className="notice warn small">
            GeoIP database {!stats.geoip.country && !stats.geoip.asn ? "is" : "is partly"} not configured on this server, so
            {!stats.geoip.country ? " country" : ""}{!stats.geoip.country && !stats.geoip.asn ? " and" : ""}{!stats.geoip.asn ? " network (ASN)" : ""} for
            log-agent events shows as <strong>Unknown</strong>. Cloudflare events carry their own country and network.
            See <em>GeoIP setup</em> on the right.
          </div>
        )}

        <div className="stats">
          <StatCard icon="radar" label="Suspicious requests" value={stats.coverage === "none" && empty ? "—" : stats.total} sub={`last ${days === 1 ? "24 hours" : `${days} days`}`} tone={stats.total > 0 ? "bad" : undefined} />
          <StatCard icon="target" label="Unique source IPs" value={stats.coverage === "none" && empty ? "—" : stats.uniqueIps} />
          <StatCard icon="org" label="Countries" value={stats.coverage === "none" && empty ? "—" : stats.countries} sub={stats.geoip.country ? undefined : "GeoIP not configured"} />
          <StatCard icon="shield" label="Blocked or challenged" value={stats.coverage === "none" && empty ? "—" : stats.blocked} sub="by your firewall" tone={stats.blocked > 0 ? "ok" : undefined} />
        </div>

        {!empty && (
          <>
            <section className="card">
              <h2>Suspicious requests per day</h2>
              <Timeline points={stats.timeline} />
              <p className="muted small">Days in UTC. Hover a bar for the exact count.</p>
            </section>

            <div className="grid2">
              <TopList title="Top countries" head="Country" rows={stats.byCountry.map((r) => ({ key: r.country ?? "?", label: <>{countryName(r.country)}{r.country && <span className="muted small"> {r.country}</span>}</>, n: r.n }))} />
              <TopList title="Attack types" head="Type" rows={stats.byType.map((r) => ({ key: r.type, label: r.label, n: r.n }))} />
              <TopList title="Top source IPs" head="IP" rows={stats.byIp.map((r) => ({
                key: r.ip, n: r.n,
                label: <><code>{r.ip}</code><div className="muted small">{countryName(r.country)}{r.asOrg ? ` · ${r.asOrg}` : ""} · last {fmt(r.last)}</div></>,
              }))} />
              <TopList title="Top networks (ASN)" head="Network" rows={stats.byAsn.map((r) => ({
                key: String(r.asn ?? "?"), n: r.n,
                label: r.asn ? <>{r.asOrg ?? "Unnamed network"} <span className="muted small">AS{r.asn}</span></> : "Unknown",
              }))} />
            </div>

            <section>
              <h2>Recent events</h2>
              <TableWrap className="card">
                <table><thead><tr><th>Time</th><th>Source</th><th>Type</th><th>Request</th><th>Outcome</th></tr></thead><tbody>
                  {stats.recent.map((r, i) => (
                    <tr key={i}>
                      <td className="nowrap small">{fmt(r.occurredAt)}</td>
                      <td><code>{r.ip}</code><div className="muted small">{countryName(r.country)}{r.asOrg ? ` · ${r.asOrg}` : ""}</div></td>
                      <td className="small">{typeLabelFor(stats, r.attackType)}</td>
                      <td className="small"><span className="muted">{r.assetHost}</span><div><code>{r.method ?? ""} {r.path ?? ""}</code></div></td>
                      <td className="small nowrap">{r.action.replace(/_/g, " ")}{r.statusCode !== null && <span className="muted"> · {r.statusCode}</span>}</td>
                    </tr>
                  ))}
                </tbody></table>
              </TableWrap>
              <p className="muted small">Paths are stored without query strings. Only requests that match an attack signature or a firewall action are kept, for 90 days.</p>
            </section>
          </>
        )}

        <section>
          <h2>Data sources</h2>
          {sources.length === 0 ? <Empty>No sources connected. {canManage ? "Connect Cloudflare or install the log agent (right)." : "Ask an org admin or security lead to connect one."}</Empty> : (
            <TableWrap className="card">
              <table><thead><tr><th>Name</th><th>Website</th><th>Kind</th><th>Status</th><th>Last activity</th>{canManage && <th><span className="sr-only">Actions</span></th>}</tr></thead><tbody>
                {sources.map((s) => (
                  <tr key={s.id}>
                    <td>{s.name}<div className="muted small nowrap">added {fmt(s.createdAt)}</div></td>
                    <td>{s.assetHost}</td>
                    <td className="small">{s.kind === "cloudflare" ? <>Cloudflare<div className="muted mono">{s.zoneId}</div></> : <>Log agent<div className="muted mono">{s.prefix}…</div></>}</td>
                    <td><StatusBadge status={s.status} />{s.lastError && s.status !== "disabled" && <div className="small" style={{ color: "var(--bad)" }}>{sourceError(s.lastError)}</div>}</td>
                    <td className="small nowrap">{s.kind === "cloudflare" && <div>polled {fmt(s.lastPolledAt)}</div>}<div className="muted">last event {fmt(s.lastEventAt)}</div></td>
                    {canManage && <td>{s.status !== "disabled" && (
                      <ActionForm action={disableAttackSourceAction} submit="Disable" variant="danger" className="row inline-form">
                        <input type="hidden" name="sourceId" value={s.id} />
                      </ActionForm>
                    )}</td>}
                  </tr>
                ))}
              </tbody></table>
            </TableWrap>
          )}
        </section>
      </div>

      <aside className="split-side stack">
        {canManage && (domains.length === 0 ? (
          <div className="card"><h2>Connect a source</h2><p className="muted small">Add and verify a website (domain) asset first. Attack data is only collected for verified websites.</p></div>
        ) : (
          <>
            <div className="card">
              <h2>Connect Cloudflare</h2>
              <p className="muted small">Reads firewall events (WAF blocks, challenges, rate limits, bad bots) for this hostname every 5 minutes. Nothing on Cloudflare is changed.</p>
              <ActionForm action={createCloudflareSourceAction} submit="Connect Cloudflare">
                <AssetSelect domains={domains} />
                <label>Name<input name="name" required maxLength={100} defaultValue="Cloudflare WAF" /></label>
                <label>Zone ID<input name="zoneId" required pattern="[a-f0-9]{32}" maxLength={32} className="mono" autoComplete="off" /><span className="field-hint">32 hex characters, on the zone&apos;s Overview page in Cloudflare.</span></label>
                <label>API token<input name="token" type="password" required maxLength={200} className="mono" autoComplete="off" /><span className="field-hint">Create a custom token with only <strong>Zone → Analytics → Read</strong> for this zone. Stored encrypted; never shown again.</span></label>
              </ActionForm>
            </div>
            <div className="card">
              <h2>Install the log agent</h2>
              <p className="muted small">For servers without Cloudflare. A small script tails your nginx/Apache access log and sends lines to RuyaShield; only suspicious requests are kept.</p>
              <ActionForm action={createLogAgentSourceAction} submit="Create ingest token">
                <AssetSelect domains={domains} />
                <label>Name<input name="name" required maxLength={100} defaultValue="Web server log" /></label>
              </ActionForm>
              <details className="small">
                <summary>Install steps</summary>
                <ol>
                  <li>Copy <code>scripts/ruya-log-agent.sh</code> to the web server, e.g. <code>/usr/local/bin/ruya-log-agent</code>, and <code>chmod 755</code> it.</li>
                  <li>Create <code>/etc/ruya-agent.env</code> with <code>chmod 600</code>:
                    <pre className="mono">{`RUYA_URL=${appUrl}\nRUYA_INGEST_TOKEN=<token shown once above>`}</pre>
                  </li>
                  <li>Run it as a systemd service with <code>EnvironmentFile=/etc/ruya-agent.env</code> and <code>ExecStart=/usr/local/bin/ruya-log-agent /var/log/nginx/access.log</code>, as a user that can read the log. Logs go to <code>{appUrl}/v1/attacks/ingest</code>.</li>
                  <li>Check this page for &quot;last event&quot;.</li>
                </ol>
              </details>
            </div>
          </>
        ))}
        <div className="card">
          <h2>GeoIP setup</h2>
          <p className="muted small">Country and network lookups for log-agent events use MaxMind GeoLite2 databases stored on this server; no IP is sent anywhere for lookup.</p>
          <ol className="small">
            <li>Create a free MaxMind account and a licence key.</li>
            <li>On the server: <code>MAXMIND_ACCOUNT_ID=… MAXMIND_LICENSE_KEY=… npx tsx scripts/geoip-update.mts</code></li>
            <li>Set <code>GEOIP_COUNTRY_DB_PATH</code> and <code>GEOIP_ASN_DB_PATH</code> to the printed paths and restart.</li>
          </ol>
          <p className="small">Status: country {stats.geoip.country ? <StatusBadge status="ok" /> : <StatusBadge status="unavailable" />} · network {stats.geoip.asn ? <StatusBadge status="ok" /> : <StatusBadge status="unavailable" />}</p>
        </div>
      </aside>
    </div>
  );
}

function typeLabelFor(stats: AttackStats, t: string) {
  return stats.byType.find((x) => x.type === t)?.label ?? t.replace(/_/g, " ");
}

function AssetSelect({ domains }: { domains: { id: string; host: string }[] }) {
  return (
    <label>Website
      <select name="assetId" required>
        {domains.map((d) => <option key={d.id} value={d.id}>{d.host}</option>)}
      </select>
    </label>
  );
}

/** Never let "zero events" read as "no attacks" when nothing is collecting. */
function Coverage({ stats }: { stats: AttackStats }) {
  const s = stats.sources;
  if (stats.coverage === "none") {
    return (
      <div className="notice bad small">
        <strong>No data — this is not an all-clear.</strong>{" "}
        {s.total === 0 ? "No source is connected for this view." : `${s.total} source${s.total === 1 ? " is" : "s are"} connected but none is collecting (${s.error} in error, ${s.pending} waiting for the first data).`}{" "}
        {stats.total > 0 ? "The events below are older data from sources that have stopped." : "Attacks may be happening without being recorded."}
      </div>
    );
  }
  if (stats.coverage === "partial") {
    return (
      <div className="notice warn small">
        <strong>Partial data.</strong> {s.active} of {s.total} sources are collecting; {s.error > 0 ? `${s.error} in error` : ""}{s.error > 0 && s.pending > 0 ? ", " : ""}{s.pending > 0 ? `${s.pending} waiting for first data` : ""}. Counts below are a lower bound.
      </div>
    );
  }
  return stats.total === 0
    ? <div className="notice ok small">All {s.active} source{s.active === 1 ? " is" : "s are"} collecting. No suspicious requests were recorded in this period — that covers only the traffic these sources see.</div>
    : null;
}

function Timeline({ points }: { points: { day: string; n: number }[] }) {
  const W = 640, H = 180, L = 34, B = 24, T = 10, R = 8;
  const max = Math.max(4, ...points.map((p) => p.n));
  const step = Math.ceil(max / 4);
  const top = step * 4;
  const y = (v: number) => T + (H - T - B) * (1 - v / top);
  const colW = (W - L - R) / points.length;
  const bw = Math.max(2, Math.min(16, colW - 2));
  const label = (d: string) => new Date(`${d}T00:00:00Z`).toLocaleDateString("en-GB", { day: "numeric", month: "short", timeZone: "UTC" });
  const every = Math.max(1, Math.ceil(points.length / 8));
  return (
    <svg className="trend" viewBox={`0 0 ${W} ${H}`} aria-hidden="true" focusable="false">
      {[0, 1, 2, 3, 4].map((i) => (
        <g key={i}>
          <line x1={L} x2={W - R} y1={y(i * step)} y2={y(i * step)} className="trend-grid" />
          <text x={L - 8} y={y(i * step) + 4} className="trend-axis" textAnchor="end">{i * step}</text>
        </g>
      ))}
      {points.map((p, i) => {
        const cx = L + colW * i + colW / 2;
        return (
          <g key={p.day} className="trend-col">
            <title>{`${label(p.day)}: ${p.n} suspicious request${p.n === 1 ? "" : "s"}`}</title>
            <rect x={L + colW * i} y={T} width={colW} height={H - T - B} className="trend-hit" />
            {p.n > 0 && <rect x={cx - bw / 2} y={y(p.n)} width={bw} height={Math.max(1, H - B - y(p.n))} rx={Math.min(3, bw / 2)} className="trend-bar attacks" />}
            {(points.length - 1 - i) % every === 0 && <text x={cx} y={H - 6} className="trend-axis" textAnchor="middle">{label(p.day)}</text>}
          </g>
        );
      })}
    </svg>
  );
}

function TopList({ title, head, rows }: { title: string; head: string; rows: { key: string; label: React.ReactNode; n: number }[] }) {
  const max = Math.max(1, ...rows.map((r) => r.n));
  return (
    <section className="card">
      <h2>{title}</h2>
      {rows.length === 0 ? <p className="muted small">No data.</p> : (
        <table className="hbar-table"><thead><tr><th>{head}</th><th className="num">Requests</th></tr></thead><tbody>
          {rows.map((r) => (
            <tr key={r.key}>
              <td>{r.label}<div className="hbar" aria-hidden="true"><span style={{ width: `${Math.max(2, (r.n / max) * 100)}%` }} /></div></td>
              <td className="num">{r.n.toLocaleString("en-GB")}</td>
            </tr>
          ))}
        </tbody></table>
      )}
    </section>
  );
}
