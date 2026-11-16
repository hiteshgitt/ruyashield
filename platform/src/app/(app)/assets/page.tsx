import { Suspense } from "react";
import Link from "next/link";
import { grantFor } from "@/server/policy/matrix";
import { listAssets } from "@/server/assets/assets";
import { listSuggestions } from "@/server/assets/suggestions";
import { listClientGroups } from "@/server/orgs/orgs";
import { ActionForm } from "../_components/ActionForm";
import { StatusBadge } from "../_components/StatusBadge";
import { addAssetAction, addSuggestionAction, dismissSuggestionAction } from "../actions";
import { fmt, pageOrg } from "../_lib/page";
import { Empty, Loading, MetaChips, PageHeader } from "../_components/Page";
import { TableWrap } from "../_components/TableWrap";

export default function AssetsPage({ searchParams }: PageProps<"/assets">) {
  return (
    <>
      <PageHeader title="Assets" lead="Only verified assets, or assets covered by a recorded authorization, can be assessed." />
      <Suspense fallback={<Loading />}><Assets searchParams={searchParams} /></Suspense>
    </>
  );
}

async function Assets({ searchParams }: { searchParams: PageProps<"/assets">["searchParams"] }) {
  const sp = await searchParams;
  // ?host= fills in the add form, for links from WebMonitor ("Add in RuyaShield").
  const prefill = typeof sp.host === "string" ? sp.host.trim().slice(0, 253) : "";
  const c = await pageOrg("/assets");
  const [assets, groups, suggestions] = await Promise.all([listAssets(c), listClientGroups(c), listSuggestions(c)]);
  const hostOf = new Map(assets.map((a) => [a.id, a.host]));
  const canAdd = grantFor(c.principal.role, "asset.edit") !== "N";
  const count = (s: string) => assets.filter((a) => a.status === s).length;
  return (
    <div className={canAdd ? "split" : undefined}>
      <section className="split-main" aria-label="Asset list">
        {assets.length > 0 && (
          <MetaChips label="Asset counts">
            <li>{assets.length} total</li>
            <li>{count("verified")} verified</li>
            <li>{count("unverified")} not yet verified</li>
            <li>{count("lapsed") + count("revoked")} lapsed or revoked</li>
          </MetaChips>
        )}
        <TableWrap className="card">
          {assets.length === 0 ? <Empty>No assets yet.{canAdd && " Add your first one with the form."}</Empty> : (
            <table><thead><tr><th>Host</th><th>Environment</th><th>Criticality</th><th>Status</th><th>Next re-verification</th></tr></thead><tbody>
              {assets.map((a) => (
                <tr key={a.id}>
                  <td className="host-cell"><Link href={`/assets/${a.id}`} className="mono">{a.host}</Link>{a.displayName !== a.host && <div className="muted small">{a.displayName}</div>}</td>
                  <td><span className="chip">{a.environment}</span></td>
                  <td className="small">{a.criticality ?? <span className="muted">not set</span>}</td>
                  <td><StatusBadge status={a.status} /></td>
                  <td className="small">{a.status === "verified" ? fmt(a.nextReverifyAt) : "—"}</td>
                </tr>
              ))}
            </tbody></table>
          )}
        </TableWrap>
        {suggestions.length > 0 && (
          <section className="card stack" aria-labelledby="suggested-assets">
            <h2 id="suggested-assets">Suggested assets <span className="chip">{suggestions.length}</span></h2>
            <p className="muted small">Hostnames found in public Certificate Transparency logs for your verified domains. Nothing has contacted them. Adding one creates an unverified asset: verify ownership before it can be scanned.</p>
            <TableWrap>
              <table><thead><tr><th>Host</th><th>Found via</th><th>Last seen</th>{canAdd && <th>Decision</th>}</tr></thead><tbody>
                {suggestions.map((s) => (
                  <tr key={s.id}>
                    <td className="mono">{s.host}</td>
                    <td className="small">{s.sourceAssetId && hostOf.get(s.sourceAssetId) ? <Link href={`/assets/${s.sourceAssetId}`} className="mono">{hostOf.get(s.sourceAssetId)}</Link> : "CT logs"}</td>
                    <td className="small">{fmt(s.lastSeen)}</td>
                    {canAdd && (
                      <td><div className="row">
                        <ActionForm action={addSuggestionAction} submit="Add" pending="Adding…" variant="secondary" className="row inline-form">
                          <input type="hidden" name="suggestionId" value={s.id} />
                        </ActionForm>
                        <ActionForm action={dismissSuggestionAction} submit="Dismiss" pending="Dismissing…" variant="secondary" className="row inline-form">
                          <input type="hidden" name="suggestionId" value={s.id} />
                        </ActionForm>
                      </div></td>
                    )}
                  </tr>
                ))}
              </tbody></table>
            </TableWrap>
          </section>
        )}
      </section>
      {canAdd && (
        <section className="card split-side" aria-labelledby="add-asset">
          <h2 id="add-asset">Add an asset</h2>
          <ActionForm action={addAssetAction} submit="Add asset">
            <label>Hostname<input type="text" name="host" required placeholder="app.example.com" defaultValue={prefill} autoFocus={!!prefill} /></label>
            <label>Display name (optional)<input type="text" name="displayName" maxLength={80} /></label>
            <label>Environment<select name="environment" defaultValue="production">
              <option value="production">Production</option><option value="staging">Staging</option><option value="development">Development</option>
            </select></label>
            {groups.length > 0 && (
              <label>Client group<select name="clientGroupId" defaultValue="">
                <option value="">None</option>{groups.map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}
              </select></label>
            )}
            <p className="muted small">Private, loopback and reserved addresses are refused. Adding an asset does not authorize testing it: verify ownership or record a written authorization next.</p>
          </ActionForm>
        </section>
      )}
    </div>
  );
}
