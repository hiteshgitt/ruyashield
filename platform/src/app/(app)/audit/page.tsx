import { Suspense } from "react";
import Link from "next/link";
import { AUDIT_EXPORT_MAX, AUDIT_PAGE_SIZE, listAuditEvents, type AuditFilter } from "@/server/audit/view";
import { grantFor } from "@/server/policy/matrix";
import { isAppError } from "@/server/errors";
import { ActionForm } from "../_components/ActionForm";
import { verifyAuditChainAction } from "../actions";
import { messageFor } from "../_lib/messages";
import { fmt, pageOrg } from "../_lib/page";
import { Empty, Loading, MetaChips, PageHeader, ProGate } from "../_components/Page";
import { isProOrg } from "@/server/policy/policy";
import { TableWrap } from "../_components/TableWrap";

export default function AuditPage({ searchParams }: PageProps<"/audit">) {
  return (
    <>
      <PageHeader title="Audit log" lead="Append-only and hash-chained. Verifying recomputes every hash for this organization." />
      <Suspense fallback={<Loading />}><Audit searchParams={searchParams} /></Suspense>
    </>
  );
}

const KEYS = ["action", "outcome", "actorId", "from", "to"] as const;

async function Audit({ searchParams }: { searchParams: PageProps<"/audit">["searchParams"] }) {
  const sp = await searchParams;
  const c = await pageOrg("/audit");
  if (grantFor(c.principal.role, "audit.view") === "N") return <p className="notice warn">Only org admins and security leads can view the audit log.</p>;
  const before = Number(typeof sp.before === "string" ? sp.before : "") || undefined;
  const f: AuditFilter = {};
  for (const k of KEYS) if (typeof sp[k] === "string" && sp[k]) f[k] = sp[k] as string;
  const qs = (extra: Record<string, string>) => new URLSearchParams({ ...(f as Record<string, string>), ...extra }).toString();
  let events;
  try {
    events = await listAuditEvents(c, before, f);
  } catch (e) {
    if (isAppError(e) && e.status < 500) return <><Filters f={f} /><div className="notice bad">{messageFor(e.code, e.message)} <Link href="/audit">Clear filters</Link></div></>;
    throw e;
  }
  const last = events.at(-1);
  const canExport = grantFor(c.principal.role, "audit.export") !== "N";
  const tone = (o: string) => o === "success" ? "ok" : o === "denied" ? "warn" : "bad";
  return (
    <>
      <div className="card audit-top">
        <div className="audit-verify">
          <ActionForm action={verifyAuditChainAction} submit="Verify chain" pending="Verifying…" variant="secondary" />
          <p className="muted small">Recomputes every event hash and chain link for this organization and reports the first break, if any.</p>
        </div>
        {canExport && !isProOrg(c.org) && <div className="audit-export"><ProGate compact rows={2} title="Audit log export">Download the filtered log as CSV or JSON, with hashes, for auditors.</ProGate></div>}
        {canExport && isProOrg(c.org) && (
          <div className="audit-export">
            <div className="row">
              <a className="button secondary" href={`/v1/audit/export?${qs({ format: "csv" })}`}>Export CSV</a>
              <a className="button secondary" href={`/v1/audit/export?${qs({ format: "json" })}`}>Export JSON</a>
            </div>
            <p className="muted small">Exports the filtered log, oldest first, with hashes. Needs a recent MFA sign-in; at most {AUDIT_EXPORT_MAX.toLocaleString()} events; the export is itself audited.</p>
          </div>
        )}
      </div>
      <Filters f={f} />
      <MetaChips label="Page summary">
        <li>{events.length} on this page</li>
        {(["success", "denied", "error"] as const).map((o) => <li key={o}>{events.filter((e) => e.outcome === o).length} {o}</li>)}
        {before && <li>older than #{before}</li>}
      </MetaChips>
      <TableWrap className="card">
        {events.length === 0 ? <Empty>No events{Object.keys(f).length > 0 ? " match these filters" : ""}.</Empty> : (
          <table className="audit-table"><thead><tr><th>#</th><th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Outcome</th></tr></thead><tbody>
            {events.map((e) => (
              <tr key={e.id}>
                <td className="small mono muted">{e.seq}</td>
                <td className="small">{fmt(e.ts)}</td>
                <td className="small">{e.actorType}{e.actorId ? <> <span className="mono" title={e.actorId}>{e.actorId.slice(0, 8)}</span></> : ""}{e.actorIp ? <div className="muted mono">{e.actorIp}</div> : null}</td>
                <td><code>{e.action}</code></td>
                <td className="small">{e.targetType ? <>{e.targetType} <span className="mono" title={e.targetId ?? undefined}>{e.targetId?.slice(0, 8) ?? ""}</span></> : "—"}</td>
                <td><span className={`badge ${tone(e.outcome)}`}>{e.outcome}</span>{e.reason && <div className="muted small">{e.reason}</div>}</td>
              </tr>
            ))}
          </tbody></table>
        )}
      </TableWrap>
      <nav className="row pager" aria-label="Audit pages">
        {before && <Link href={`/audit?${qs({})}`} className="button secondary">Newest</Link>}
        {events.length === AUDIT_PAGE_SIZE && last && <Link href={`/audit?${qs({ before: String(last.seq) })}`} className="button secondary">Older →</Link>}
      </nav>
    </>
  );
}

function Filters({ f }: { f: AuditFilter }) {
  return (
    <form method="get" action="/audit" className="card toolbar audit-filters" aria-label="Filter audit events">
      <label>Action prefix<input name="action" defaultValue={f.action} placeholder="e.g. finding." /></label>
      <label>Outcome<select name="outcome" defaultValue={f.outcome ?? ""}>
        <option value="">Any outcome</option><option value="success">success</option><option value="denied">denied</option><option value="error">error</option>
      </select></label>
      <label>Actor id<input name="actorId" defaultValue={f.actorId} placeholder="User or token id" /></label>
      <label>From<input type="date" name="from" defaultValue={f.from} /></label>
      <label>To<input type="date" name="to" defaultValue={f.to} /></label>
      <div className="row toolbar-end">
        <button type="submit" className="secondary">Filter</button>
        {Object.keys(f).length > 0 && <Link href="/audit" className="small">Clear</Link>}
      </div>
    </form>
  );
}
