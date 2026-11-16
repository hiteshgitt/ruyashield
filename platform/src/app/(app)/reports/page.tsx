import { Suspense } from "react";
import { listReports } from "@/server/reports/reports";
import { listClientGroups } from "@/server/orgs/orgs";
import { isAppError } from "@/server/errors";
import { ActionForm } from "../_components/ActionForm";
import { generateReportAction } from "../actions";
import { messageFor } from "../_lib/messages";
import { fmt, pageOrg } from "../_lib/page";
import { Empty, Loading, MetaChips, PageHeader, ProNotice } from "../_components/Page";
import { isProOrg } from "@/server/policy/policy";
import { TableWrap } from "../_components/TableWrap";

export default function ReportsPage({ searchParams }: PageProps<"/reports">) {
  return (
    <>
      <PageHeader title="Reports" lead="A report is a stored snapshot of the security overview, with its SHA-256 recorded. Each one lists failed and incomplete checks, accepted risks and the limitations of the assessment. It is not a certification." />
      <Suspense fallback={<Loading />}><Reports searchParams={searchParams} /></Suspense>
    </>
  );
}

async function Reports({ searchParams }: { searchParams: PageProps<"/reports">["searchParams"] }) {
  const sp = await searchParams;
  const groupId = typeof sp.clientGroupId === "string" ? sp.clientGroupId : "";
  const c = await pageOrg("/reports");
  if (!isProOrg(c.org)) {
    return <ProNotice>Generating and downloading reports (PDF and CSV, with SHA-256) is part of RuyaShield Pro. Your security overview stays on the dashboard.</ProNotice>;
  }
  let items;
  try {
    items = await listReports(c);
  } catch (e) {
    if (isAppError(e) && e.status < 500) return <div className="notice bad">{messageFor(e.code, e.message)}</div>;
    throw e;
  }
  const groups = await listClientGroups(c);
  const groupName = (id: string | null) => id ? groups.find((g) => g.id === id)?.name ?? "(group)" : "All in scope";
  return (
    <div className="split">
      <section className="split-main" aria-labelledby="reports-h">
        <h2 id="reports-h">Generated reports</h2>
        {items.length > 0 && (
          <MetaChips label="Report counts">
            <li>{items.length} total</li>
            <li>{items.filter((r) => r.format === "pdf").length} PDF</li>
            <li>{items.filter((r) => r.format === "csv").length} CSV</li>
          </MetaChips>
        )}
        {items.length === 0 ? <Empty>No reports yet. Generate one with the form.</Empty> : (
          <TableWrap className="card"><table><thead><tr><th>Created</th><th>Format</th><th>Client group</th><th>Size</th><th>SHA-256</th><th><span className="sr-only">Download</span></th></tr></thead><tbody>
            {items.map((r) => <tr key={r.id}><td className="small">{fmt(r.createdAt)}</td><td><span className="chip">{r.format.toUpperCase()}</span></td>
              <td>{groupName(r.clientGroupId)}</td>
              <td className="small">{Math.ceil(r.sizeBytes / 1024)} KB</td><td className="small"><code className="mono" title={r.sha256}>{r.sha256.slice(0, 16)}…</code></td>
              <td><a href={`/v1/reports/${r.id}`} className="button secondary small-btn">Download</a></td></tr>)}
          </tbody></table></TableWrap>
        )}
      </section>
      <section className="card split-side" aria-labelledby="gen-report">
        <h2 id="gen-report">Generate a report</h2>
        <ActionForm action={generateReportAction} submit="Generate" pending="Generating…">
          <label>Format <select name="format" defaultValue="pdf"><option value="pdf">PDF</option><option value="csv">CSV</option></select></label>
          <label>Client group <select name="clientGroupId" defaultValue={groupId}>
            <option value="">{c.principal.restricted ? "All my client groups" : "All assets"}</option>
            {groups.map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}
          </select></label>
          <p className="muted small">Includes failed and incomplete checks, accepted risks and limitations. Not a certification or a compliance attestation.</p>
        </ActionForm>
      </section>
    </div>
  );
}
