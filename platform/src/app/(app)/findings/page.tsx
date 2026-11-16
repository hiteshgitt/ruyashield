import { Suspense } from "react";
import Link from "next/link";
import { listFindings } from "@/server/findings/findings";
import { ALL_STATUSES } from "@/server/findings/lifecycle";
import { isAppError } from "@/server/errors";
import { StatusBadge } from "../_components/StatusBadge";
import { messageFor } from "../_lib/messages";
import { fmt, pageOrg } from "../_lib/page";
import { Empty, Loading, PageHeader } from "../_components/Page";
import { TableWrap } from "../_components/TableWrap";
import { SECURITY_AREAS, areaByKey } from "@/server/reports/areas";
import { SeverityCards } from "../_components/Charts";
import type { Severity } from "@/server/db/schema";

/** Quick views: one click for the questions people ask most. */
const VIEWS: { label: string; status: string; hint: string }[] = [
  { label: "Open", status: "open", hint: "Everything still needing work" },
  { label: "New", status: "new", hint: "Not triaged yet" },
  { label: "Awaiting re-test", status: "fix_pending_verification", hint: "Fixed, waiting for proof" },
  { label: "Resolved", status: "resolved_verified", hint: "Fix confirmed by a re-test" },
  { label: "All", status: "", hint: "Every status" },
];

const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const CONFIDENCES = ["confirmed", "likely", "suspected", "unknown"];
const FILTERS = ["assetId", "area", "severity", "confidence", "status", "owner", "cursor"] as const;

export default function FindingsPage({ searchParams }: PageProps<"/findings">) {
  return (
    <>
      <PageHeader title="Findings" lead={<>Ordered by priority: severity × confidence × the asset&apos;s business criticality. A finding stays open until a verification re-test confirms the fix.</>} />
      <Suspense fallback={<Loading />}><Findings searchParams={searchParams} /></Suspense>
    </>
  );
}

async function Findings({ searchParams }: { searchParams: PageProps<"/findings">["searchParams"] }) {
  const sp = await searchParams;
  const q: Record<string, string> = {};
  for (const k of FILTERS) { const v = sp[k]; if (typeof v === "string" && v) q[k] = v; }
  if (!("status" in sp)) q.status = "open";
  const c = await pageOrg("/findings");
  let data;
  try {
    data = await listFindings(c, q);
  } catch (e) {
    if (isAppError(e) && e.status < 500) return <div className="notice bad">{messageFor(e.code, e.message)}</div>;
    throw e;
  }
  const next = data.nextCursor ? `/findings?${new URLSearchParams({ ...q, cursor: data.nextCursor })}` : null;
  const link = (patch: Record<string, string | null>) => {
    const p: Record<string, string> = { ...q };
    delete p.cursor;
    for (const [k, v] of Object.entries(patch)) if (v === null) delete p[k]; else p[k] = v;
    return `/findings?${new URLSearchParams(p)}`;
  };
  const matched = Object.values(data.bySeverity).reduce((n, v) => n + v, 0);
  const view = VIEWS.find((v) => v.status === (q.status ?? ""));
  const area = q.area ? areaByKey(q.area) : undefined;

  return (
    <>
      <nav className="quick-views" aria-label="Quick views">
        {VIEWS.map((v) => (
          <Link key={v.label} href={link({ status: v.status, severity: null })} className={v === view ? "active" : undefined} aria-current={v === view ? "page" : undefined}>
            <span>{v.label}</span><small>{v.hint}</small>
          </Link>
        ))}
      </nav>

      <section className="card panel sev-summary" aria-labelledby="sev-summary-h">
        <div className="sev-summary-head">
          <h3 id="sev-summary-h">By severity</h3>
          <p className="muted small">
            {matched} finding{matched === 1 ? "" : "s"} {view ? <>in <strong>{view.label.toLowerCase()}</strong></> : <>with status <strong>{(q.status ?? "").replace(/_/g, " ")}</strong></>}
            {area && <> · area <strong>{area.label}</strong></>}. Click a card to filter. A zero only means no check that ran reported one.
          </p>
        </div>
        <SeverityCards counts={data.bySeverity as Record<Severity, number>} active={q.severity} hrefFor={(s) => link({ severity: s })} />
      </section>

      <form method="get" className="card toolbar small">
        {q.assetId && <input type="hidden" name="assetId" value={q.assetId} />}
        <label>Status <select name="status" defaultValue={q.status ?? ""}>
          <option value="open">Open</option><option value="">All</option>
          {ALL_STATUSES.map((s) => <option key={s} value={s}>{s.replace(/_/g, " ")}</option>)}
        </select></label>
        <label>Area <select name="area" defaultValue={q.area ?? ""}>
          <option value="">Any</option>{SECURITY_AREAS.filter((a) => a.checks.length).map((a) => <option key={a.key} value={a.key}>{a.label}</option>)}
        </select></label>
        <label>Severity <select name="severity" defaultValue={q.severity ?? ""}>
          <option value="">Any</option>{SEVERITIES.map((s) => <option key={s}>{s}</option>)}
        </select></label>
        <label>Confidence <select name="confidence" defaultValue={q.confidence ?? ""}>
          <option value="">Any</option>{CONFIDENCES.map((s) => <option key={s}>{s}</option>)}
        </select></label>
        <label>Owner <select name="owner" defaultValue={q.owner ?? ""}>
          <option value="">Anyone</option><option value="me">Me</option><option value="none">Unassigned</option>
        </select></label>
        <button type="submit" className="secondary">Filter</button>
        {q.assetId && <Link href="/findings">Clear asset filter</Link>}
        <span className="muted toolbar-end" role="status">{data.items.length} shown{next ? " on this page" : ""}</span>
      </form>

      {data.items.length === 0 ? (
        <Empty>No findings match these filters. This does not mean the assets are free of issues — only that no check that ran reported one.</Empty>
      ) : (
        <TableWrap className="card">
          <table><thead><tr><th>Priority</th><th>Severity</th><th>Finding</th><th>Asset</th><th>Status</th><th>Owner</th><th>Due</th><th>Last seen</th></tr></thead><tbody>
            {data.items.map((f) => (
              <tr key={f.id}>
                <td><span className="prio" title="Priority score">{f.priority.score.toFixed(1)}</span></td>
                <td><StatusBadge status={f.severity} />{f.confidence !== "confirmed" && <div className="muted small">{f.confidence}</div>}</td>
                <td className="finding-cell"><Link href={`/findings/${f.id}`}>{f.title}</Link><div className="muted small mono">{f.location}</div></td>
                <td className="mono small"><Link href={`/assets/${f.assetId}`}>{f.host}</Link></td>
                <td><StatusBadge status={f.status} /></td>
                <td className="small">{f.owner?.name ?? f.owner?.email ?? <span className="muted">—</span>}</td>
                <td className="small">{f.dueAt ? <>{fmt(f.dueAt).slice(0, 10)}{f.overdue && <> <span className="badge bad">overdue</span></>}</> : "—"}</td>
                <td className="small">{fmt(f.lastSeen)}</td>
              </tr>
            ))}
          </tbody></table>
        </TableWrap>
      )}
      {next && <p className="pager"><Link className="button secondary" href={next}>Next page →</Link></p>}
    </>
  );
}
