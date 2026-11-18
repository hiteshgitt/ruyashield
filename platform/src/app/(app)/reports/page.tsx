import { Suspense } from "react";
import { listReports } from "@/server/reports/reports";
import { listClientGroups } from "@/server/orgs/orgs";
import { isAppError } from "@/server/errors";
import Link from "next/link";
import { ReportBuilder } from "./ReportBuilder";
import { PRESETS, SECTIONS, SECTION_KEYS } from "@/server/reports/content";

const SECTION_LABEL: Record<string, string> = Object.fromEntries(SECTION_KEYS.map((k) => [k, SECTIONS[k].label]));
const PRESET_LABEL: Record<string, string> = { ...Object.fromEntries(Object.entries(PRESETS).map(([k, v]) => [k, v.label])), custom: "Custom" };
import { generateReportAction } from "../actions";
import { messageFor } from "../_lib/messages";
import { fmt, pageOrg } from "../_lib/page";
import { Empty, Loading, MetaChips, PageHeader, ProGate } from "../_components/Page";
import { isProOrg } from "@/server/policy/policy";

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
    return (
      <ProGate title="Reports" rows={6} features={["PDF and CSV", "SHA-256 per file", "Per client group", "Failed checks and limits listed"]}>
        Generate a stored snapshot of your security overview to send to a client or auditor. Your overview stays on the dashboard.
      </ProGate>
    );
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
        {items.length === 0 ? <Empty>No reports yet. Pick a report type and generate one.</Empty> : (
          <ul className="report-list">
            {items.map((r) => {
              const pr = (r.params ?? {}) as { title?: string; preset?: string; sections?: string[]; snapshot?: { openTotal?: number; open?: Record<string, number> } };
              const snap = pr.snapshot;
              return (
                <li key={r.id} className="card report-item">
                  <div className="report-item-main">
                    <Link href={`/reports/${r.id}`} className="report-item-title">{pr.title || "Security report"}</Link>
                    <div className="muted small">{fmt(r.createdAt)} · {groupName(r.clientGroupId)} · {Math.ceil(r.sizeBytes / 1024)} KB</div>
                    <ul className="report-chips">
                      <li className="chip">{r.format.toUpperCase()}</li>
                      {pr.preset && <li className="chip">{PRESET_LABEL[pr.preset] ?? pr.preset}</li>}
                      {(pr.sections ?? []).map((k) => <li key={k} className="chip subtle">{SECTION_LABEL[k] ?? k}</li>)}
                    </ul>
                  </div>
                  {snap?.open && (
                    <div className="report-item-figures" aria-label="Open findings when generated">
                      <span className="sev-critical">{snap.open.critical ?? 0}<small>crit</small></span>
                      <span className="sev-high">{snap.open.high ?? 0}<small>high</small></span>
                      <span className="sev-medium">{snap.open.medium ?? 0}<small>med</small></span>
                      <span className="sev-low">{snap.open.low ?? 0}<small>low</small></span>
                    </div>
                  )}
                  <div className="report-item-actions">
                    <Link href={`/reports/${r.id}`} className="button secondary small-btn">Details</Link>
                    <a href={`/v1/reports/${r.id}`} className="button small-btn">Download</a>
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </section>
      <section className="card split-side" aria-labelledby="gen-report">
        <h2 id="gen-report">Generate a report</h2>
        <ReportBuilder action={generateReportAction} groupId={groupId} restricted={c.principal.restricted} groups={groups.map((g) => ({ id: g.id, name: g.name }))}
          sections={SECTION_KEYS.map((k) => ({ key: k, ...SECTIONS[k] }))}
          presets={(Object.keys(PRESETS) as (keyof typeof PRESETS)[]).map((k) => ({ key: k, label: PRESETS[k].label, hint: PRESETS[k].hint, sections: [...PRESETS[k].sections], minSeverity: PRESETS[k].minSeverity, includeFixes: PRESETS[k].includeFixes }))} />
      </section>
    </div>
  );
}
