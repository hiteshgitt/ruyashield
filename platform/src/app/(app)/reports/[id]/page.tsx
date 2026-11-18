import { Suspense } from "react";
import Link from "next/link";
import { notFound } from "next/navigation";
import { getReportInfo } from "@/server/reports/reports";
import { PRESETS, SECTIONS, SECTION_KEYS } from "@/server/reports/content";
import { listClientGroups } from "@/server/orgs/orgs";
import { isAppError } from "@/server/errors";
import { fmt, pageOrg } from "../../_lib/page";
import { Loading, PageHeader } from "../../_components/Page";

type Params = {
  title?: string; preset?: string; sections?: string[]; minSeverity?: string; includeFixes?: boolean; windowDays?: number;
  snapshot?: {
    openTotal: number; open: Record<string, number>; overdue: number; fixedVerified: number; assets: number; verifiedAssets: number;
    assessments: number; failedVerifications: number; incomplete: number; acceptedRisks: number; findingsListed: number; findingsTotal: number; attacks: number | null;
  };
};

export default function ReportPage({ params }: PageProps<"/reports/[id]">) {
  return (
    <>
      <p className="small"><Link href="/reports">← Reports</Link></p>
      <Suspense fallback={<Loading />}><Report params={params} /></Suspense>
    </>
  );
}

async function Report({ params }: { params: PageProps<"/reports/[id]">["params"] }) {
  const { id } = await params;
  const c = await pageOrg(`/reports/${id}`);
  let r;
  try {
    r = await getReportInfo(c, id);
  } catch (e) {
    if (isAppError(e) && e.status === 404) notFound();
    throw e;
  }
  const p = (r.params ?? {}) as Params;
  const s = p.snapshot;
  const groups = await listClientGroups(c);
  const scope = r.clientGroupId ? groups.find((g) => g.id === r.clientGroupId)?.name ?? "(client group)" : "All assets in scope";
  const presetLabel = p.preset === "custom" ? "Custom" : PRESETS[p.preset as keyof typeof PRESETS]?.label ?? "Security report";
  const included = new Set(p.sections ?? SECTION_KEYS);

  return (
    <div className="stack">
      <PageHeader title={p.title || "Security report"} lead={`${presetLabel} · ${r.format.toUpperCase()} · generated ${fmt(r.createdAt)} · ${scope}`} />
      <div className="row">
        <a className="button" href={`/v1/reports/${r.id}`}>Download {r.format.toUpperCase()}</a>
        <Link className="button secondary" href="/reports">Generate another</Link>
      </div>

      {s && (
        <section className="stats" aria-label="Figures when the report was generated">
          <div className="card stat-mini"><span className="label">Open findings</span><strong>{s.openTotal}</strong><span className="muted small">{s.open.critical} critical · {s.open.high} high · {s.open.medium} medium · {s.open.low} low</span></div>
          <div className="card stat-mini"><span className="label">Fixed and re-tested</span><strong>{s.fixedVerified}</strong><span className="muted small">last {p.windowDays ?? 30} days</span></div>
          <div className="card stat-mini"><span className="label">Assets</span><strong>{s.assets}</strong><span className="muted small">{s.verifiedAssets} verified · {s.assessments} assessments</span></div>
          <div className="card stat-mini"><span className="label">Needs attention</span><strong>{s.overdue + s.failedVerifications}</strong><span className="muted small">{s.overdue} past due · {s.failedVerifications} re-tests not passed</span></div>
        </section>
      )}

      <section className="card">
        <h2>What this report contains</h2>
        <ul className="report-contents">
          {SECTION_KEYS.map((k) => (
            <li key={k} className={included.has(k) ? "on" : "off"}>
              <span className="report-contents-mark" aria-hidden="true">{included.has(k) ? "✓" : "–"}</span>
              <span><b>{SECTIONS[k].label}</b> <span className="muted small">{included.has(k) ? SECTIONS[k].hint : "Not included."}</span>
                {k === "findings" && included.has(k) && s && <span className="muted small"> {s.findingsListed} of {s.findingsTotal} listed, {p.minSeverity ?? "info"} severity and above{p.includeFixes ? ", with fixes" : ""}.</span>}
                {k === "attacks" && included.has(k) && s && <span className="muted small"> {s.attacks == null ? "No attack source covered these assets." : `${s.attacks} hostile requests.`}</span>}
              </span>
            </li>
          ))}
          <li className="on"><span className="report-contents-mark" aria-hidden="true">✓</span><span><b>Limitations</b> <span className="muted small">Always included: what the checks cover and what they do not.</span></span></li>
        </ul>
      </section>

      <section className="card">
        <h2>Integrity</h2>
        <p className="small">The file is stored exactly as generated. Anyone can check a copy matches this record:</p>
        <dl className="kv small">
          <dt>SHA-256</dt><dd><code className="mono" style={{ wordBreak: "break-all" }}>{r.sha256}</code></dd>
          <dt>Size</dt><dd>{(r.sizeBytes / 1024).toFixed(1)} KB</dd>
          <dt>Check it</dt><dd><code className="mono">sha256sum ruyashield-report-*.{r.format}</code></dd>
        </dl>
        <p className="muted small">Downloads are recorded in the audit log. This report is not a certification or a compliance attestation.</p>
      </section>
    </div>
  );
}
