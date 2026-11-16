import { Suspense } from "react";
import Link from "next/link";
import { listAssessments } from "@/server/assessments/assessments";
import type { AssessmentStatus, Coverage as Cov } from "@/server/db/schema";
import { Coverage } from "../_components/Coverage";
import { StatusBadge } from "../_components/StatusBadge";
import { StatCard } from "../_components/Charts";
import { Meter } from "../_components/Meter";
import { fmt, pageOrg } from "../_lib/page";
import { Loading, PageHeader } from "../_components/Page";
import { TableWrap } from "../_components/TableWrap";
import { AutoRefresh } from "../_components/AutoRefresh";

export default function AssessmentsPage() {
  return (
    <>
      <PageHeader title="Assessments" lead={<>Assessments run only against verified or authorized assets, inside the scope fixed at launch. Start one from an asset&apos;s page.</>} />
      <Suspense fallback={<Loading />}><List /></Suspense>
    </>
  );
}

type Outcome = "full" | "partial" | "active" | "stopped";

/** Only a completed run where every planned check succeeded counts as full; everything else is said plainly. */
function outcomeOf(status: AssessmentStatus, c: Cov | null): Outcome {
  if (status === "draft" || status === "queued" || status === "running" || status === "cancelling") return "active";
  if (status === "completed" && c?.complete && c.ok === c.planned) return "full";
  if (status === "completed" || status === "completed_with_errors" || status === "timed_out") return "partial";
  return "stopped";
}

const OUTCOME_TEXT: Record<Outcome, string> = {
  full: "All planned checks ran",
  partial: "Partial: some checks did not finish",
  active: "In progress",
  stopped: "Stopped: no complete result",
};

async function List() {
  const c = await pageOrg("/assessments");
  const rows = await listAssessments(c);
  if (!rows.length) {
    return (
      <div className="card hero-empty">
        <h2>Run your first assessment</h2>
        <p className="muted">Open a verified <Link href="/assets">asset</Link> and choose <strong>Run assessment</strong>. It takes a few minutes and only runs safe, non-intrusive checks.</p>
        <p><Link className="button" href="/assets">Go to assets</Link></p>
      </div>
    );
  }
  const n: Record<Outcome, number> = { full: 0, partial: 0, active: 0, stopped: 0 };
  for (const { assessment: x } of rows) n[outcomeOf(x.status, x.coverage)]++;
  const lastDone = rows.find(({ assessment: x }) => x.finishedAt)?.assessment.finishedAt ?? null;
  const assets = new Set(rows.map((r) => r.asset.id)).size;

  return (
    <>
      {n.active > 0 && <AutoRefresh label={`${n.active} run${n.active === 1 ? "" : "s"} in progress: this list updates automatically.`} />}
      <div className="stats">
        <StatCard icon="assessments" label="Assessments" value={rows.length} sub={<>{assets} asset{assets === 1 ? "" : "s"} · last finished {lastDone ? fmt(lastDone) : "never"}</>} />
        <StatCard icon="check" tone="ok" label="Full coverage" value={n.full} sub="Every planned check ran" />
        <StatCard icon="clock" tone="violet" label="In progress" value={n.active} sub="Queued or running now" />
        <StatCard icon="target" tone={n.partial + n.stopped ? "warn" : "ok"} label="Partial or stopped" value={n.partial + n.stopped} sub="Not a clean bill of health" />
      </div>

      <section className="card panel">
        <h3>Outcome of the last {rows.length} assessment{rows.length === 1 ? "" : "s"}</h3>
        <Meter empty="No assessments yet." segments={[
          { label: "full coverage", count: n.full, tone: "ok" },
          { label: "partial", count: n.partial, tone: "warn" },
          { label: "in progress", count: n.active, tone: "violet" },
          { label: "stopped", count: n.stopped, tone: "bad" },
        ]} />
      </section>

      <TableWrap className="card">
        <table><thead><tr><th>Asset</th><th>Result</th><th>Coverage</th><th>Queued</th><th>Finished</th><th><span className="sr-only">Open</span></th></tr></thead><tbody>
          {rows.map(({ assessment: x, asset: a }) => {
            const o = outcomeOf(x.status, x.coverage);
            return (
              <tr key={x.id} className={`run-row run-${o}`}>
                <td className="host-cell">
                  <Link href={`/assessments/${x.id}`} className="mono">{a.host.startsWith("repo:") ? `repo · ${a.host.slice(5)}` : a.host}</Link>
                  {a.displayName && a.displayName !== a.host && <div className="muted small">{a.displayName}</div>}
                </td>
                <td><StatusBadge status={x.status} /><div className="muted small">{OUTCOME_TEXT[o]}</div></td>
                <td className="small"><Coverage c={x.coverage} /></td>
                <td className="small nowrap">{fmt(x.queuedAt)}</td>
                <td className="small nowrap">{fmt(x.finishedAt)}</td>
                <td className="small nowrap"><Link href={`/assessments/${x.id}`}>Details →</Link></td>
              </tr>
            );
          })}
        </tbody></table>
      </TableWrap>
    </>
  );
}
