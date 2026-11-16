import { randomUUID } from "node:crypto";
import { Suspense } from "react";
import Link from "next/link";
import { notFound } from "next/navigation";
import { grantFor } from "@/server/policy/matrix";
import { ACTIVE_STATUSES, getAssessment, isCleanResult } from "@/server/assessments/assessments";
import { isAppError } from "@/server/errors";
import { ActionForm } from "../../_components/ActionForm";
import { Coverage } from "../../_components/Coverage";
import { Meter } from "../../_components/Meter";
import { StatusBadge } from "../../_components/StatusBadge";
import { cancelAssessmentAction, rerunAssessmentAction } from "../../actions";
import { fmt, pageOrg } from "../../_lib/page";
import { Loading, MetaChips, ProGate } from "../../_components/Page";
import { TableWrap } from "../../_components/TableWrap";
import { AutoRefresh } from "../../_components/AutoRefresh";
import { SEVERITIES, StatCard } from "../../_components/Charts";
import { SECURITY_AREAS } from "@/server/reports/areas";

/** "tls.config@1" -> the security area that check reports under, if any. */
const areaOfCheck = (checkId: string) => SECURITY_AREAS.find((a) => a.checks.includes(checkId.split("@")[0]));
const SEV_RANK = Object.fromEntries(SEVERITIES.map((s, i) => [s, i])) as Record<string, number>;

function duration(from: Date | null, to: Date | null) {
  if (!from || !to) return null;
  const s = Math.max(0, Math.round((to.getTime() - from.getTime()) / 1000));
  return s < 90 ? `${s}s` : s < 5400 ? `${Math.round(s / 60)} min` : `${(s / 3600).toFixed(1)} h`;
}

const REASON: Record<string, string> = {
  cancelled_by_user: "Cancelled by a user.",
  kill_switch_engaged: "Stopped by a kill switch.",
  window_ended: "The approved testing window ended.",
  max_duration_reached: "The maximum duration was reached.",
  authorization_lapsed: "The asset's verification or authorization lapsed during the run.",
  no_check_succeeded: "No check completed successfully.",
  some_checks_failed: "Some checks did not complete. Results are partial.",
  lease_expired: "The worker stopped responding.",
  timeout: "Timed out.",
  no_adapter: "This check is not available in this engine version.",
  malformed_output: "The check produced output that failed validation and was discarded.",
};
const why = (r: string | null) => (r ? REASON[r] ?? r.replace(/_/g, " ") : "—");

export default function AssessmentPage({ params }: PageProps<"/assessments/[id]">) {
  return (
    <>
      <p className="small crumb"><Link href="/assessments">← Assessments</Link></p>
      <Suspense fallback={<Loading />}><Assessment params={params} /></Suspense>
    </>
  );
}

async function Assessment({ params }: { params: PageProps<"/assessments/[id]">["params"] }) {
  const { id } = await params;
  const c = await pageOrg(`/assessments/${id}`);
  let data;
  try {
    data = await getAssessment(c, id);
  } catch (e) {
    if (isAppError(e) && e.status === 404) notFound();
    throw e;
  }
  const { assessment: x, asset: a, scope, runs, findings, severities, lockedFindings, canFindings } = data;
  const active = ACTIVE_STATUSES.includes(x.status);
  const canCancel = active && x.status !== "cancelling" && grantFor(c.principal.role, "assessment.cancel") !== "N";
  const canRerun = !active && grantFor(c.principal.role, "assessment.launch") !== "N";
  const cov = x.coverage;

  const outcome = (st: string) => runs.filter(({ run }) => run.status === st).length;
  const okRuns = outcome("ok");
  const full = x.status === "completed" && !!cov?.complete && okRuns === runs.length && runs.length > 0;
  const used = runs.reduce((n, { run }) => n + run.requestsUsed, 0);
  const took = duration(x.startedAt, x.finishedAt);
  const sevCount = (sv: string) => severities.filter((s) => s === sv).length;
  const worst = findings.map(({ finding: f }) => f.severity).sort((p, q) => SEV_RANK[p] - SEV_RANK[q])[0];
  const sorted = [...findings].sort((p, q) => SEV_RANK[p.finding.severity] - SEV_RANK[q.finding.severity]);

  return (
    <>
      <div className="badge-row"><StatusBadge status={x.status} /></div>
      {active && <AutoRefresh />}
      <h1>Assessment of <Link href={`/assets/${a.id}`} className="mono">{a.host}</Link></h1>
      <MetaChips label="Run details">
        <li>Queued {fmt(x.queuedAt)}</li>
        <li>Started {fmt(x.startedAt)}</li>
        <li>Finished {fmt(x.finishedAt)}</li>
        <li>Engine {x.engineVersion ?? "—"}</li>
      </MetaChips>

      <div className="stats">
        <StatCard icon="check" label="Checks completed" tone={active ? "violet" : full ? "ok" : okRuns ? "warn" : "bad"}
          value={`${okRuns}/${runs.length}`} sub={active ? "Still running" : full ? "Every planned check ran" : "Partial: see the notes below"} />
        <StatCard icon="findings" label="Findings" value={canFindings ? findings.length : "—"}
          tone={!canFindings ? "violet" : worst === "critical" || worst === "high" ? "bad" : findings.length ? "warn" : full ? "ok" : "warn"}
          sub={!canFindings ? "Your role cannot view findings" : findings.length ? `Worst: ${worst}` : full ? "None from the checks that ran" : "None so far, but the run is incomplete"} />
        <StatCard icon="target" label="Requests sent" value={used} sub={scope ? `Budget: up to ${scope.maxRequests}` : "Within the approved scope"} />
        <StatCard icon="clock" label="Duration" value={took ?? "—"} sub={x.finishedAt ? `Finished ${fmt(x.finishedAt)}` : active ? "Not finished yet" : "No finish time recorded"} />
      </div>

      <ResultNotice status={x.status} reason={x.reason} coverage={cov} findingCount={findings.length} canFindings={canFindings} />

      {canRerun && (
        <div className="toolbar card rerun-bar">
          <ActionForm action={rerunAssessmentAction} submit="Run again" pending="Queuing…" className="row">
            <input type="hidden" name="assessmentId" value={x.id} />
            <input type="hidden" name="idempotencyKey" value={randomUUID()} />
          </ActionForm>
          <span className="muted small">Runs a new assessment of {a.host} with every check allowed for it today, including any added since this run. To pick checks, use the <Link href={`/assets/${a.id}`}>asset page</Link>.</span>
        </div>
      )}

      {canCancel && (
        <div className="toolbar">
          <ActionForm action={cancelAssessmentAction} submit="Cancel assessment" variant="danger" className="row">
            <input type="hidden" name="assessmentId" value={x.id} />
          </ActionForm>
          <span className="muted small">Stops after the check in progress; nothing further is sent to the site.</span>
        </div>
      )}

      <div className="detail">
        <aside className="detail-side card" aria-labelledby="h-outcomes">
          <h2 id="h-outcomes" className="card-label">Check outcomes</h2>
          <Meter empty="No checks recorded for this run." segments={[
            { label: "ok", count: outcome("ok"), tone: "ok" },
            { label: "error", count: outcome("error"), tone: "bad" },
            { label: "timed out", count: outcome("timeout"), tone: "bad" },
            { label: "skipped", count: outcome("skipped"), tone: "none" },
            { label: "pending", count: outcome("pending"), tone: "warn-soft" },
          ]} />
          {cov && <p className="small"><Coverage c={cov} /></p>}
        </aside>

        <div className="detail-main">
          <h2>Checks</h2>
          <TableWrap className="card">
            <table><thead><tr><th>Check</th><th>Area</th><th>Class</th><th>Status</th><th>Requests</th><th>Note</th></tr></thead><tbody>
              {runs.map(({ run, def }) => (
                <tr key={run.id} className={`check-row check-${run.status}`}>
                  <td>{def?.title ?? run.checkId}<div className="muted small mono">{run.checkId}</div></td>
                  <td className="small">{areaOfCheck(run.checkId)?.label ?? <span className="muted">—</span>}</td>
                  <td>{def ? <span className="class-tag">{def.class}</span> : "—"}</td>
                  <td><StatusBadge status={run.status} /></td>
                  <td className="mono">{run.requestsUsed}</td>
                  <td className="small">{run.status === "ok" ? "—" : why(run.reason)}</td>
                </tr>
              ))}
            </tbody></table>
          </TableWrap>

          {canFindings && severities.length > 0 && (
            <>
              <h2>Findings ({severities.length})</h2>
              <div className="card panel">
                <Meter empty="No findings." segments={SEVERITIES.map((sv) => ({ label: sv, count: sevCount(sv), tone: `sev-${sv}` }))} />
              </div>
              <div className="stack">
                {sorted.map(({ finding: f }) => (
                  <div key={f.id} className={`card stack finding-card sev-${f.severity}`}>
                    <div className="badge-row"><StatusBadge status={f.severity} /><StatusBadge status={f.status} /></div>
                    <strong><Link href={`/findings/${f.id}`}>{f.title}</Link></strong>
                    <div className="small muted"><span className="mono">{f.location}</span> · first seen {fmt(f.firstSeen)}</div>
                    {f.remediation && <p>{f.remediation}</p>}
                  </div>
                ))}
              </div>
              {lockedFindings > 0 && (
                <ProGate title={`${lockedFindings} more finding${lockedFindings === 1 ? "" : "s"} from this assessment`} features={["Every finding", "Evidence", "Zealot explanations", "Fix plans"]}>
                  The Free plan shows your 5 highest-priority findings across all assets. The meter above counts everything this run found.
                </ProGate>
              )}
            </>
          )}
        </div>

        {scope && (
          <section className="detail-triage card" aria-labelledby="h-scope">
            <h2 id="h-scope" className="card-label">Approved scope · v{scope.version}</h2>
            <dl className="kv small">
              <dt>Hosts</dt><dd><code>{scope.hosts.join(", ")}</code></dd>
              <dt>Paths</dt><dd><code>{scope.basePaths.join(", ")}</code></dd>
              {scope.excludedPaths.length > 0 && <><dt>Excluded</dt><dd><code>{scope.excludedPaths.join(", ")}</code></dd></>}
              <dt>Classes</dt><dd>{scope.classes.join(", ")}</dd>
              <dt>Budget</dt><dd>up to {scope.maxRequests} requests · max {scope.maxDurationS}s</dd>
              <dt>Window</dt><dd>{fmt(scope.windowStart)} → {fmt(scope.windowEnd)}</dd>
            </dl>
            <p className="muted small">Scope hash <code>{x.scopeSha256.slice(0, 16)}…</code> — the worker refuses to run if the stored scope no longer matches it.</p>
          </section>
        )}
      </div>
    </>
  );
}

function ResultNotice(p: { status: string; reason: string | null; coverage: { ok: number; planned: number; complete: boolean } | null; findingCount: number; canFindings: boolean }) {
  const cov = p.coverage ? ` ${p.coverage.ok} of ${p.coverage.planned} checks completed.` : "";
  if (["queued", "running", "cancelling"].includes(p.status)) {
    return <div className="notice warn"><strong>In progress.</strong> No results yet; this page updates by itself when the run finishes.{cov}</div>;
  }
  if (isCleanResult({ status: p.status as never, coverage: p.coverage as never }, p.findingCount) && p.canFindings) {
    return <div className="notice ok"><strong>No issues found by the checks that ran.</strong> All {p.coverage?.planned} planned checks completed. This covers only the checks listed below, not the whole site.</div>;
  }
  if (p.status === "completed") {
    return <div className="notice ok"><strong>Completed.</strong> All planned checks ran.</div>;
  }
  // Partial, failed, cancelled or timed-out runs are never presented as clean.
  return <div className="notice bad"><strong>Incomplete result — not a clean bill of health.</strong> {why(p.reason)}{cov} Findings below are only from checks that completed.</div>;
}
