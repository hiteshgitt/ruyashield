import { Suspense } from "react";
import Link from "next/link";
import { securitySummary, needsOnboarding, type SecuritySummary } from "@/server/reports/summary";
import { dashboardInsights, SCORE_WEIGHTS, TREND_WEEKS, type DashboardInsights } from "@/server/reports/insights";
import { listClientGroups } from "@/server/orgs/orgs";
import { grantFor } from "@/server/policy/matrix";
import { isAppError } from "@/server/errors";
import { StatusBadge } from "../_components/StatusBadge";
import { Meter } from "../_components/Meter";
import { messageFor } from "../_lib/messages";
import { fmt, pageOrg } from "../_lib/page";
import { Empty, Loading, PageHeader, ProGate } from "../_components/Page";
import { TableWrap } from "../_components/TableWrap";
import { AreaBoard, AssetMap, ScoreGauge, SeverityDonut, StatCard, TrendChart } from "../_components/Charts";
import { nextStep, type NextStep } from "@/server/reports/nextStep";
import { Icon } from "../_components/Icon";
import { webmonitorCoverage, webmonitorAddSiteUrl, webmonitorUrl, type WebMonitorCoverage } from "@/server/webmonitor/watch";
import { log } from "@/server/log";
import { isProOrg } from "@/server/policy/policy";

export default function DashboardPage({ searchParams }: PageProps<"/dashboard">) {
  return (
    <>
      <PageHeader title="Security overview" lead="Counts come from recorded assessments and verification re-tests only. Checks that failed, timed out or did not run are listed below, never counted as passed." />
      <Suspense fallback={<Loading />}><Dashboard searchParams={searchParams} /></Suspense>
    </>
  );
}

async function Dashboard({ searchParams }: { searchParams: PageProps<"/dashboard">["searchParams"] }) {
  const sp = await searchParams;
  const groupId = typeof sp.clientGroupId === "string" ? sp.clientGroupId : "";
  const c = await pageOrg("/dashboard");
  let s: SecuritySummary;
  let ins: DashboardInsights;
  try {
    s = await securitySummary(c, { clientGroupId: groupId || null });
    ins = await dashboardInsights(c, { clientGroupId: groupId || null });
  } catch (e) {
    if (isAppError(e) && e.status < 500) return <div className="notice bad">{messageFor(e.code, e.message)}</div>;
    throw e;
  }
  const groups = await listClientGroups(c);
  // Uptime coverage is a side panel: if it fails, the security overview still renders.
  const coverage = await webmonitorCoverage(c).catch((e) => { log.error("dashboard.webmonitor", { error: e instanceof Error ? e.message : String(e) }); return null; });
  const canConnect = grantFor(c.principal.role, "token.manage") !== "N";
  const canReport = grantFor(c.principal.role, "report.generate") !== "N" && isProOrg(c.org);
  const days = s.windowDays;
  const sev = s.findings.open;
  const a = s.assessments;
  // total counts every assessment queued in the window; anything not completed/failed is still queued, running or cancelled.
  const otherAssessments = Math.max(0, a.total - a.completed - a.completedWithErrors - a.failed);

  return (
    <>
      <form method="get" className="card toolbar small">
        <label>Client group <select name="clientGroupId" defaultValue={groupId}>
          {!s.scope.restrictedToGroups && <option value="">All assets</option>}
          {s.scope.restrictedToGroups && <option value="">All my client groups</option>}
          {groups.map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}
        </select></label>
        <button type="submit" className="secondary">Apply</button>
        {canReport && <Link className="button secondary toolbar-end" href={`/reports${groupId ? `?clientGroupId=${groupId}` : ""}`}>Generate a report →</Link>}
      </form>

      {needsOnboarding(s) && <Onboarding s={s} />}

      {s.findings.untriagedCritical > 0 && (
        <div className="notice bad">Warning: {s.findings.untriagedCritical} critical finding{s.findings.untriagedCritical === 1 ? "" : "s"} not yet triaged. <Link href="/findings?status=new&severity=critical">Review</Link></div>
      )}
      {(s.verification.failed + s.verification.partiallyVerified + s.verification.unverified + s.verification.notRun) > 0 && (
        <div className="notice warn">Warning: {s.verification.failed} verification re-test{s.verification.failed === 1 ? "" : "s"} failed, {s.verification.partiallyVerified} partially verified and {s.verification.unverified + s.verification.notRun} inconclusive or not run in the last {days} days. These fixes are not confirmed.</div>
      )}
      {s.incompleteAssessments.length > 0 && (
        <div className="notice warn">Warning: {s.incompleteAssessments.length} assessment{s.incompleteAssessments.length === 1 ? "" : "s"} in the last {days} days did not complete every check. Coverage for those assets is partial.</div>
      )}

      <div className="dash-hero">
        <section className="card panel score-card" aria-labelledby="score-h">
          <h3 id="score-h">Exposure score</h3>
          <ScoreGauge score={ins.score} />
          {ins.score ? (
            <p className="small muted">
              {ins.score.value}/100 across {ins.score.assessedAssets} assessed asset{ins.score.assessedAssets === 1 ? "" : "s"}.
              Each open finding lowers it (critical {SCORE_WEIGHTS.critical}, high {SCORE_WEIGHTS.high}, medium {SCORE_WEIGHTS.medium}, low {SCORE_WEIGHTS.low} points, averaged per asset).
              It only reflects the checks that ran.
            </p>
          ) : <p className="small muted">A score appears once at least one asset has a completed assessment. No data is never shown as a perfect score.</p>}
        </section>

        <section className="card panel" aria-labelledby="sev-h">
          <h3 id="sev-h">Open findings by severity</h3>
          {s.findings.openTotal === 0
            ? <Empty>{needsOnboarding(s) ? "No assessment results yet." : "No open findings in the assessed scope."}</Empty>
            : <SeverityDonut open={sev} total={s.findings.openTotal} />}
        </section>

        <NextStepCard step={nextStep(s, ins.areas)} />
      </div>

      <section className="stats" aria-label="Key figures">
        <StatCard icon="findings" label="Open findings" value={s.findings.openTotal} href="/findings"
          tone={sev.critical + sev.high > 0 ? "bad" : s.findings.openTotal > 0 ? "warn" : "ok"}
          sub={s.findings.overdue > 0 ? <span className="badge bad">{s.findings.overdue} past due date</span> : "0 past due date"} />
        <StatCard icon="assets" label="Assets" value={s.assets.total} href="/assets"
          sub={`${s.assets.verified} verified · ${s.assets.unverified} unverified · ${s.assets.lapsedOrRevoked} lapsed or revoked`} />
        <StatCard icon="shield" label="Fixed and re-tested" value={s.findings.resolvedVerifiedInWindow} tone="ok"
          sub={`Last ${days} days. Only counted when a re-test confirmed the fix.`} />
        <StatCard icon="clock" label={`Assessments (last ${days} days)`} value={a.total} href="/assessments"
          sub={`Last completed: ${fmt(a.lastCompletedAt)}`} />
      </section>

      {!isProOrg(c.org) && (
        <ProGate title="Trends, asset map and attack monitoring" rows={5} features={["Weekly trend of found and fixed", "Asset map, riskiest first", "Attack origins", "Reports"]}>
          See how findings open and close week by week, every asset on one map, and where hostile traffic comes from.
        </ProGate>
      )}

      <section className="card panel areas-panel" aria-labelledby="areas-h">
        <h3 id="areas-h">What we check, most important first</h3>
        <p className="small muted">Each area links to its open findings. &quot;Not run yet&quot; means no result yet, which is not a pass. &quot;Not scanned by RuyaShield yet&quot; means we do not cover that area today.</p>
        <AreaBoard areas={ins.areas} />
      </section>

      {coverage && coverage.assets.length > 0 && <UptimeCard coverage={coverage} canConnect={canConnect} />}

      {isProOrg(c.org) && (
      <div className="dash-wide">
        <section className="card panel" aria-labelledby="trend-h">
          <h3 id="trend-h">Findings over the last {TREND_WEEKS} weeks</h3>
          <ul className="legend small"><li className="bad">found <strong>{ins.trend.reduce((t, w) => t + w.opened, 0)}</strong></li><li className="ok">fixed and re-tested <strong>{ins.trend.reduce((t, w) => t + w.resolved, 0)}</strong></li></ul>
          <TrendChart weeks={ins.trend} />
          <p className="small muted">Hover a week for its counts. &quot;Fixed&quot; only includes findings closed by a passing verification re-test.</p>
        </section>

        <section className="card panel" aria-labelledby="map-h">
          <h3 id="map-h">Asset map <span className="muted small">{ins.assets.length} shown, riskiest first</span></h3>
          {ins.assets.length === 0 ? <Empty>No assets yet. <Link href="/assets">Add one</Link>.</Empty> : <AssetMap tiles={ins.assets} />}
          <ul className="legend small map-key">
            <li className="sev-critical">critical</li><li className="sev-high">high</li><li className="sev-medium">medium</li><li className="sev-low">low / info</li>
            <li className="ok">no open findings</li><li className="none">not assessed or not verified</li>
          </ul>
        </section>
      </div>
      )}

      <div className="panels panels-2">
        <section className="card panel">
          <h3>Verification re-tests (last {days} days)</h3>
          <Meter empty={`No re-tests in the last ${days} days.`} segments={[
            { label: "verified", count: s.verification.verified, tone: "ok" },
            { label: "partially verified", count: s.verification.partiallyVerified, tone: "warn" },
            { label: "failed", count: s.verification.failed, tone: "bad" },
            { label: "inconclusive", count: s.verification.unverified, tone: "warn-soft" },
            { label: "not run", count: s.verification.notRun, tone: "none" },
          ]} />
          <p className="muted small">Only &quot;verified&quot; confirms a fix.</p>
        </section>
        <section className="card panel">
          <h3>Assessment outcomes (last {days} days)</h3>
          <Meter empty={`No assessments in the last ${days} days.`} segments={[
            { label: "completed", count: a.completed, tone: "ok" },
            { label: "completed with errors", count: a.completedWithErrors, tone: "warn" },
            { label: "failed, timed out or rejected", count: a.failed, tone: "bad" },
            ...(otherAssessments > 0 ? [{ label: "queued, running or cancelled", count: otherAssessments, tone: "none" }] : []),
          ]} />
        </section>
      </div>

      <h2>Highest-priority open findings</h2>
      {s.topOpen.length === 0 ? <Empty>{needsOnboarding(s) ? "No assessment results yet." : "No open findings in the assessed scope. This reflects the checks that ran, not a guarantee that no issues exist."}</Empty> : (
        <TableWrap><table><thead><tr><th>Finding</th><th>Severity</th><th>Status</th><th>Asset</th><th>Due</th></tr></thead><tbody>
          {s.topOpen.map((f) => <tr key={f.id}><td><Link href={`/findings/${f.id}`}>{f.title}</Link></td><td><StatusBadge status={f.severity} /></td><td><StatusBadge status={f.status} /></td><td className="mono small">{f.host}</td><td className="small">{fmt(f.dueAt)}</td></tr>)}
        </tbody></table></TableWrap>
      )}

      {s.failedVerifications.length > 0 && <>
        <h2 id="failed-retests">Verification re-tests that did not pass</h2>
        <TableWrap><table><thead><tr><th>Finding</th><th>Asset</th><th>Outcome</th><th>Finished</th></tr></thead><tbody>
          {s.failedVerifications.map((v, i) => <tr key={i}><td><Link href={`/findings/${v.findingId}`}>{v.title}</Link></td><td className="mono small">{v.host}</td><td><StatusBadge status={v.outcome} /></td><td className="small">{fmt(v.finishedAt)}</td></tr>)}
        </tbody></table></TableWrap>
      </>}

      {s.incompleteAssessments.length > 0 && <>
        <h2>Incomplete assessments</h2>
        <TableWrap><table><thead><tr><th>Asset</th><th>Status</th><th>Checks</th><th>Reason</th><th>Finished</th></tr></thead><tbody>
          {s.incompleteAssessments.map((a) => <tr key={a.id}><td><Link href={`/assessments/${a.id}`}>{a.host}</Link></td><td><StatusBadge status={a.status} /></td>
            <td className="small">{a.coverage ? `${a.coverage.ok}/${a.coverage.planned} ok · ${a.coverage.error} error · ${a.coverage.timeout} timeout · ${a.coverage.skipped} skipped` : "—"}</td>
            <td className="small">{a.reason ?? "—"}</td><td className="small">{fmt(a.finishedAt)}</td></tr>)}
        </tbody></table></TableWrap>
      </>}

      <h2>Accepted risks</h2>
      {s.acceptedRisks.length === 0 ? <p className="muted small">No active risk acceptances.</p> : (
        <TableWrap><table><thead><tr><th>Finding</th><th>Severity</th><th>Asset</th><th>Justification</th><th>Expires</th></tr></thead><tbody>
          {s.acceptedRisks.map((r) => <tr key={r.findingId}><td><Link href={`/findings/${r.findingId}`}>{r.title}</Link></td><td><StatusBadge status={r.severity} /></td><td className="mono small">{r.host}</td><td className="small">{r.justification}</td><td className="small">{fmt(r.expiresAt)}</td></tr>)}
        </tbody></table></TableWrap>
      )}
      <p className="muted small footnote">Generated {fmt(s.generatedAt)}. RuyaShield results are not a certification or a compliance attestation.</p>
    </>
  );
}

function Onboarding({ s }: { s: SecuritySummary }) {
  const steps: [boolean, string, string][] = [
    [s.onboarding.hasAsset, "Add an asset you own or are authorized to test", "/assets"],
    [s.onboarding.hasVerifiedAsset, "Verify ownership of the asset (DNS or file)", "/assets"],
    [s.onboarding.hasAssessment, "Run a first assessment", "/assessments"],
    [s.onboarding.hasCompletedAssessment, "Review the completed assessment results", "/assessments"],
    [s.onboarding.hasTeammate, "Invite a teammate (optional)", "/settings/members"],
  ];
  const done = steps.filter(([d]) => d).length;
  return (
    <div className="card onboarding"><h3>Get started <span className="muted small">{done} of {steps.length} done</span></h3>
      <div className="progress" aria-hidden="true"><span style={{ width: `${(done / steps.length) * 100}%` }} /></div>
      <p className="small muted">There are no assessment results to summarize yet, so nothing below should be read as &quot;all clear&quot;.</p>
      <ol className="steps small">{steps.map(([d, label, href]) => <li key={label} className={d ? "done" : undefined}><span className={`badge${d ? " ok" : ""}`}>{d ? "Done" : "To do"}</span> <Link href={href}>{label}</Link></li>)}</ol>
    </div>
  );
}

function NextStepCard({ step }: { step: NextStep }) {
  return (
    <section className={`card panel next-step tone-${step.tone}`} aria-labelledby="next-h">
      <p className="next-kicker" id="next-h"><Icon name="shield" /> Your next step</p>
      <h3 className="next-title">{step.title}</h3>
      <p className="small next-detail">{step.detail}</p>
      <Link className="button" href={step.href}>{step.cta} →</Link>
    </section>
  );
}

const UPTIME_LIST = 5;

/** Which assets WebMonitor watches for uptime, with one-click links for the ones it does not. */
function UptimeCard({ coverage, canConnect }: { coverage: WebMonitorCoverage; canConnect: boolean }) {
  const total = coverage.assets.length;
  const unwatched = coverage.assets.filter((a) => !a.watched && a.status === "verified");
  const watched = coverage.assets.filter((a) => a.watched).length;
  const connected = !!coverage.lastSeenAt;
  return (
    <section className="card panel uptime-card" aria-labelledby="uptime-h">
      <div className="uptime-head">
        <div>
          <p className="next-kicker"><Icon name="monitor" /> Uptime, from WebMonitor</p>
          <h3 id="uptime-h">{connected ? `${watched} of ${total} site${total === 1 ? "" : "s"} watched for downtime` : "Know when a site goes down, not just when it is vulnerable"}</h3>
          <p className="small muted">
            {connected
              ? <>WebMonitor last checked in {fmt(coverage.lastSeenAt)}. It shows these findings next to uptime and alerts on new critical and high ones.</>
              : <>RuyaShield finds security issues; WebMonitor checks every minute that your sites are up and fast. Connected, each site&apos;s findings appear next to its uptime, with alerts on new critical and high issues.</>}
          </p>
        </div>
        {connected
          ? (canConnect && <Link className="button secondary" href="/settings/webmonitor">Manage →</Link>)
          : canConnect
            ? <Link className="button" href="/settings/webmonitor">Connect WebMonitor →</Link>
            : <a className="button secondary" href={webmonitorUrl("/")} target="_blank" rel="noopener noreferrer">About WebMonitor →</a>}
      </div>
      {connected && unwatched.length > 0 && (
        <ul className="uptime-list small">
          {unwatched.slice(0, UPTIME_LIST).map((a) => (
            <li key={a.id}><span className="mono">{a.host}</span><span className="badge warn">not watched</span><a href={webmonitorAddSiteUrl(a.host)} target="_blank" rel="noopener noreferrer">Watch in WebMonitor →</a></li>
          ))}
          {unwatched.length > UPTIME_LIST && canConnect && <li><Link href="/settings/webmonitor">{unwatched.length - UPTIME_LIST} more →</Link></li>}
        </ul>
      )}
      {coverage.notInRuyaShield.length > 0 && (
        <p className="small">
          {coverage.notInRuyaShield.length} site{coverage.notInRuyaShield.length === 1 ? " WebMonitor monitors is" : "s WebMonitor monitors are"} not scanned by RuyaShield yet
          {" "}(<span className="mono">{coverage.notInRuyaShield.slice(0, 3).join(", ")}{coverage.notInRuyaShield.length > 3 ? ", …" : ""}</span>).
          {" "}<Link href={`/assets?host=${encodeURIComponent(coverage.notInRuyaShield[0])}`}>Add {coverage.notInRuyaShield.length === 1 ? "it" : "the first"} →</Link>
        </p>
      )}
    </section>
  );
}
