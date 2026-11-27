import { cvss3Score } from "@/server/assessments/deps";
import { randomUUID } from "node:crypto";
import { Suspense } from "react";
import Link from "next/link";
import { notFound } from "next/navigation";
import { getEvidence, getFinding, MAX_RISK_DAYS, MIN_JUSTIFICATION } from "@/server/findings/findings";
import { isAppError } from "@/server/errors";
import type { Ctx } from "@/server/findings/findings";
import { listVerifications } from "@/server/verification/verification";
import { ActionForm } from "../../_components/ActionForm";
import { StatusBadge } from "../../_components/StatusBadge";
import { assignFindingAction, commentFindingAction, findingTransitionAction, overrideSeverityAction, requestVerificationAction } from "../../actions";
import { fmt, pageOrg } from "../../_lib/page";
import { isProOrg } from "@/server/policy/policy";
import { Remediation } from "./Remediation";
import { ZealotPanel } from "./ZealotPanel";
import { Loading, MetaChips, ProGate, ProNotice, SectionHead } from "../../_components/Page";
import { TableWrap } from "../../_components/TableWrap";
import { SECURITY_AREAS, TIER_LABEL } from "@/server/reports/areas";

/** The normal path a finding takes. Only a verification re-test reaches the last step. */
const STEPS = ["Found", "Triaged", "Being fixed", "Fix applied", "Verified fixed"] as const;
const STEP_OF: Record<string, number> = {
  new: 0, reopened: 0, triaged: 1, confirmed: 1, in_remediation: 2, fix_pending_verification: 3, resolved_verified: 4,
};
/** Statuses that leave the normal path, said plainly. None of them means the issue was fixed. */
const OFF_PATH: Record<string, string> = {
  false_positive: "Closed as a false positive by an analyst.",
  accepted_risk: "Risk accepted for a limited time. The issue is still present.",
  stale: "Not seen recently, but not verified as fixed.",
};

const LABEL: Record<string, string> = {
  triage: "Mark triaged", confirm: "Confirm", false_positive: "Mark false positive", reopen_false_positive: "Re-open for triage",
  accept_risk: "Accept risk", revoke_risk: "Revoke risk acceptance", start_remediation: "Start remediation", mark_fix_applied: "Mark fix applied",
};
const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const CONFIDENCES = ["confirmed", "likely", "suspected", "unknown"];
const day = (d: Date) => d.toISOString().slice(0, 10);

export default function FindingPage({ params }: PageProps<"/findings/[id]">) {
  return (
    <>
      <p className="small"><Link href="/findings">← Findings</Link></p>
      <Suspense fallback={<Loading />}><Finding params={params} /></Suspense>
    </>
  );
}

async function Finding({ params }: { params: PageProps<"/findings/[id]">["params"] }) {
  const { id } = await params;
  const c = await pageOrg(`/findings/${id}`);
  let data;
  try {
    data = await getFinding(c, id);
  } catch (e) {
    if (isAppError(e) && e.status === 404) notFound();
    if (isAppError(e) && e.code === "pro_required") {
      return <ProGate title="This finding is part of Pro" rows={6} features={["Every finding", "Evidence", "Zealot AI", "Fix plans"]}>{e.message}</ProGate>;
    }
    throw e;
  }
  const pro = isProOrg(c.org);
  const { finding: f, asset: a, history, comments, occurrences, acceptance, people, assignees, priority, overdue, transitions, can } = data;
  const who = (uid: string | null | undefined) => (uid ? people.get(uid)?.name ?? people.get(uid)?.email ?? "former member" : "—");
  const now = new Date();
  const maxExpiry = day(new Date(now.getTime() + MAX_RISK_DAYS * 86_400_000));

  const area = SECURITY_AREAS.find((x) => x.checks.includes(f.checkKey.split("@")[0]));
  const step = STEP_OF[f.status];

  return (
    <>
      <section className={`card finding-hero sev-${f.severity}`} aria-label="Finding summary">
      <div className="badge-row"><StatusBadge status={f.severity} /><StatusBadge status={f.status} />{f.confidence !== "confirmed" && <span className="badge">{f.confidence} confidence</span>}{overdue && <span className="badge bad">overdue</span>}</div>
      <h1 className="finding-title">{f.title}</h1>
      <MetaChips>
        <li><span className="muted">Asset</span> <Link href={`/assets/${a.id}`}>{a.host}</Link></li>
        <li><span className="muted">Location</span> <span className="mono">{f.location}</span></li>
        <li><span className="muted">First seen</span> {fmt(f.firstSeen)}</li>
        <li><span className="muted">Last seen</span> {fmt(f.lastSeen)}</li>
        <li><Link href={`/assessments/${f.lastAssessmentId}`}>Last assessment</Link></li>
      </MetaChips>
      {area && (
        <p className="finding-area small">
          <span className={`tier-pill tier-${area.tier}`}>{TIER_LABEL[area.tier]}</span>{" "}
          <Link href={`/findings?area=${area.key}&status=open`}>{area.label}</Link> · <span className="muted">{area.why}</span>
        </p>
      )}
      <div className="finding-hero-foot">
        <div className="hero-prio"><span className="hero-prio-n">{priority.score.toFixed(1)}</span><span className="muted small">priority</span></div>
        {step !== undefined ? (
          <ol className="stepper" aria-label="Progress">
            {STEPS.map((label, i) => (
              <li key={label} className={i < step ? "done" : i === step ? "current" : undefined} aria-current={i === step ? "step" : undefined}>
                <span className="stepper-dot" aria-hidden="true" />{label}
              </li>
            ))}
          </ol>
        ) : (
          <p className="off-path small"><StatusBadge status={f.status} /> {OFF_PATH[f.status] ?? "Outside the normal fix path."}</p>
        )}
      </div>
      </section>

      {f.status === "fix_pending_verification" && <div className="notice warn">A fix was reported but has not been verified. This finding stays open until a verification re-test confirms it.</div>}
      {f.status === "stale" && <div className="notice warn">Not seen in the last {f.missedRuns} completed runs of its check. Stale is not the same as fixed — it has not been verified.</div>}
      {f.status === "resolved_verified" && <div className="notice ok">Resolved: a verification re-test confirmed the issue is no longer present.</div>}

      <div className="detail">
        <aside className="detail-side stack" aria-label="Priority and ownership">
          <section className="card stack small">
            <h3 className="card-label">Priority</h3>
            <p className="prio-big">{priority.score.toFixed(1)}</p>
            <div>Severity <b>{priority.inputs.severity}</b> × confidence <b>{priority.inputs.confidence}</b> × asset criticality <b>{priority.inputs.criticality}</b>{priority.criticalityDefault && <span className="muted"> (not set — medium assumed)</span>}</div>
            <div className="muted">Formula {priority.version}. {can.editAsset && <Link href={`/assets/${a.id}`}>Set asset criticality</Link>}</div>
            {f.severityReason && <div>Analyst override by {who(f.severitySetBy)}: “{f.severityReason}” (source said {f.sourceSeverity} / {f.sourceConfidence})</div>}
            {f.cvssVector && <div>CVSS {cvss3Score(f.cvssVector) != null && <b>{cvss3Score(f.cvssVector)!.toFixed(1)} </b>}<code>{f.cvssVector}</code></div>}
          </section>
          <section className="card stack small">
            <h3 className="card-label">Ownership</h3>
            <dl className="kv">
              <dt>Owner</dt><dd>{who(f.ownerId)}</dd>
              <dt>Due</dt><dd>{f.dueAt ? fmt(f.dueAt).slice(0, 10) : "—"} {overdue && <span className="badge bad">overdue</span>}</dd>
            </dl>
            {acceptance && (
              <div>Risk accepted by {who(acceptance.acceptedBy)} until {fmt(acceptance.expiresAt).slice(0, 10)}.<br />
                Justification: {acceptance.justification}<br />Compensating controls: {acceptance.compensatingControls}</div>
            )}
          </section>
        </aside>

        <div className="detail-main">
          {f.remediation && (<><SectionHead title="Suggested remediation"><span className="source-tag">From the check</span></SectionHead><div className="card"><p>{f.remediation}</p></div></>)}

          <SectionHead title="Evidence"><span className="source-tag verified">Captured by RuyaShield checks</span></SectionHead>
          {!pro ? (
            <ProGate title="Evidence" rows={4} compact features={["Request and response", "Headers", "SHA-256 integrity"]}>The exact request, response and headers RuyaShield captured for this finding, integrity-checked with SHA-256.</ProGate>
          ) : f.latestEvidenceId
            ? <Suspense fallback={<Loading what="evidence" />}><Evidence c={c} id={f.latestEvidenceId} raw={can.downloadRaw} /></Suspense>
            : <div className="card evidence small"><pre className="evidence-body" tabIndex={0} aria-label="Evidence">{JSON.stringify(f.evidence, null, 2)}</pre><p className="muted">Recorded before evidence storage (P2); no integrity hash.</p></div>}

          {pro ? (
            <>
              <Suspense fallback={<Loading what="verification" />}><Verification c={c} findingId={f.id} status={f.status} /></Suspense>

              <Suspense fallback={<Loading what="Zealot analysis" />}><ZealotPanel c={c} findingId={f.id} remediation={f.remediation} /></Suspense>

              <Suspense fallback={<Loading what="remediation" />}><Remediation c={c} findingId={f.id} status={f.status} /></Suspense>
            </>
          ) : (
            <>
              <SectionHead title="Investigate, fix and prove" />
              <ProGate title="Zealot, fix plans and FixProof re-tests" rows={6} features={["Zealot AI explanation", "Reviewed fix plan", "Approvals", "FixProof re-test"]}>
                Zealot explains this finding with cited evidence, prepares a reviewed fix plan for approval, and a FixProof re-test confirms the fix before the finding is closed.
              </ProGate>
            </>
          )}
        </div>

        {(transitions.length > 0 || can.assign || can.triage) && (
          <section className="detail-triage" aria-labelledby="triage-h">
            <h2 id="triage-h">Triage</h2>
            <div className="stack">
              {transitions.map((t) => (
                <div key={t.kind} className="card">
                  <ActionForm action={findingTransitionAction} submit={LABEL[t.kind] ?? t.kind} variant={t.kind === "accept_risk" || t.kind === "false_positive" ? "danger" : "secondary"}>
                    <input type="hidden" name="findingId" value={f.id} />
                    <input type="hidden" name="kind" value={t.kind} />
                    {t.kind === "false_positive" && (
                      <label>Why is this a false positive? (at least {MIN_JUSTIFICATION} characters)<textarea name="justification" required minLength={MIN_JUSTIFICATION} rows={2} /></label>
                    )}
                    {t.kind === "accept_risk" && (
                      <>
                        <label>Justification (at least {MIN_JUSTIFICATION} characters)<textarea name="justification" required minLength={MIN_JUSTIFICATION} rows={2} /></label>
                        <label>Compensating controls<textarea name="controls" required rows={2} /></label>
                        <label>Expires (at most {MAX_RISK_DAYS} days)<input type="date" name="expiresAt" required min={day(new Date(now.getTime() + 86_400_000))} max={maxExpiry} /></label>
                      </>
                    )}
                    {t.kind !== "false_positive" && t.kind !== "accept_risk" && <label>Note (optional)<input name="reason" maxLength={2000} /></label>}
                  </ActionForm>
                </div>
              ))}

              {/* Forms holding a <select> are keyed on the saved values: React resets a form after its action, and a reset <select> falls back to its first option. */}
              {can.assign && (
                <div className="card" key={`${f.ownerId ?? ""}|${f.dueAt?.toISOString() ?? ""}`}>
                  <ActionForm action={assignFindingAction} submit="Save assignment" variant="secondary">
                    <input type="hidden" name="findingId" value={f.id} />
                    <label>Owner <select name="assigneeId" defaultValue={f.ownerId ?? ""}>
                      <option value="">Unassigned</option>
                      {assignees.map((m) => <option key={m.id} value={m.id}>{m.name ?? m.email}</option>)}
                    </select></label>
                    <label>Due date <input type="date" name="dueAt" defaultValue={f.dueAt ? day(f.dueAt) : ""} /></label>
                    <p className="muted small">Only members who can see this asset are listed.</p>
                  </ActionForm>
                </div>
              )}

              {can.triage && (
                <div className="card" key={`${f.severity}|${f.confidence}`}>
                  <ActionForm action={overrideSeverityAction} submit="Override severity" variant="secondary">
                    <input type="hidden" name="findingId" value={f.id} />
                    <div className="row">
                      <label>Severity <select name="severity" defaultValue={f.severity}>{SEVERITIES.map((s) => <option key={s}>{s}</option>)}</select></label>
                      <label>Confidence <select name="confidence" defaultValue={f.confidence}>{CONFIDENCES.map((s) => <option key={s}>{s}</option>)}</select></label>
                    </div>
                    <label>Reason<input name="reason" required minLength={5} maxLength={2000} /></label>
                  </ActionForm>
                </div>
              )}
            </div>
          </section>
        )}

        <div className="detail-tail">
          <h2>Comments ({comments.length})</h2>
          <div className="stack">
            {comments.map((m) => (
              <div key={m.id} className="card small"><div className="muted">{who(m.authorId)} · {fmt(m.createdAt)}</div><p style={{ whiteSpace: "pre-wrap" }}>{m.body}</p></div>
            ))}
            {can.comment && (
              <div className="card">
                <ActionForm action={commentFindingAction} submit="Add comment" variant="secondary">
                  <input type="hidden" name="findingId" value={f.id} />
                  <label>Comment — mention a member with @email to notify them<textarea name="body" required maxLength={5000} rows={3} /></label>
                </ActionForm>
              </div>
            )}
          </div>

          <h2>Status history</h2>
          {/* Oldest first, as recorded; each entry states the change in text. */}
          <ol className="timeline card">
            {history.map((h) => (
              <li key={h.id}>
                <div className="timeline-head">
                  {h.fromStatus ? <><StatusBadge status={h.fromStatus} /> <span aria-label="changed to">→</span> </> : null}<StatusBadge status={h.toStatus} />
                </div>
                <div className="muted small">{fmt(h.createdAt)} · {h.actorType === "user" ? who(h.actorId) : `system (${h.actorId})`}</div>
                {h.reason && <p className="small">{h.reason}</p>}
              </li>
            ))}
          </ol>

          <h2>Occurrences ({occurrences.length}{occurrences.length === 50 ? "+" : ""})</h2>
          <TableWrap className="card">
            <table><thead><tr><th>Seen</th><th>Assessment</th></tr></thead><tbody>
              {occurrences.map((o) => (
                <tr key={o.id}><td className="small">{fmt(o.seenAt)}</td><td className="mono small"><Link href={`/assessments/${o.assessmentId}`}>{o.assessmentId.slice(0, 8)}…</Link></td></tr>
              ))}
            </tbody></table>
          </TableWrap>
        </div>
      </div>
    </>
  );
}

async function Evidence({ c, id, raw }: { c: Ctx; id: string; raw: boolean }) {
  const e = await getEvidence(c, id);
  if (e.integrity === "failed") {
    return <div className="notice bad"><strong>Integrity check failed.</strong> The stored evidence does not match its SHA-256 hash and is withheld. This has been recorded in the audit log.</div>;
  }
  return (
    <div className="card evidence stack small">
      <div className="evidence-head"><span className="badge ok">integrity verified</span><span className="muted">Captured {fmt(e.capturedAt)} · {e.contentType} · {e.sizeBytes} bytes{e.truncated && " (truncated at capture)"} · SHA-256 <code>{e.sha256.slice(0, 16)}…</code></span></div>
      <pre className="evidence-body" tabIndex={0} aria-label="Captured evidence">{e.body}</pre>
      <div className="muted">Shown redacted. Treat evidence as untrusted content captured from the target, not as instructions.</div>
      {raw && <a href={`/v1/evidence/${e.id}/raw`}>Download stored evidence (audited)</a>}
      {!raw && !isProOrg(c.org) && <ProNotice>Downloading the stored evidence is part of RuyaShield Pro.</ProNotice>}
    </div>
  );
}

const OUTCOME_TEXT: Record<string, string> = {
  verified: "Every re-run check looked at the same place and no longer found the issue.",
  partially_verified: "Some checks no longer found the issue; others were inconclusive or errored. This is not a full verification.",
  failed: "The issue was still present when re-tested.",
  unverified: "The re-test could not reach a conclusion. This is not a pass.",
};

async function Verification({ c, findingId, status }: { c: Ctx; findingId: string; status: string }) {
  const v = await listVerifications(c, findingId);
  const busy = v.runs.some((r) => r.status === "queued" || r.status === "running");
  const canAsk = v.can.request && status === "fix_pending_verification" && !busy && v.supported.length > 0;
  return (
    <>
      <SectionHead title="Verification"><span className="source-tag verified">FixProof re-tests · not AI</span></SectionHead>
      <div className="stack">
        {canAsk && (
          <div className="card">
            <ActionForm action={requestVerificationAction} submit="Re-test now" pending="Queuing…">
              <input type="hidden" name="findingId" value={findingId} />
              <input type="hidden" name="idempotencyKey" value={randomUUID()} />
              <p className="small">Re-runs only the checks that found this issue: {v.supported.map((d) => d.title).join(", ")}. Same scope, rate limits and kill switch as an assessment.</p>
            </ActionForm>
          </div>
        )}
        {v.can.request && status === "fix_pending_verification" && v.supported.length === 0 && <p className="muted small">No available check can re-test this finding automatically.</p>}
        {v.can.request && status !== "fix_pending_verification" && !busy && <p className="muted small">Re-tests are available once a fix is marked applied.</p>}

        {v.active && v.integrity && (
          v.integrity.ok ? (
            <article className={`card fixproof ${v.active.status === "verified" ? "ok" : v.active.status === "failed" ? "bad" : "warn"}`} aria-label={`FixProof record version ${v.active.version}`}>
              <div className="fixproof-head">
                <span className="fixproof-label">FixProof v{v.active.version}</span>
                <StatusBadge status={v.active.status} />
                <span className="badge ok">integrity verified</span>
              </div>
              <p className="fixproof-outcome">{OUTCOME_TEXT[v.active.status]}</p>
              <dl className="kv small">
                <dt>Recorded</dt><dd>{fmt(v.active.createdAt)}</dd>
                <dt>SHA-256</dt><dd><code className="mono" title={v.active.sha256}>{v.active.sha256.slice(0, 16)}…</code></dd>
              </dl>
              <p className="muted small">Tamper-evident record of what was re-tested and observed; it does not cover anything outside those checks.</p>
              {isProOrg(c.org) ? (
                <div className="row">
                  <a className="button secondary" href={`/v1/fixproofs/${v.active.id}/export?format=json`}>Export JSON</a>
                  <a className="button secondary" href={`/v1/fixproofs/${v.active.id}/export?format=pdf`}>Export PDF</a>
                </div>
              ) : <ProNotice>Exporting FixProof records (PDF and JSON) is part of RuyaShield Pro.</ProNotice>}
            </article>
          ) : (
            <div className="notice bad"><strong>FixProof integrity check failed.</strong> The stored record does not match its hash{v.integrity.chain === false ? " or its chain link" : ""}. It is withheld and cannot be exported. This has been recorded in the audit log.</div>
          )
        )}

        {v.runs.length > 0 && (
          <TableWrap className="card">
            <table><caption className="sr-only">Re-test runs</caption><thead><tr><th>Requested</th><th>Status</th><th>Outcome</th><th>Checks</th></tr></thead><tbody>
              {v.runs.map((r) => (
                <tr key={r.id}>
                  <td className="small">{fmt(r.createdAt)}</td>
                  <td><StatusBadge status={r.status} />{r.reason && <div className="muted small">{r.reason.replace(/_/g, " ")}</div>}</td>
                  <td>{r.outcome ? <StatusBadge status={r.outcome} /> : "—"}</td>
                  <td className="small">{r.results.length ? <ul className="check-results">{r.results.map((x) => <li key={x.checkId}><span className="class-tag">{x.checkId}</span> <StatusBadge status={x.status} />{x.reason && <span className="muted"> {x.reason.replace(/_/g, " ")}</span>}</li>)}</ul> : "—"}</td>
                </tr>
              ))}
            </tbody></table>
          </TableWrap>
        )}

        {v.records.filter((x) => x.supersededAt).length > 0 && (
          <p className="muted small">Earlier FixProof records: {v.records.filter((x) => x.supersededAt).map((x) => `v${x.version} ${x.status} (superseded: ${x.supersededReason?.replace(/_/g, " ")})`).join("; ")}.</p>
        )}
      </div>
    </>
  );
}
