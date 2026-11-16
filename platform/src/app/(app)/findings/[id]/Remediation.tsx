import { randomUUID } from "node:crypto";
import Link from "next/link";
import type { Ctx } from "@/server/findings/findings";
import { getPlan, listPlansForFinding } from "@/server/remediation/plans";
import { listIntegrations } from "@/server/remediation/integrations";
import { sandboxAvailable } from "@/server/remediation/sandbox";
import { grantFor } from "@/server/policy/matrix";
import { ActionForm } from "../../_components/ActionForm";
import { StatusBadge } from "../../_components/StatusBadge";
import {
  createPlanAction, editPlanAction, markAppliedAction, requestApprovalAction, revokeApprovalAction, sandboxAction, submitPlanAction,
} from "../../actions";
import { fmt } from "../../_lib/page";
import { Empty, MetaChips, SectionHead } from "../../_components/Page";
import { TableWrap } from "../../_components/TableWrap";

const PLANNABLE = ["new", "triaged", "confirmed", "in_remediation", "reopened"];
const EDITABLE = ["draft", "proposed", "test_passed", "test_failed"];
const SANDBOXABLE = ["proposed", "test_failed", "test_passed"];
const APPROVABLE = ["proposed", "test_passed"];
const SHOWN = 5;

// Remediation plans (RS-REM-001..006). Nothing here changes customer systems by itself: patches are tested in an
// isolated sandbox, need a second person's approval, and are only opened as a change for the customer to merge.
// "Applied" never means "fixed"; only a passing re-test can close the finding.
export async function Remediation({ c, findingId, status }: { c: Ctx; findingId: string; status: string }) {
  const role = c.principal.role;
  const can = {
    edit: grantFor(role, "remediation.edit") !== "N",
    sandbox: grantFor(role, "remediation.sandbox") !== "N",
    request: grantFor(role, "remediation.request_approval") !== "N",
    applied: grantFor(role, "remediation.mark_applied") !== "N",
    decide: grantFor(role, "approval.decide") !== "N",
  };
  const rows = await listPlansForFinding(c, findingId);
  const [plans, integrations] = await Promise.all([
    Promise.all(rows.slice(0, SHOWN).map((p) => getPlan(c, p.id))),
    can.edit ? listIntegrations(c) : Promise.resolve([]),
  ]);
  const active = integrations.filter((i) => i.status === "active");
  const sandboxReady = sandboxAvailable();

  return (
    <>
      <SectionHead title="Remediation" />
      <p className="muted small">Applied is not fixed: a plan is only complete when a FixProof re-test passes.</p>
      <div className="stack">
        {plans.length === 0 && <Empty>No remediation plan yet.</Empty>}
        {rows.length > SHOWN && <p className="muted small">Showing the {SHOWN} most recent of {rows.length} plans.</p>}

        {plans.map(({ plan: p, sandboxRuns: runs, approvals, codeChanges, integration, history }) => {
          const pending = approvals.find((a) => a.state === "pending");
          const approved = approvals.find((a) => a.state === "approved");
          const lastRun = runs[0];
          return (
            <article key={p.id} className="card plan-card small" aria-label={`Remediation plan: ${p.title}`}>
              <div className="plan-head">
                <h3 className="plan-title">{p.title}</h3>
                <div className="plan-badges">
                  <StatusBadge status={p.state} /> <span className="chip">{p.type}</span>
                  {p.aiClaimId && <> <span className="badge warn">from AI recommendation</span></>}
                </div>
              </div>
              <MetaChips className="plan-meta">
                <li><span className="muted">Version</span> v{p.version}</li>
                <li><span className="muted">Updated</span> {fmt(p.updatedAt)}</li>
                <li><span className="muted">Content</span> <span className="mono">{p.contentSha256.slice(0, 12)}</span></li>
              </MetaChips>
              <Lifecycle type={p.type} state={p.state} />
              <p className="plan-desc">{p.description}</p>
              {(p.affectedComponents.length > 0 || p.verificationChecks.length > 0 || p.rollbackNotes || p.type === "patch") && (
                <dl className="kv plan-kv">
                  {p.affectedComponents.length > 0 && <><dt>Affects</dt><dd>{p.affectedComponents.join(", ")}</dd></>}
                  {p.verificationChecks.length > 0 && <><dt>Verify with</dt><dd>{p.verificationChecks.map((v) => <span key={v} className="class-tag">{v}</span>)}</dd></>}
                  {p.rollbackNotes && <><dt>Rollback</dt><dd>{p.rollbackNotes}</dd></>}
                  {p.type === "patch" && <><dt>Repository</dt><dd>{integration ? `${integration.name} (${integration.externalId}${integration.status === "disabled" ? ", disconnected" : ""})` : "—"}{p.baseCommit && <> · base <span className="mono">{p.baseCommit.slice(0, 12)}</span></>}</dd></>}
                </dl>
              )}
              {p.type === "patch" && p.diff && <details className="diff-block"><summary>Diff <span className="mono muted">{p.diffSha256?.slice(0, 12)}</span></summary><TableWrap as="pre" className="diff" label="Diff">{p.diff}</TableWrap></details>}

              {runs.length > 0 && (
                <section className="plan-sub" aria-label="Sandbox runs">
                  <h4>Sandbox runs</h4>
                  <TableWrap>
                    <table><thead><tr><th>Sandbox run</th><th>Result</th><th>Isolation</th></tr></thead><tbody>
                      {runs.slice(0, 5).map((r) => (
                        <tr key={r.id}>
                          <td>{fmt(r.createdAt)}{r.contentSha256 !== p.contentSha256 && <div className="muted">for an earlier version</div>}</td>
                          <td>{r.result ? <StatusBadge status={r.result} /> : <StatusBadge status={r.status} />}{r.reason && <div className="muted">{r.reason.replace(/_/g, " ")}</div>}</td>
                          <td className="muted">{r.isolation}{r.egressBlocked ? " · network blocked" : ""}</td>
                        </tr>
                      ))}
                    </tbody></table>
                  </TableWrap>
                </section>
              )}

              {approvals.length > 0 && (
                <section className="plan-sub" aria-label="Approvals">
                  <h4>Approvals</h4>
                  <ul className="plan-list">{approvals.slice(0, 5).map((a) => (
                    <li key={a.id}>
                      <div className="plan-list-head">
                        <StatusBadge status={a.state} /> <span>{a.policy.replace(/_/g, " ")}</span>
                        {a.untestedOverride && <span className="badge bad">untested override</span>}
                        {a.selfApproved && <span className="badge warn">self-approved (single-approver policy)</span>}
                      </div>
                      <div className="muted">requested {fmt(a.createdAt)}{a.decidedAt && ` · decided ${fmt(a.decidedAt)}`} · expires {fmt(a.expiresAt)}{a.subjectSha256 !== p.contentSha256 && " · for an earlier version"}</div>
                      {(a.decisionReason || a.endReason) && <div className="muted">{a.decisionReason ?? a.endReason?.replace(/_/g, " ")}</div>}
                    </li>
                  ))}</ul>
                  {pending && can.decide && <p><Link href="/approvals">Decide on the approvals page →</Link></p>}
                </section>
              )}

              {codeChanges.length > 0 && (
                <section className="plan-sub" aria-label="Code changes">
                  <h4>Code changes</h4>
                  <ul className="plan-list">{codeChanges.map((ch) => (
                    <li key={ch.id}>
                      <div className="plan-list-head">
                        <StatusBadge status={ch.state} /> branch <code>{ch.branch}</code>
                        {ch.prUrl && <a href={ch.prUrl} rel="noreferrer noopener" target="_blank">change</a>}
                      </div>
                      {(ch.headSha || ch.mergeSha) && <div className="muted mono">{ch.headSha && `head ${ch.headSha.slice(0, 12)}`}{ch.headSha && ch.mergeSha && " · "}{ch.mergeSha && `merged as ${ch.mergeSha.slice(0, 12)}`}</div>}
                      {ch.error && <div className="muted">{ch.error}</div>}
                    </li>
                  ))}</ul>
                  <p className="muted">RuyaShield opens the change only; merging it is your decision. A merge is observed, not performed.</p>
                </section>
              )}

              <div className="plan-actions stack">
              {/* actions */}
              {p.state === "draft" && can.edit && (
                <ActionForm action={submitPlanAction} submit="Propose this plan" variant="secondary">
                  <input type="hidden" name="planId" value={p.id} />
                </ActionForm>
              )}
              {p.type === "patch" && SANDBOXABLE.includes(p.state) && can.sandbox && (
                sandboxReady && integration?.status === "active" && integration.testCommands.length > 0 ? (
                  <ActionForm action={sandboxAction} submit={lastRun ? "Re-run sandbox tests" : "Run sandbox tests"} variant="secondary" pending="Queuing…">
                    <input type="hidden" name="planId" value={p.id} />
                    <input type="hidden" name="idempotencyKey" value={randomUUID()} />
                    <span className="muted">Applies the diff to a copy of {integration.externalId} at the base commit and runs: {integration.testCommands.map((t) => t.join(" ")).join("; ")}. No network.</span>
                  </ActionForm>
                ) : <p className="muted">Sandbox testing is unavailable: {!sandboxReady ? "the sandbox is not installed on this deployment" : !integration || integration.status !== "active" ? "the repository is not connected" : "the repository has no test commands"}.</p>
              )}
              {APPROVABLE.includes(p.state) && can.request && !pending && (
                <ActionForm action={requestApprovalAction} submit="Request approval" variant="secondary">
                  <input type="hidden" name="planId" value={p.id} />
                  <input type="hidden" name="idempotencyKey" value={randomUUID()} />
                  <label>Note for the approver<input name="note" maxLength={2000} /></label>
                  {p.type === "patch" && p.state !== "test_passed" && (
                    <label className="row check-label"><input type="checkbox" name="untestedOverride" /> Request approval without a passing sandbox run (shown to the approver as untested)</label>
                  )}
                </ActionForm>
              )}
              {p.state === "approved" && p.type === "guided" && can.applied && approved && (
                <ActionForm action={markAppliedAction} submit="I applied this change" variant="secondary">
                  <input type="hidden" name="planId" value={p.id} />
                  <label>What did you change, and where?<input name="note" required minLength={5} maxLength={2000} /></label>
                  <span className="muted">This records your statement only. The finding moves to pending verification and closes only if a re-test passes.</span>
                </ActionForm>
              )}
              {approved && can.decide && (
                <ActionForm action={revokeApprovalAction} submit="Revoke approval" variant="danger">
                  <input type="hidden" name="approvalId" value={approved.id} />
                  <label>Reason<input name="reason" required minLength={5} maxLength={2000} /></label>
                </ActionForm>
              )}
              {EDITABLE.includes(p.state) && can.edit && (
                <details className="form-disclosure">
                  <summary>Edit plan</summary>
                  <ActionForm key={p.version} action={editPlanAction} submit="Save changes" variant="secondary">
                    <input type="hidden" name="planId" value={p.id} />
                    <input type="hidden" name="planType" value={p.type} />
                    <input type="hidden" name="version" value={p.version} />
                    <PlanFields title={p.title} description={p.description} components={p.affectedComponents} rollback={p.rollbackNotes} checks={p.verificationChecks} />
                    {p.type === "patch" && <PatchFields baseCommit={p.baseCommit ?? ""} diff={p.diff ?? ""} />}
                    <span className="muted">Saving a change invalidates earlier sandbox results and approvals for this plan.</span>
                  </ActionForm>
                </details>
              )}
              </div>
              {history.length > 0 && (
                <details className="plan-history"><summary>History ({history.length})</summary>
                  <ul>{history.map((h) => <li key={h.id}>{fmt(h.createdAt)} · {h.fromState ?? "—"} → {h.toState}{h.reason && ` · ${h.reason.replace(/_/g, " ")}`}</li>)}</ul>
                </details>
              )}
            </article>
          );
        })}

        {can.edit && PLANNABLE.includes(status) && (
          <div className="card">
            <details className="form-disclosure new-plan">
              <summary>New remediation plan</summary>
              <div className="grid2">
                <ActionForm action={createPlanAction} submit="Create guided plan" variant="secondary">
                  <input type="hidden" name="findingId" value={findingId} />
                  <input type="hidden" name="type" value="guided" />
                  <input type="hidden" name="idempotencyKey" value={randomUUID()} />
                  <p className="muted small">Guided: steps your team applies. You record when it was applied; a re-test confirms it.</p>
                  <PlanFields />
                </ActionForm>
                {active.length > 0 ? (
                  <ActionForm action={createPlanAction} submit="Create patch plan" variant="secondary">
                    <input type="hidden" name="findingId" value={findingId} />
                    <input type="hidden" name="type" value="patch" />
                    <input type="hidden" name="idempotencyKey" value={randomUUID()} />
                    <p className="muted small">Patch: a diff tested in the sandbox and, once approved, opened as a change on a new branch. It is never merged by RuyaShield.</p>
                    <label>Repository <select name="integrationId" required>{active.map((i) => <option key={i.id} value={i.id}>{i.name} ({i.externalId})</option>)}</select></label>
                    <PlanFields />
                    <PatchFields />
                  </ActionForm>
                ) : <p className="muted small">Patch plans need a connected repository. {grantFor(role, "integration.manage") !== "N" && <Link href="/settings/integrations">Connect one</Link>}</p>}
              </div>
            </details>
          </div>
        )}
        {!PLANNABLE.includes(status) && plans.length === 0 && <p className="muted small">New plans can only be started for open findings.</p>}
      </div>
    </>
  );
}

// Text stepper of the plan lifecycle. Only "completed" (set after a passing re-test) marks the last step done.
const STEPS = {
  guided: [["draft"], ["proposed"], ["awaiting_approval", "approved"], ["applied_by_customer"], ["verifying", "completed"]],
  patch: [["draft"], ["proposed"], ["sandbox_testing", "test_passed", "test_failed"], ["awaiting_approval", "approved"], ["change_submitted", "merged_observed"], ["verifying", "completed"]],
} as const;
const STEP_LABEL = {
  guided: ["Draft", "Proposed", "Approved", "Applied (your statement)", "Verified by re-test"],
  patch: ["Draft", "Proposed", "Sandbox tested", "Approved", "Change opened / merged", "Verified by re-test"],
};
const STOPPED: Record<string, string> = {
  rejected: "Stopped: the approval was rejected.",
  closed_unmerged: "Stopped: the change was closed without merging.",
  remediation_failed: "Not fixed: the re-test did not pass, or the change could not be completed.",
};

function Lifecycle({ type, state }: { type: "guided" | "patch"; state: string }) {
  const steps = STEPS[type];
  const at = steps.findIndex((s) => (s as readonly string[]).includes(state));
  const doneAt = (i: number) => i < at || (i === at && (state === "approved" || state === "completed" || state === "test_passed" || state === "applied_by_customer" || state === "merged_observed"));
  return (
    <div className="lifecycle">
      <ol aria-label="Plan lifecycle">
        {STEP_LABEL[type].map((label, i) => {
          const done = at >= 0 && doneAt(i);
          const cur = i === at && !done;
          return (
            <li key={label} className={done ? "done" : cur ? "current" : undefined} aria-current={cur ? "step" : undefined}>
              <span className="lc-dot" aria-hidden="true" />{label}<span className="sr-only">{done ? " (done)" : cur ? " (current)" : ""}</span>
            </li>
          );
        })}
      </ol>
      {STOPPED[state] && <p className="notice bad small">{STOPPED[state]}</p>}
    </div>
  );
}

function PlanFields({ title = "", description = "", components = [], rollback = "", checks = [] }: { title?: string; description?: string; components?: string[]; rollback?: string; checks?: string[] }) {
  return (
    <>
      <label>Title<input name="title" required minLength={3} maxLength={200} defaultValue={title} /></label>
      <label>What to change<textarea name="description" required rows={4} maxLength={10000} defaultValue={description} /></label>
      <label>Affected components (one per line)<textarea name="affectedComponents" rows={2} defaultValue={components.join("\n")} /></label>
      <label>Rollback notes<textarea name="rollbackNotes" rows={2} maxLength={5000} defaultValue={rollback} /></label>
      <label>Verification check IDs (one per line)<textarea name="verificationChecks" rows={2} defaultValue={checks.join("\n")} /></label>
    </>
  );
}

function PatchFields({ baseCommit = "", diff = "" }: { baseCommit?: string; diff?: string }) {
  return (
    <>
      <label>Base commit (40-character SHA)<input name="baseCommit" pattern="[0-9a-f]{40}" defaultValue={baseCommit} /></label>
      <label>Unified diff<textarea name="diff" rows={8} defaultValue={diff} style={{ fontFamily: "monospace" }} /></label>
    </>
  );
}
