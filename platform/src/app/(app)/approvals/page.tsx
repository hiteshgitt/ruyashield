import { Suspense } from "react";
import Link from "next/link";
import { getPlan } from "@/server/remediation/plans";
import { listApprovals } from "@/server/remediation/approvals";
import { grantFor } from "@/server/policy/matrix";
import { ActionForm } from "../_components/ActionForm";
import { StatusBadge } from "../_components/StatusBadge";
import { decideApprovalAction } from "../actions";
import { fmt, pageOrg } from "../_lib/page";
import { Empty, Loading, MetaChips, PageHeader } from "../_components/Page";
import { TableWrap } from "../_components/TableWrap";

const DECIDE_SHOWN = 20;

export default function ApprovalsPage() {
  return (
    <>
      <PageHeader title="Approvals" lead="Remediation plans waiting for a decision. The person who requested an approval cannot decide it, and deciding needs a recent MFA sign-in. An approval covers exactly the plan version shown; any edit invalidates it." />
      <Suspense fallback={<Loading />}><Approvals /></Suspense>
    </>
  );
}

async function Approvals() {
  const c = await pageOrg("/approvals");
  const rows = await listApprovals(c);
  const pending = rows.filter((r) => r.approval.state === "pending");
  const done = rows.filter((r) => r.approval.state !== "pending").slice(0, 50);
  const details = await Promise.all(pending.slice(0, DECIDE_SHOWN).map((r) => getPlan(c, r.plan.id)));
  const mayDecide = grantFor(c.principal.role, "approval.decide") !== "N";
  const untested = pending.filter((r) => r.approval.untestedOverride).length;
  return (
    <div className="stack">
      <MetaChips label="Approval counts">
        <li>{pending.length} pending</li>
        <li>{untested} marked untested</li>
        <li>{done.length} recent decisions</li>
      </MetaChips>
      <h2>Pending ({pending.length})</h2>
      {pending.length === 0 && <Empty>Nothing is waiting for approval.</Empty>}
      {pending.slice(0, DECIDE_SHOWN).map((r, i) => {
        const { plan: p, sandboxRuns } = details[i];
        const run = sandboxRuns.find((s) => s.id === r.approval.sandboxRunId);
        const stale = p.contentSha256 !== r.approval.subjectSha256;
        return (
          <article key={r.approval.id} className="card approval-card small" aria-label={`Approval request: ${p.title}`}>
            <div className="plan-head">
              <h3 className="plan-title">{p.title}</h3>
              <div className="plan-badges">
                <span className="chip">{p.type}</span> <StatusBadge status={p.state} />
                {p.aiClaimId && <> <span className="badge warn">from AI recommendation</span></>}
              </div>
            </div>
            <MetaChips className="plan-meta">
              <li><span className="muted">Requested</span> {fmt(r.approval.createdAt)}</li>
              <li><span className="muted">Expires</span> {fmt(r.approval.expiresAt)}</li>
              <li><span className="muted">Policy</span> {r.approval.policy.replace(/_/g, " ")}</li>
              <li><span className="muted">Covers</span> <span className="mono">{r.approval.subjectSha256.slice(0, 12)}</span></li>
            </MetaChips>
            <dl className="kv plan-kv">
              <dt>Finding</dt><dd><Link href={`/findings/${r.finding.id}`}>{r.finding.title}</Link> <StatusBadge status={r.finding.severity} /></dd>
              {r.approval.requestNote && <><dt>Requester note</dt><dd>{r.approval.requestNote}</dd></>}
              {p.rollbackNotes && <><dt>Rollback</dt><dd>{p.rollbackNotes}</dd></>}
            </dl>
            <p className="plan-desc">{p.description}</p>
            {p.type === "patch" && (
              <>
                {r.approval.untestedOverride || !run
                  ? <div className="notice bad">Untested: this patch has no passing sandbox run. Approving it accepts that risk.</div>
                  : <div className="notice ok">Sandbox: <StatusBadge status={run.result ?? run.status} /> at {fmt(run.finishedAt)} · {run.isolation}</div>}
                {p.diff && <details className="diff-block"><summary>Diff <span className="mono muted">{p.diffSha256?.slice(0, 12)} · base {p.baseCommit?.slice(0, 12)}</span></summary><TableWrap as="pre" className="diff" label="Diff">{p.diff}</TableWrap></details>}
                <div className="muted">Approving lets RuyaShield open this exact diff as a change on a new branch. It never merges; your team does.</div>
              </>
            )}
            {stale && <div className="notice warn">The plan changed after this request; it can no longer be approved.</div>}
            {r.canDecide ? (
              <div className="decide">
                <ActionForm action={decideApprovalAction} submit="Approve">
                  <input type="hidden" name="approvalId" value={r.approval.id} />
                  <input type="hidden" name="decision" value="approve" />
                  <input type="hidden" name="subjectSha256" value={r.approval.subjectSha256} />
                  <label>Reason (optional)<input name="reason" maxLength={2000} /></label>
                </ActionForm>
                <ActionForm action={decideApprovalAction} submit="Reject" variant="danger">
                  <input type="hidden" name="approvalId" value={r.approval.id} />
                  <input type="hidden" name="decision" value="reject" />
                  <input type="hidden" name="subjectSha256" value={r.approval.subjectSha256} />
                  <label>Reason<input name="reason" required minLength={5} maxLength={2000} /></label>
                </ActionForm>
              </div>
            ) : <p className="muted decide-blocked">{!mayDecide ? "Your role cannot decide approvals." : r.approval.requesterId === c.principal.userId ? "You requested this approval, so someone else must decide it." : "You cannot decide this approval."}</p>}
          </article>
        );
      })}
      {pending.length > DECIDE_SHOWN && <p className="muted small">Showing the {DECIDE_SHOWN} most recent pending requests.</p>}

      <h2>Recent decisions</h2>
      {done.length === 0 ? <Empty>No decisions yet.</Empty> : (
        <TableWrap className="card">
          <table><thead><tr><th>Plan</th><th>Finding</th><th>State</th><th>Decided</th><th>Reason</th></tr></thead><tbody>
            {done.map((r) => (
              <tr key={r.approval.id}>
                <td>{r.plan.title} <span className="chip">{r.plan.type}</span></td>
                <td><Link href={`/findings/${r.finding.id}`}>{r.finding.title}</Link></td>
                <td><StatusBadge status={r.approval.state} />{r.approval.selfApproved && <div className="muted small">self-approved</div>}</td>
                <td className="small">{fmt(r.approval.decidedAt ?? r.approval.revokedAt)}</td>
                <td className="small">{r.approval.decisionReason ?? r.approval.endReason?.replace(/_/g, " ") ?? "—"}</td>
              </tr>
            ))}
          </tbody></table>
        </TableWrap>
      )}
    </div>
  );
}
