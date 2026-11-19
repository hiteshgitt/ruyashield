import { randomUUID } from "node:crypto";
import type { ReactNode } from "react";
import type { Ctx } from "@/server/findings/findings";
import { aiStatus, listAnalyses, listChat, requestAnalysis } from "@/server/ai/gateway";
import { MAX_QUESTION_CHARS } from "@/server/ai/prompts";
import { grantFor } from "@/server/policy/matrix";
import { ActionForm } from "../../_components/ActionForm";
import { StatusBadge } from "../../_components/StatusBadge";
import { chatAiAction, createPlanFromAiAction, requestAiAction } from "../../actions";
import { fmt } from "../../_lib/page";
import { MetaChips } from "../../_components/Page";

type Entry = Awaited<ReturnType<typeof listAnalyses>>[number];

const CLAIM_HEAD = { observation: "Observations", inference: "Hypotheses (unconfirmed)", recommendation: "Recommendations" } as const;
const n = (x: number) => x.toLocaleString("en-US");

// AI output is advisory (RS-AI-001..003): it is labelled, cites evidence, and never changes the finding.
// Everything Zealot says lives inside this one outlined panel so it can't be mistaken for check results or FixProof outcomes.
export async function ZealotPanel({ c, findingId, remediation }: { c: Ctx; findingId: string; remediation: string | null }) {
  const [st, firstHistory, threads] = await Promise.all([aiStatus(c), listAnalyses(c, findingId, 5), listChat(c, findingId)]);
  const canAsk = grantFor(c.principal.role, "ai.request") !== "N";
  const canPlan = grantFor(c.principal.role, "remediation.edit") !== "N";
  const blocked = st.killed ? "AI assistance is stopped by the organization kill switch."
    : !st.enabled ? "AI assistance is turned off for this organization."
    : !st.provider ? "No AI provider is configured on this deployment."
    : st.used >= st.budget ? "This month's AI token budget is used up."
    : null;
  // Opening a finding explains it once: no button needed. The key includes the day, so a provider outage is
  // retried at most once a day per finding (and a replay never calls the provider twice).
  let history = firstHistory;
  const explained = history.some((e) => e.analysis.useCase === "explain" && (e.analysis.status === "completed" || e.analysis.status === "inconclusive"));
  if (!blocked && canAsk && st.released.explain && !explained && !c.principal.tokenScopes && !c.principal.breakGlassId) {
    const key = `auto-explain-${findingId}-${new Date().toISOString().slice(0, 10)}`;
    const done = await requestAnalysis(c, findingId, { useCase: "explain", idempotencyKey: key }).then(() => true, () => false);
    if (done) history = await listAnalyses(c, findingId, 5);
  }
  const manual = remediation ? <p className="small">Manual guidance: {remediation}</p> : null;
  const [latest, ...earlier] = history;
  return (
    <section className="zealot" aria-labelledby="zealot-h">
      <header className="zealot-head">
        <span className="zealot-glyph" aria-hidden="true">Z</span>
        <div className="zealot-title">
          <h2 id="zealot-h">Zealot · AI analysis</h2>
          <p className="muted small">Explains and suggests from the stored evidence. It never changes this finding&apos;s status, severity or verification — only a FixProof re-test confirms a fix.</p>
        </div>
        <span className="source-tag ai">AI-generated · advisory</span>
      </header>

      {st.provider && (
        <MetaChips label="AI provider status" className="zealot-status">
          <li><span className="muted">Provider</span> <span className="mono">{st.provider === "fixture" ? "offline fixture (not a language model)" : `${st.provider}/${st.model}`}</span></li>
          <li><span className="muted">Explain</span> {st.released.explain ? "released" : "not released"}</li>
          <li><span className="muted">Remediation</span> {st.released.remediation ? "released" : "not released"}</li>
          <li><span className="muted">Chat</span> {st.released.chat ? "released" : "not released"}</li>
          <li><span className="muted">Tokens</span> {n(st.used)} of {n(st.budget)} used ({st.period})</li>
        </MetaChips>
      )}

      <div className="stack">
        {blocked ? (
          <div className="zealot-box small"><p className="muted">{blocked}</p>{manual}</div>
        ) : canAsk ? (
          <div className="zealot-box">
            <div className="row">
              {(["explain", "remediation"] as const).map((u) => st.released[u] ? (
                <ActionForm key={u} action={requestAiAction} submit={u === "explain" ? "Explain this finding" : "Suggest remediation"} variant="secondary" pending="Analysing…">
                  <input type="hidden" name="findingId" value={findingId} />
                  <input type="hidden" name="useCase" value={u} />
                  <input type="hidden" name="idempotencyKey" value={randomUUID()} />
                </ActionForm>
              ) : <p key={u} className="muted small">{u === "explain" ? "Explain" : "Remediation"} is not released for {st.provider}/{st.model} (no passing evaluation).</p>)}
            </div>
            <p className="muted small">Sends this finding and up to 5 redacted evidence items to {st.provider === "fixture" ? "the offline fixture provider (not a language model)" : `${st.provider}/${st.model}`}. Output is advisory and never changes the finding.</p>
          </div>
        ) : null}

        {!latest && !blocked && <p className="muted small">No analyses for this finding yet.</p>}
        {latest && <Analysis entry={latest} findingId={findingId} canPlan={canPlan} manual={manual} />}
        {earlier.length > 0 && (
          <details className="form-disclosure zealot-earlier">
            <summary>Earlier analyses ({earlier.length})</summary>
            <div className="stack">
              {earlier.map((e) => <Analysis key={e.analysis.id} entry={e} findingId={findingId} canPlan={canPlan} manual={manual} />)}
            </div>
          </details>
        )}

        <section className="zealot-chat stack" aria-labelledby="zealot-chat-h">
          <h3 id="zealot-chat-h">Ask about this finding</h3>
          <p className="muted small">Answers come only from this finding&apos;s stored evidence and are advisory. Zealot cannot mark it fixed, confirm a compromise or test the site; only a FixProof re-test confirms a fix. Do not paste passwords or keys — anything that looks like one is redacted or the question is refused.</p>
          {threads.map((t, i) => (
            <details key={t.threadId} className="form-disclosure" open={i === 0}>
              <summary>Conversation {i === 0 ? "(latest)" : threads.length - i} · {t.turns.length} question{t.turns.length === 1 ? "" : "s"}</summary>
              <div className="stack">
                {t.turns.map((turn) => (
                  <div key={turn.analysis.id} className="stack">
                    <p className="small"><strong>You asked:</strong> {turn.analysis.question}</p>
                    <Analysis entry={turn} findingId={findingId} canPlan={false} manual={manual} />
                  </div>
                ))}
                {!blocked && canAsk && st.released.chat && (t.full
                  ? <p className="muted small">This conversation is full. Start a new one below.</p>
                  : <ChatForm findingId={findingId} threadId={t.threadId} label="Ask a follow-up" />)}
              </div>
            </details>
          ))}
          {blocked ? null : !canAsk ? <p className="muted small">Your role cannot ask the AI.</p>
            : !st.released.chat ? <p className="muted small">Chat is not released for {st.provider}/{st.model} (no passing evaluation).</p>
            : <ChatForm findingId={findingId} label={threads.length ? "Start a new conversation" : "Ask"} />}
        </section>
      </div>
    </section>
  );
}

function ChatForm({ findingId, threadId, label }: { findingId: string; threadId?: string; label: string }) {
  return (
    <ActionForm action={chatAiAction} submit={label} variant="secondary" pending="Thinking…">
      <input type="hidden" name="findingId" value={findingId} />
      {threadId && <input type="hidden" name="threadId" value={threadId} />}
      <input type="hidden" name="idempotencyKey" value={randomUUID()} />
      <label>Question<textarea name="question" rows={2} required maxLength={MAX_QUESTION_CHARS} placeholder="e.g. How do I fix this on nginx without breaking my subdomains?" /></label>
    </ActionForm>
  );
}

function Analysis({ entry: { analysis: a, claims }, findingId, canPlan, manual }: { entry: Entry; findingId: string; canPlan: boolean; manual: ReactNode }) {
  return (
    <article className="zealot-run stack small" aria-label={`AI ${a.useCase} analysis, ${fmt(a.createdAt)}`}>
      <div className="zealot-run-head">
        <span className="badge warn">AI-generated — review before use</span> <StatusBadge status={a.status} />
        <span className="muted mono zealot-meta">{a.useCase} · {a.provider}/{a.model} · prompt {a.promptId}@{a.promptVersion} · {fmt(a.createdAt)}</span>
      </div>
      {a.status === "inconclusive" && <div className="notice warn">Inconclusive: the evidence did not support a conclusion. This is not a finding that the issue is absent.</div>}
      {(a.status === "rejected" || a.status === "unavailable") && <div className="notice bad">{a.status === "rejected" ? "The reply failed validation and was discarded." : "The provider was unavailable."}{a.error && ` ${a.error}`}{manual}</div>}
      {a.summary && <p className="zealot-summary">{a.summary}</p>}
      {(["observation", "inference", "recommendation"] as const).map((t) => {
        const list = claims.filter((cl) => cl.type === t);
        if (!list.length) return null;
        return (
          <div key={t} className={`claim-group ${t}`}>
            <h3 className="claim-type">{CLAIM_HEAD[t]} <span className="muted">({list.length})</span></h3>
            <ul className="claims">{list.map((cl) => (
              <li key={cl.id} className="claim">
                <p className="claim-text">{cl.text}</p>
                <div className="claim-meta">
                  <span className="chip">{cl.confidenceLabel} confidence</span>
                  <span className="muted">Cites evidence</span>
                  {cl.evidenceIds.map((e) => <code key={e} className="cite" title={e}>{e.slice(0, 8)}</code>)}
                </div>
                {t === "recommendation" && (
                  <>
                    {cl.steps.length > 0 && <ol className="claim-steps">{cl.steps.map((s, i) => <li key={i}>{s}</li>)}</ol>}
                    <div className="claim-meta">
                      <span className="muted">Verify with</span>
                      {cl.verificationCheckIds.length ? cl.verificationCheckIds.map((id) => <span key={id} className="class-tag">{id}</span>) : <span className="muted">—</span>}
                      {cl.approvalRequired && <span className="badge bad">approval required</span>}
                    </div>
                    {canPlan && a.status === "completed" && (
                      <ActionForm action={createPlanFromAiAction} submit="Start a draft plan from this" variant="secondary">
                        <input type="hidden" name="findingId" value={findingId} />
                        <input type="hidden" name="claimId" value={cl.id} />
                        <input type="hidden" name="idempotencyKey" value={randomUUID()} />
                      </ActionForm>
                    )}
                  </>
                )}
              </li>
            ))}</ul>
          </div>
        );
      })}
      {(a.uncertainty || a.missingEvidence.length > 0 || a.droppedClaims > 0 || a.flags.length > 0) && (
        <dl className="kv zealot-limits">
          {a.uncertainty && <><dt>Uncertainty</dt><dd>{a.uncertainty}</dd></>}
          {a.missingEvidence.length > 0 && <><dt>Missing evidence</dt><dd>{a.missingEvidence.join("; ")}</dd></>}
          {(a.droppedClaims > 0 || a.flags.length > 0) && <><dt>Validator</dt><dd>Removed {a.droppedClaims} unsupported claim(s){a.flags.length > 0 && ` · flags: ${a.flags.join(", ")}`}</dd></>}
        </dl>
      )}
    </article>
  );
}
