import { Suspense } from "react";
import { grantFor } from "@/server/policy/matrix";
import { ActionForm } from "../../_components/ActionForm";
import { aiStatus } from "@/server/ai/gateway";
import { aiSettingsAction, intrusiveNetworkAction, killSwitchAction, regressionIntervalAction } from "../../actions";
import { getIntrusiveNetwork, getRegressionInterval } from "@/server/orgs/orgs";
import { pageOrg } from "../../_lib/page";
import { Loading, PageHeader, SectionHead } from "../../_components/Page";

export default function SafetyPage() {
  return (
    <>
      <PageHeader title="Safety controls" lead="Kill switches stop new work immediately for this organization. Every change is recorded in the audit log with its reason." />
      <Suspense fallback={<Loading />}><Safety /></Suspense>
    </>
  );
}

async function Safety() {
  const c = await pageOrg("/settings/safety");
  if (grantFor(c.principal.role, "killswitch.manage") === "N") return <p className="notice warn">Only org admins and security leads can change safety controls.</p>;
  return (
    <div className="stack">
      <SectionHead title="Kill switches"><span className="muted small">Take effect immediately · reason required · audited</span></SectionHead>
      <div className="switch-grid">
        <Switch which="scanning" title="Scanning" engaged={c.org.killScanning}
          what="Blocks new assessments and ownership checks. Re-verification of existing assets pauses." />
        <Switch which="ai" title="AI assistance" engaged={c.org.killAi}
          what="Blocks all AI requests. Scanning and reporting continue without AI." />
      </div>
      {grantFor(c.principal.role, "scope.enable_a2") !== "N" && <IntrusiveNetwork c={c} />}
      {(grantFor(c.principal.role, "ai.configure") !== "N" || grantFor(c.principal.role, "org.settings.edit") !== "N") && (
        <SectionHead title="Settings" />
      )}
      {grantFor(c.principal.role, "ai.configure") !== "N" && <AiSettings c={c} />}
      {grantFor(c.principal.role, "org.settings.edit") !== "N" && <Regression c={c} />}
    </div>
  );
}

function Switch({ which, title, engaged, what }: { which: "scanning" | "ai"; title: string; engaged: boolean; what: string }) {
  const noun = title.toLowerCase().replace(/^ai\b/, "AI");
  return (
    <section className={`card switch-card ${engaged ? "stopped" : "running"}`} aria-labelledby={`sw-${which}`}>
      <div className="setting-head">
        <h3 id={`sw-${which}`}>{title}</h3>
        <span className={`badge ${engaged ? "bad" : "ok"}`}>{engaged ? "stopped" : "running"}</span>
      </div>
      <p className="switch-state">{engaged ? `${title} is stopped for this organization.` : `${title} is running normally.`}</p>
      <p className="muted small"><strong className="switch-label">{engaged ? "While stopped" : "If stopped"}</strong> {what}</p>
      <ActionForm action={killSwitchAction} submit={engaged ? `Resume ${noun}` : `Stop ${noun}`} variant={engaged ? "primary" : "danger"} className="row inline-form grow">
        <input type="hidden" name="which" value={which} />
        <input type="hidden" name="engaged" value={engaged ? "false" : "true"} />
        <input type="text" name="reason" required placeholder="Reason (required)" aria-label={`Reason for ${engaged ? "resuming" : "stopping"} ${noun}`} />
      </ActionForm>
    </section>
  );
}

async function AiSettings({ c }: { c: Awaited<ReturnType<typeof pageOrg>> }) {
  const s = await aiStatus(c);
  const pct = s.budget > 0 ? Math.min(100, Math.round((s.used / s.budget) * 100)) : 0;
  return (
    <section className="card" aria-labelledby="ai-settings-h">
      <SectionHead title="AI settings" id="ai-settings-h" as="h3" variant="setting"><span className={`badge ${s.enabled ? "ok" : "warn"}`}>{s.enabled ? "on" : "off"}</span></SectionHead>
      <dl className="kv small setting-kv">
        <dt>Provider</dt>
        <dd><span className="mono">{s.provider ? `${s.provider}/${s.model}` : "none configured (RUYA_AI_PROVIDER)"}</span>{s.provider === "fixture" && <span className="muted"> — offline fixture for development; not a language model</span>}</dd>
        <dt>Released</dt>
        <dd className="badge-row">{(["explain", "remediation"] as const).map((u) => <span key={u} className={`badge ${s.released[u] ? "ok" : "warn"}`}>{u}: {s.released[u] ? "released" : "not released"}</span>)}</dd>
        <dt>Tokens ({s.period})</dt>
        <dd>
          {s.used.toLocaleString()} of {s.budget.toLocaleString()} used
          {s.budget > 0 && <span className="budget-bar" aria-hidden="true"><span style={{ width: `${pct}%` }} className={pct >= 100 ? "full" : pct >= 80 ? "high" : undefined} /></span>}
        </dd>
      </dl>
      <p className="muted small">A prompt is only usable after it passes the evaluation gate for this provider and model.</p>
      <ActionForm action={aiSettingsAction} submit={s.enabled ? "Turn AI off" : "Turn AI on"} variant={s.enabled ? "danger" : "primary"} className="row inline-form grow">
        <label className="small">Monthly token budget<input type="number" name="budget" min={0} defaultValue={s.budget} /></label>
        <label className="small grow">Reason (required)<input type="text" name="reason" required /></label>
      </ActionForm>
    </section>
  );
}

async function Regression({ c }: { c: Awaited<ReturnType<typeof pageOrg>> }) {
  const days = await getRegressionInterval(c);
  return (
    <section className="card" aria-labelledby="regression-h">
      <SectionHead title="Regression re-tests" id="regression-h" as="h3" variant="setting"><span className={`badge ${days ? "ok" : "warn"}`}>{days ? `every ${days} days` : "off"}</span></SectionHead>
      <p className="muted small">Re-runs the original check against findings resolved with a passing FixProof. A failed re-test reopens the finding; an inconclusive one or one that cannot run (kill switch, lapsed authorization) is reported to the owner and never counts as a pass. Leave empty to turn off.</p>
      <ActionForm action={regressionIntervalAction} submit="Save" className="row inline-form grow">
        <label className="small">Interval in days (1–90)<input type="number" name="days" min={1} max={90} defaultValue={days ?? undefined} /></label>
        <label className="small grow">Reason (required)<input type="text" name="reason" required /></label>
      </ActionForm>
    </section>
  );
}

async function IntrusiveNetwork({ c }: { c: Awaited<ReturnType<typeof pageOrg>> }) {
  const s = await getIntrusiveNetwork(c);
  const pending = s.pending;
  const mine = pending && s.requestedBy === c.principal.userId;
  const label = s.enabled ? "on" : pending ? "awaiting second admin" : "off";
  return (
    <section className="card" aria-labelledby="a2-h">
      <SectionHead title="Intrusive network checks (A2)" id="a2-h" as="h3" variant="setting"><span className={`badge ${s.enabled ? "warn" : pending ? "warn" : "ok"}`}>{label}</span></SectionHead>
      <p className="muted small">Allows the exposed-services check: a TCP connection to 26 well-known ports (databases, remote desktop, Docker, Redis…) on assets whose ownership is verified. It sends nothing and makes no login attempts, but a firewall or IDS may log it as a port scan, so tell your hosting provider or SOC first. At most once per hour per asset. Turning it on needs two different admins; turning it off needs one.</p>
      {mine && <p className="notice warn small">You requested this. Another admin must confirm it.</p>}
      {(!mine || s.enabled) && (
        <ActionForm action={intrusiveNetworkAction} submit={s.enabled ? "Turn off" : pending ? "Confirm and turn on" : "Request to turn on"} variant={s.enabled ? "danger" : "primary"} className="row inline-form grow">
          <input type="hidden" name="enable" value={s.enabled ? "false" : "true"} />
          <label className="small grow">Reason (required)<input type="text" name="reason" required /></label>
        </ActionForm>
      )}
      {mine && (
        <ActionForm action={intrusiveNetworkAction} submit="Withdraw request" className="row inline-form grow">
          <input type="hidden" name="enable" value="false" />
          <label className="small grow">Reason (required)<input type="text" name="reason" required /></label>
        </ActionForm>
      )}
    </section>
  );
}
