"use client";

import { useEffect, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import gsap from "gsap";

type Stage = { id: string; name: string; hint: string; title: string; body: string; points: string[]; mock: ReactNode };

/* Every mock below is an illustrative example on example.com — never live data. */
const STAGES: Stage[] = [
  {
    id: "detect", name: "Detect", hint: "Only on assets you've proven you own",
    title: "Scope comes first, then the checks.",
    body: "An asset must pass DNS or file ownership verification before RuyaShield runs anything against it. Checks are non-intrusive and the result of every run is recorded.",
    points: ["Ownership verified by DNS TXT record or a hosted file", "TLS certificate expiry, HTTP security headers, SPF/DMARC and CAA checks", "Repeat sightings are deduplicated into one finding with an occurrence history"],
    mock: (
      <ul className="rows">
        <li><span>shop.example.com</span><span className="pill pill-ok">Ownership verified · DNS</span></li>
        <li><span className="k">tls.cert_expiry</span><span className="pill pill-warn">Finding · expires in 9 days</span></li>
        <li><span className="k">http.security_headers</span><span className="pill pill-bad">Finding · CSP missing</span></li>
        <li><span className="k">dns.email_posture</span><span className="pill pill-ok">No finding</span></li>
        <li><span className="k">dns.caa</span><span className="pill pill-mute">No finding</span></li>
      </ul>
    ),
  },
  {
    id: "investigate", name: "Investigate", hint: "Zealot explains, citing evidence",
    title: "An explanation you can check line by line.",
    body: "Zealot reads the stored evidence and writes claims labelled as observation, inference or recommendation. Each one must cite evidence; anything it can't support is dropped and counted.",
    points: ["Confidence stated as confirmed, likely or possible", "Missing evidence is reported, not guessed", "Zealot can't change a finding — people do"],
    mock: (
      <ul className="rows">
        <li><span><span className="pill pill-info">Observation</span>&nbsp; No Content-Security-Policy header on / <span className="k">[E1]</span></span></li>
        <li><span><span className="pill pill-violet">Inference · likely</span>&nbsp; Inline scripts would run unrestricted <span className="k">[E1, E2]</span></span></li>
        <li><span><span className="pill pill-warn">Recommendation</span>&nbsp; Start with a report-only policy</span></li>
      </ul>
    ),
  },
  {
    id: "validate", name: "Validate", hint: "People decide severity and status",
    title: "Triage with reasons on the record.",
    body: "An analyst confirms, adjusts or dismisses the finding. Severity changes record who made them and why; a false positive needs an evidence class; accepted risk expires.",
    points: ["Severity info → critical, plus confidence and an optional CVSS vector", "Owner and due date on every confirmed finding", "Risk acceptances expire and notify the team"],
    mock: (
      <ul className="rows">
        <li><span className="k">Status</span><span className="pill pill-violet">Confirmed</span></li>
        <li><span className="k">Severity</span><span><span className="pill pill-warn">Medium</span> <span className="k">&nbsp;was Low · set by analyst</span></span></li>
        <li><span className="k">Reason</span><span>Checkout page serves third-party scripts</span></li>
        <li><span className="k">Owner · due</span><span>Web team · 14 days</span></li>
      </ul>
    ),
  },
  {
    id: "prepare", name: "Prepare fix", hint: "Approved, on a branch, tested in a sandbox",
    title: "A proposed change, never a silent one.",
    body: "A remediation plan needs approval from someone other than the requester, with an MFA step-up. Code changes land on a branch in your connected repository, pass diff safety checks and run in a network-less sandbox.",
    points: ["Admins can't approve their own request; approvals expire after 7 days", "Branch named ruyashield/<plan>-v<n> — nothing is merged for you", "Sandboxed run with no network and a 120-second limit"],
    mock: (
      <pre className="diff" aria-label="Illustrative diff">
        <span className="ctx">{"  # branch ruyashield/plan-42-v1\n  location / {\n"}</span>
        <span className="add">{"+   add_header Content-Security-Policy-Report-Only\n+     \"default-src 'self'\" always;\n"}</span>
        <span className="ctx">{"  }"}</span>
      </pre>
    ),
  },
  {
    id: "verify", name: "Verify", hint: "Re-test before anything is called fixed",
    title: "Fixed means re-tested, not assumed.",
    body: "The original check runs again. Only a passing re-test produces a FixProof record. Errors and inconclusive runs never count as a pass.",
    points: ["Outcomes: verified, partially verified, failed, inconclusive, not run", "FixProof stores the evidence before and after", "A failed verification is a security-critical notification"],
    mock: (
      <ul className="rows">
        <li><span className="k">Re-test · http.security_headers</span><span className="pill pill-ok">Verified</span></li>
        <li><span className="k">Evidence</span><span>Header present in the re-test response</span></li>
        <li><span className="k">FixProof</span><span className="pill pill-violet">Record created</span></li>
        <li><span className="k">Status</span><span>Resolved · verified</span></li>
      </ul>
    ),
  },
  {
    id: "prevent", name: "Prevent recurrence", hint: "Regression re-tests keep watching",
    title: "If it comes back, you hear about it.",
    body: "Verified fixes are re-tested on an interval your organization sets. A regression reopens the finding; a re-test that can't run is reported as such, never as a pass.",
    points: ["Regressions and re-tests that could not run can't be muted", "Findings that stop appearing go stale instead of resolving themselves", "Every change is in a tamper-evident audit log"],
    mock: (
      <ul className="rows">
        <li><span className="k">Regression re-test · week 1</span><span className="pill pill-ok">Still verified</span></li>
        <li><span className="k">Regression re-test · week 2</span><span className="pill pill-bad">Regressed · reopened</span></li>
        <li><span className="k">Notified</span><span>Owner and security lead · email + in-app</span></li>
      </ul>
    ),
  },
];

/** The six-stage workflow as an accessible tablist (arrow keys, Home and End move between stages). */
export function Workflow() {
  const [active, setActive] = useState(0);
  const tabs = useRef<(HTMLButtonElement | null)[]>([]);
  const panels = useRef<HTMLDivElement | null>(null);

  // The opened stage's points and mock rows cascade in (motion allowed only).
  useEffect(() => {
    const panel = panels.current?.querySelector<HTMLElement>(".flow-panel:not([hidden])");
    if (!panel || !matchMedia("(prefers-reduced-motion: no-preference)").matches) return;
    const t = gsap.from(panel.querySelectorAll(".flow-points li, .rows > li, .diff"), { autoAlpha: 0, x: -.75 * (parseFloat(getComputedStyle(document.documentElement).fontSize) || 16), duration: .5, stagger: .06, ease: "power3.out", delay: .1 });
    return () => { t.revert(); };
  }, [active]);

  function onKey(e: KeyboardEvent<HTMLButtonElement>) {
    const last = STAGES.length - 1;
    const next = { ArrowDown: active + 1, ArrowRight: active + 1, ArrowUp: active - 1, ArrowLeft: active - 1, Home: 0, End: last }[e.key];
    if (next === undefined) return;
    e.preventDefault();
    const i = next < 0 ? last : next > last ? 0 : next;
    setActive(i);
    tabs.current[i]?.focus();
  }

  return (
    <div className="flow" ref={panels}>
      <div role="tablist" aria-label="RuyaShield workflow" aria-orientation="vertical" className="flow-tabs">
        {STAGES.map((s, i) => (
          <button
            key={s.id} ref={(el) => { tabs.current[i] = el; }} type="button" role="tab" id={`flow-tab-${s.id}`}
            aria-selected={i === active} aria-controls={`flow-panel-${s.id}`} tabIndex={i === active ? 0 : -1}
            className="flow-tab" onClick={() => setActive(i)} onKeyDown={onKey}
          >
            <span className="flow-num" aria-hidden="true">{String(i + 1).padStart(2, "0")}</span>
            <span className="flow-name">{s.name}</span>
            <span className="flow-hint">{s.hint}</span>
          </button>
        ))}
      </div>
      {STAGES.map((s, i) => (
        <div key={s.id} role="tabpanel" id={`flow-panel-${s.id}`} aria-labelledby={`flow-tab-${s.id}`} hidden={i !== active} className="flow-panel" tabIndex={0}>
          <div className="flow-copy">
            <h3>{s.title}</h3>
            <p>{s.body}</p>
            <ul className="flow-points">{s.points.map((p) => <li key={p}>{p}</li>)}</ul>
          </div>
          <div className="frame">
            <div className="frame-bar">
              <span className="frame-title"><span className="frame-dots" aria-hidden="true"><i /><i /><i /></span>{s.name}</span>
              <span className="illus">Illustrative example — not live data</span>
            </div>
            <div className="frame-body">{s.mock}</div>
          </div>
        </div>
      ))}
    </div>
  );
}
