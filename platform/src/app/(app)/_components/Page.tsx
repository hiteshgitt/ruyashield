import type { ReactNode } from "react";

/** Screen title with an optional one-paragraph lead explaining what the numbers on the page mean. */
export function PageHeader({ title, lead }: { title: ReactNode; lead?: ReactNode }) {
  return (
    <>
      <h1>{title}</h1>
      {lead && <p className="muted small">{lead}</p>}
    </>
  );
}

/** Suspense fallback. `what` names the section that is streaming in ("evidence" -> "Loading evidence…"). */
export function Loading({ what }: { what?: string }) {
  return <p className="muted">{what ? `Loading ${what}…` : "Loading…"}</p>;
}

/** Empty list or table. Say what is missing and, where it matters, what the absence does not prove. */
export function Empty({ children }: { children: ReactNode }) {
  return <p className="empty">{children}</p>;
}

/** Row of small summary chips (counts, run details). Each child is an <li>; `label` names the list for screen readers. */
export function MetaChips({ label, className, children }: { label?: string; className?: string; children: ReactNode }) {
  return <ul className={["meta-chips small", className].filter(Boolean).join(" ")} aria-label={label}>{children}</ul>;
}

/**
 * Heading with trailing context: a provenance tag, a muted note or a status badge.
 * "section" heads a block of cards (h2); "setting" heads one setting inside a card and pairs it with its state.
 */
export function SectionHead({ title, id, as: H = "h2", variant = "section", children }: {
  title: ReactNode; id?: string; as?: "h2" | "h3"; variant?: "section" | "setting"; children?: ReactNode;
}) {
  return <div className={`${variant}-head`}><H id={id}>{title}</H>{children}</div>;
}

/** Shown where a Free organization meets a Pro feature (downloads, reports, raw evidence, audit export). */
export function ProNotice({ children }: { children: ReactNode }) {
  return (
    <p className="notice pro small">
      <span className="badge pro">Pro</span> {children}{" "}
      <a href="/settings/plan">See plans and request Pro</a>.
    </p>
  );
}

/**
 * A locked Pro area for Free organizations: a blurred placeholder of what is there, what it is, what Pro
 * unlocks, and the way to get it. Nothing real is rendered underneath; the server does not send the data.
 */
export function ProGate({ title, children, features = [], rows = 4, compact = false }: {
  title: string; children: ReactNode; features?: string[]; rows?: number; compact?: boolean;
}) {
  return (
    <section className={`pro-gate${compact ? " compact" : ""}`} aria-label={`${title} (Pro)`}>
      <div className="pro-gate-fake" aria-hidden="true">
        {Array.from({ length: rows }, (_, i) => <span key={i} style={{ width: `${94 - ((i * 19) % 42)}%` }} />)}
      </div>
      <div className="pro-gate-body">
        <span className="pro-gate-lock" aria-hidden="true">
          <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><rect x="4.5" y="10.5" width="15" height="10" rx="2.5" /><path d="M8 10.5V7.5a4 4 0 0 1 8 0v3" /></svg>
        </span>
        <div className="pro-gate-text">
          <p className="pro-gate-kicker">RuyaShield Pro</p>
          <h3>{title}</h3>
          <p className="pro-gate-desc">{children}</p>
          {features.length > 0 && <ul className="pro-gate-features">{features.map((f) => <li key={f}>{f}</li>)}</ul>}
        </div>
        <a className="pro-gate-cta" href="/settings/plan">Get Pro to see all <span aria-hidden="true">→</span></a>
      </div>
    </section>
  );
}

/** Slim banner on every page of a Free organization, so the limits are clear before anyone looks for data. */
export function TrialBanner({ daysLeft }: { daysLeft: number }) {
  return (
    <div className="free-banner" role="note">
      <span className="free-banner-badge">Pro trial</span>
      <span className="free-banner-text">Everything is unlocked for {daysLeft === 1 ? "1 more day" : `${daysLeft} more days`}. After that your organization goes back to Free unless Pro is activated.</span>
      <a className="free-banner-cta" href="/settings/plan">Keep Pro <span aria-hidden="true">→</span></a>
    </div>
  );
}

export function FreeBanner() {
  return (
    <div className="free-banner" role="note">
      <span className="free-banner-badge">Free plan</span>
      <span className="free-banner-text">You see your 5 highest-priority findings with suggested fixes. Pro unlocks every finding, evidence, Zealot, fixes, re-tests, attacks and reports.</span>
      <a className="free-banner-cta" href="/settings/plan">See plans <span aria-hidden="true">→</span></a>
    </div>
  );
}
