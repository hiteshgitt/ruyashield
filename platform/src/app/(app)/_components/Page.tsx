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
      <a href="https://ruyalab.com/" target="_blank" rel="noopener noreferrer">Ask Ruya Lab to upgrade your organization</a>.
    </p>
  );
}
