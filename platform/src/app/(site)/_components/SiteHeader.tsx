import { Suspense } from "react";
import Link from "next/link";
import { getContext } from "@/server/context";
import { Logo } from "./Logo";

const LINKS = [
  ["#workflow", "Workflow"],
  ["#zealot", "Zealot AI"],
  ["#fixproof", "FixProof"],
  ["#agencies", "Agencies"],
  ["#pricing", "Pricing"],
  ["#faq", "FAQ"],
] as const;

export function SiteHeader() {
  return (
    <header className="site-header">
      <div className="site-header-inner">
        <Link href="/" className="site-brand" aria-label="RuyaShield home"><Logo /></Link>
        <nav aria-label="Primary" className="site-nav">
          {LINKS.map(([href, label]) => <a key={href} href={href}>{label}</a>)}
        </nav>
        <div className="site-header-cta">
          <Suspense fallback={<a className="btn btn-primary btn-sm" href="/auth/login">Sign in</a>}>
            <AccountCta size="sm" />
          </Suspense>
        </div>
        <details className="site-menu">
          <summary aria-label="Menu"><span className="site-menu-icon" aria-hidden="true" /><span className="site-menu-label">Menu</span></summary>
          <nav aria-label="Mobile" className="site-menu-panel">
            {LINKS.map(([href, label]) => <a key={href} href={href}>{label}</a>)}
          </nav>
        </details>
      </div>
      <span className="site-progress" aria-hidden="true" />
    </header>
  );
}

/**
 * The same sign-in logic the old home page had: signed-out visitors go to sign-in, signed-in people go
 * straight to their organization (or to choose one).
 */
export async function AccountCta({ size }: { size?: "sm" | "lg" }) {
  const c = await getContext();
  const cls = `btn btn-primary${size ? ` btn-${size}` : ""}`;
  if (!c) return <a className={cls} href="/auth/login">Sign in to get started</a>;
  return <Link className={cls} href={c.ctx ? "/assets" : "/orgs"}>{c.ctx ? `Continue to ${c.ctx.org.name}` : "Choose or create an organization"} <span aria-hidden="true">→</span></Link>;
}
