import Link from "next/link";
import { cacheLife } from "next/cache";
import { Logo } from "./Logo";

export function SiteFooter() {
  return (
    <footer className="site-footer">
      <div className="site-footer-top">
        <div className="site-footer-brand">
          <Logo />
          <p>Authorized-scope website security: detect, investigate, validate, prepare the fix, verify it and catch regressions.</p>
        </div>
        <nav aria-label="Product" className="site-footer-col">
          <h2>Product</h2>
          <Link href="/#workflow">Workflow</Link>
          <Link href="/#zealot">Zealot AI</Link>
          <Link href="/#fixproof">Remediation &amp; FixProof</Link>
          <Link href="/#capabilities">Capabilities</Link>
        </nav>
        <nav aria-label="Who it is for" className="site-footer-col">
          <h2>Who it&apos;s for</h2>
          <Link href="/#agencies">Agencies &amp; MSPs</Link>
          <Link href="/#webmonitor">WebMonitor customers</Link>
          <Link href="/#pricing">Pricing</Link>
          <Link href="/#faq">FAQ</Link>
        </nav>
        <nav aria-label="Account" className="site-footer-col">
          <h2>Account</h2>
          <a href="/auth/signin">Sign in</a>
          <a href="/auth/signin?new=1">Create account</a>
          <a href="/orgs">Organizations</a>
          <a href="https://webmonitor.ruyalab.com" target="_blank" rel="noopener noreferrer">WebMonitor by Ruya Lab ↗</a>
        </nav>
      </div>
      <div className="site-footer-bottom">
        <p>RuyaShield only tests assets your organization has proven it owns, or holds recorded written authorization to test. Results reflect the checks that ran; they are not a certification or a compliance attestation.</p>
        <p>© <Year /> RuyaShield</p>
      </div>
    </footer>
  );
}

/* Cached so the footer can be prerendered under cacheComponents; refreshed daily. */
async function Year() {
  "use cache";
  cacheLife("days");
  return new Date().getFullYear();
}
