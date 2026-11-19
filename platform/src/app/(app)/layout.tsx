import { Suspense } from "react";
import Link from "next/link";
import { Funnel_Display, Funnel_Sans, Geist_Mono } from "next/font/google";
import { AppChrome } from "./_components/AppChrome";
import { ShellBehavior } from "./_components/ShellBehavior";
import { FreeBanner, TrialBanner } from "./_components/Page";
import { eq } from "drizzle-orm";
import { withOrg } from "@/server/db/client";
import { orgs } from "@/server/db/schema";
import { trialDaysLeft } from "@/server/plans/lifecycle";
import { getContext } from "@/server/context";
import { isProOrg } from "@/server/policy/policy";
import "./app.css";

// Same faces as the public site: Funnel Display for headings, Funnel Sans for text, Geist Mono for labels and code.
const display = Funnel_Display({ subsets: ["latin"], variable: "--font-display", display: "swap" });
const sans = Funnel_Sans({ subsets: ["latin"], variable: "--font-sans", display: "swap" });
const mono = Geist_Mono({ subsets: ["latin"], variable: "--font-mono", display: "swap" });

export default function AppLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <div className={`app ${display.variable} ${sans.variable} ${mono.variable}`}>
      <a href="#app-main" className="skip">Skip to content</a>
      {/* The sidebar and top bar are grid items of .frame; <main> streams independently of them. */}
      <div className="frame">
        <Suspense fallback={<header className="topbar"><Link href="/" className="brand">RuyaShield</Link></header>}>
          <AppChrome />
        </Suspense>
        <main id="app-main" tabIndex={-1}>
          <Suspense fallback={null}><PlanBanner /></Suspense>
          {children}
        </main>
      </div>
      {/* Reads the pathname, which dynamic routes only know at request time. */}
      <Suspense fallback={null}><ShellBehavior /></Suspense>
    </div>
  );
}

/** Free organizations see their plan's limits at the top of every page. */
async function PlanBanner() {
  const c = await getContext();
  if (!c?.ctx || c.ctx.principal.breakGlassId) return null;
  if (isProOrg(c.ctx.org)) {
    const orgId = c.ctx.org.id;
    const o = (await withOrg(orgId, (tx) => tx.select({ planSource: orgs.planSource, trialEndsAt: orgs.trialEndsAt }).from(orgs).where(eq(orgs.id, orgId))))[0];
    const left = o ? trialDaysLeft(o) : null;
    return left === null ? null : <TrialBanner daysLeft={left} />;
  }
  return <FreeBanner />;
}
