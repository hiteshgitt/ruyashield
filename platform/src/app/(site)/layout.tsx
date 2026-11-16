import type { Metadata } from "next";
import { Funnel_Display, Funnel_Sans, Geist_Mono } from "next/font/google";
import { SiteHeader } from "./_components/SiteHeader";
import { SiteFooter } from "./_components/SiteFooter";
import "./site.css";
import "./above-1920.css";

// Funnel Display (sharp ink-trap details) for headings, Funnel Sans for body text, Geist Mono for labels, evidence and code.
const display = Funnel_Display({ subsets: ["latin"], variable: "--font-display", display: "swap" });
const sans = Funnel_Sans({ subsets: ["latin"], variable: "--font-sans", display: "swap" });
const mono = Geist_Mono({ subsets: ["latin"], variable: "--font-mono", display: "swap" });

export const metadata: Metadata = {
  title: "RuyaShield — Find the real risk. Prove the fix.",
  description: "RuyaShield checks the websites you are authorized to test, explains findings with Zealot, prepares reviewed fixes and only calls a fix verified after a re-test passes.",
};

/** Runs before first paint: opts into the motion styles (hero hidden until the GSAP intro starts), with a failsafe
 * that shows everything after 3s if the motion script never loads. */
const motionBoot = `try{if(matchMedia("(prefers-reduced-motion: no-preference)").matches){var d=document.documentElement;d.classList.add("rs-motion");setTimeout(function(){d.classList.add("rs-ready")},3000)}}catch(e){}`;

export default function SiteLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <div data-site="marketing" className={`site ${display.variable} ${sans.variable} ${mono.variable}`}>
      <script dangerouslySetInnerHTML={{ __html: motionBoot }} />
      <a className="skip" href="#main">Skip to content</a>
      <SiteHeader />
      <main id="main">{children}</main>
      <SiteFooter />
    </div>
  );
}
