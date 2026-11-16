import { createHash } from "node:crypto";
import { EGRESS_MAX_BODY, EgressError, guardedGet, type FetchResult } from "../net/egress";
import { isIpLiteral } from "../net/ip";
import type { CheckAdapter, CheckContext, CheckResult, FindingCandidate } from "./checks";

/**
 * http.compromise (class A1): passive signs that a site has been tampered with, read from its home page.
 *  - Two ordinary GETs of https://host/: one as RuyaShield, one with a search-engine crawler User-Agent, so content
 *    shown only to crawlers (SEO-spam cloaking) can be compared. Nothing is submitted, no script is executed, and
 *    external scripts are never downloaded: only their host names are read from the page.
 *  - Indicators: hidden iframes, scripts from IP addresses or throwaway TLDs, obfuscated inline scripts, browser
 *    crypto-miners, search-engine-referrer redirects, and spam keywords (hidden, or cloaked for crawlers).
 *    Every external script host is also listed (info), so a host that appears suddenly stands out.
 *  - These are heuristics: findings are "suspected" or "likely", never "confirmed". No blocklist feed is consulted.
 *  - Evidence holds host names, pattern names, counts and a SHA-256 of the page, never page content.
 *  - At most 64 KB of each page is read; a cut-short page is noted in evidence.
 *  - Fails closed: 429, 5xx, a non-HTML answer or a network error is an error, never "no signs of compromise".
 */

export const CRAWLER_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
export const MAX_HOST_FINDINGS = 30;

export type Fetch = (url: string, ctx: CheckContext, opts: { crawler: boolean }) => Promise<FetchResult>;
const defaultFetch: Fetch = (url, ctx, { crawler }) => guardedGet(url, {
  ...ctx.egress, onHop: ctx.onHop, timeoutMs: Math.min(ctx.timeoutMs, 10000), truncateAt: EGRESS_MAX_BODY,
  accept: "text/html, application/xhtml+xml;q=0.9", tlsLenient: true, ...(crawler ? { userAgent: CRAWLER_UA } : {}),
});

const SUSPICIOUS_TLDS = ["xyz", "top", "tk", "ml", "ga", "cf", "gq", "icu", "cyou", "buzz", "click", "rest", "monster"];
const MINERS = ["coinhive", "cryptonight", "coinimp", "crypto-loot", "cryptoloot", "webminepool", "minero.cc", "jsecoin", "deepminer", "webmine.pro", "monerominer"];
export const SPAM_TERMS = ["casino", "viagra", "cialis", "levitra", "slot gacor", "slot online", "judi online", "togel", "replica watches", "payday loan", "porn", "escort service", "cheap jerseys", "buy followers", "essay writing service", "kamagra"];
const OBFUSCATION: ReadonlyArray<[string, RegExp]> = [
  ["packer_eval", /eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e/],
  ["eval_atob", /eval\s*\(\s*atob\s*\(/],
  ["write_unescape", /document\.write\s*\(\s*unescape\s*\(/],
  ["hex_escape_run", /(?:\\x[0-9a-fA-F]{2}){40,}/],
  ["hex_identifiers", /(?:_0x[0-9a-f]{4,}[\s\S]{0,200}){10,}/],
  ["charcode_blob", /String\.fromCharCode\s*\(\s*(?:\d{2,3}\s*,\s*){20,}/],
];

const sha256 = (s: string) => createHash("sha256").update(s, "utf8").digest("hex");
const key = (s: string) => s.toLowerCase().replace(/[^a-z0-9_.-]/g, "-").slice(0, 80);

/** The site's own registrable-ish suffix (last two labels), so its subdomains and CDN-less assets are not "external". */
const siteOf = (host: string) => host.toLowerCase().split(".").slice(-2).join(".");

export interface PageSignals {
  scriptHosts: string[]; hiddenIframeHosts: string[]; obfuscation: string[]; miners: string[];
  referrerRedirect: boolean; visibleSpam: string[]; hiddenSpam: string[]; inlineScripts: number;
}

const HIDDEN_STYLE = /display\s*:\s*none|visibility\s*:\s*hidden|(?:left|top)\s*:\s*-\d{3,}px|font-size\s*:\s*0(?:px)?\s*(?:;|$)|opacity\s*:\s*0(?:\.0+)?\s*(?:;|$)/i;

function hostOf(src: string, pageHost: string): string | null {
  try {
    const u = new URL(src, `https://${pageHost}/`);
    return u.protocol === "http:" || u.protocol === "https:" ? u.hostname.toLowerCase() : null;
  } catch { return null; }
}

const textOf = (html: string) => html.replace(/<(script|style|noscript)\b[\s\S]*?<\/\1\s*>/gi, " ").replace(/<[^>]+>/g, " ").replace(/&nbsp;/g, " ").toLowerCase();
const termsIn = (text: string) => SPAM_TERMS.filter((t) => new RegExp(`\\b${t.replace(/ /g, "\\s+")}\\b`, "i").test(text));

/** Pure: everything this check reads from one page. */
export function analysePage(html: string, pageHost: string): PageSignals {
  const site = siteOf(pageHost);
  const scriptHosts = new Set<string>();
  for (const m of html.matchAll(/<script\b[^>]*\bsrc\s*=\s*["']?([^"'\s>]+)/gi)) {
    const h = hostOf(m[1], pageHost);
    if (h && h !== pageHost.toLowerCase() && !h.endsWith(`.${site}`) && h !== site) scriptHosts.add(h);
  }
  const hiddenIframeHosts = new Set<string>();
  for (const m of html.matchAll(/<iframe\b([^>]*)>/gi)) {
    const attrs = m[1];
    const style = /\bstyle\s*=\s*["']([^"']*)["']/i.exec(attrs)?.[1] ?? "";
    const tiny = /\b(?:width|height)\s*=\s*["']?[01](?:px)?["'\s>]/i.test(` ${attrs} `) || /(?:width|height)\s*:\s*[01](?:px)?\s*(?:;|$)/i.test(style);
    if (HIDDEN_STYLE.test(style) || tiny) {
      const src = /\bsrc\s*=\s*["']?([^"'\s>]+)/i.exec(attrs)?.[1];
      hiddenIframeHosts.add((src && hostOf(src, pageHost)) || "(no src)");
    }
  }
  const inline = [...html.matchAll(/<script\b(?![^>]*\bsrc\s*=)[^>]*>([\s\S]*?)<\/script\s*>/gi)].map((m) => m[1]);
  const js = inline.join("\n");
  const obfuscation = OBFUSCATION.filter(([, re]) => re.test(js)).map(([n]) => n);
  const lower = html.toLowerCase();
  const miners = MINERS.filter((m) => lower.includes(m));
  const referrerRedirect = inline.some((s) => /document\.referrer/.test(s) && /(?:window\.|document\.|top\.)?location(?:\.href)?\s*(?:=|\.replace\s*\(|\.assign\s*\()/.test(s) && /google|bing|yahoo|yandex|baidu|duckduckgo/i.test(s));
  const hiddenText: string[] = [];
  for (const m of html.matchAll(/<(div|span|p|a|section|ul|li)\b[^>]*\bstyle\s*=\s*["']([^"']*)["'][^>]*>([\s\S]{0,4000}?)<\/\1\s*>/gi)) {
    if (HIDDEN_STYLE.test(m[2])) hiddenText.push(m[3]);
  }
  const hiddenSpam = termsIn(textOf(hiddenText.join(" ")));
  const visibleSpam = termsIn(textOf(html)).filter((t) => !hiddenSpam.includes(t));
  return { scriptHosts: [...scriptHosts].sort(), hiddenIframeHosts: [...hiddenIframeHosts].sort(), obfuscation, miners, referrerRedirect, visibleSpam, hiddenSpam, inlineScripts: inline.length };
}

const REMEDIATION = {
  compromise: "Treat the site as possibly compromised until you know why this is here: compare the served page with your source or last known-good deploy, check recently changed files, plugins and themes, rotate admin and hosting passwords, and restore from a clean build. Then re-run the assessment.",
  host: "Review whether this script host is expected. If nobody on your team added it, find where it is injected (theme, plugin, tag manager, CDN) and remove it. Pin third-party scripts with Subresource Integrity (integrity=…) where you can.",
  tld: "Scripts from short-lived domains on low-cost TLDs are a common sign of injected malware. Confirm the script is yours; if not, remove it and investigate how it was added.",
  obfuscation: "Heavily obfuscated inline JavaScript is a common sign of injected malware, though some vendors obfuscate legitimately. Identify which component emits it; if nobody can account for it, treat the site as compromised.",
  spam: "Spam keywords on the page usually mean injected SEO spam (often in a theme, plugin or database content). Find and remove it, patch the entry point, and ask search engines to re-crawl.",
} as const;

export function compromiseFindings(host: string, user: PageSignals, crawler: PageSignals): FindingCandidate[] {
  const loc = `https://${host}/`;
  const out: FindingCandidate[] = [];
  const f = (issueKey: string, title: string, severity: FindingCandidate["severity"], confidence: FindingCandidate["confidence"], evidence: Record<string, unknown>, remediation: string) =>
    out.push({ issueKey, title, severity, confidence, location: loc, evidence, remediation });

  if (user.hiddenIframeHosts.length) f("hidden_iframe", "Page contains a hidden iframe", "high", "suspected", { iframeHosts: user.hiddenIframeHosts.slice(0, 20) }, REMEDIATION.compromise);
  if (user.miners.length) f("crypto_miner", "Page references a browser crypto-miner", "high", "likely", { patterns: user.miners }, REMEDIATION.compromise);
  if (user.referrerRedirect) f("referrer_redirect", "Inline script redirects visitors who arrive from a search engine", "high", "suspected", { pattern: "document.referrer + location + search-engine name" }, REMEDIATION.compromise);
  if (user.obfuscation.length) {
    const strong = user.obfuscation.some((p) => p === "eval_atob" || p === "write_unescape" || p === "packer_eval");
    f("obfuscated_inline_script", "Page contains obfuscated inline JavaScript", strong ? "high" : "medium", "suspected", { patterns: user.obfuscation }, REMEDIATION.obfuscation);
  }
  const ipHosts = user.scriptHosts.filter(isIpLiteral);
  if (ipHosts.length) f("script_from_ip", "Page loads a script from a bare IP address", "high", "suspected", { hosts: ipHosts.slice(0, 20) }, REMEDIATION.tld);
  const tldHosts = user.scriptHosts.filter((h) => !isIpLiteral(h) && SUSPICIOUS_TLDS.includes(h.split(".").pop() ?? ""));
  if (tldHosts.length) f("script_suspicious_tld", "Page loads a script from a domain on a TLD often used for malware", "medium", "suspected", { hosts: tldHosts.slice(0, 20) }, REMEDIATION.tld);

  if (user.hiddenSpam.length) f("seo_spam_hidden", "Hidden spam keywords on the page", "high", "likely", { terms: user.hiddenSpam }, REMEDIATION.spam);
  if (user.visibleSpam.length >= 2) f("seo_spam_visible", "Spam keywords on the page", "medium", "suspected", { terms: user.visibleSpam }, REMEDIATION.spam);
  const userTerms = new Set([...user.hiddenSpam, ...user.visibleSpam]);
  const cloaked = [...crawler.hiddenSpam, ...crawler.visibleSpam].filter((t) => !userTerms.has(t));
  const crawlerOnlyHosts = crawler.scriptHosts.filter((h) => !user.scriptHosts.includes(h));
  if (cloaked.length) f("seo_spam_cloaked", "Spam keywords shown only to search-engine crawlers (cloaking)", "high", "likely", { terms: cloaked, crawlerOnlyScriptHosts: crawlerOnlyHosts.slice(0, 20) }, REMEDIATION.spam);
  else if (crawlerOnlyHosts.length) f("crawler_only_scripts", "Scripts served only to search-engine crawlers", "medium", "suspected", { hosts: crawlerOnlyHosts.slice(0, 20) }, REMEDIATION.compromise);

  const room = Math.max(0, Math.min(MAX_HOST_FINDINGS, 50 - out.length));
  for (const h of user.scriptHosts.slice(0, room)) {
    f(`script_host.${key(h)}`.slice(0, 80), `Page loads scripts from ${h}`.slice(0, 200), "info", "confirmed", { host: h }, REMEDIATION.host);
  }
  return out;
}

export function createCompromiseAdapter(fetch: Fetch = defaultFetch): CheckAdapter {
  return {
    id: "http.compromise@1", checkKey: "http.compromise", target: "host",
    async run(ctx): Promise<CheckResult> {
      const url = `https://${ctx.host}/`;
      const pages: Record<string, unknown>[] = [];
      try {
        const got: FetchResult[] = [];
        for (const crawler of [false, true]) {
          const r = await fetch(url, ctx, { crawler });
          pages.push({ view: crawler ? "crawler" : "user", status: r.status, contentType: r.contentType?.slice(0, 80) ?? null, bytes: Buffer.byteLength(r.body, "utf8"), truncated: r.truncated, sha256: sha256(r.body), redirects: r.redirects });
          if (r.status === 429 || r.status >= 500) return { status: "error", reason: `http_${r.status}`, evidence: { pages } };
          if (r.status >= 400) return { status: "error", reason: `http_${r.status}: the home page could not be read`, evidence: { pages } };
          if (!/html/i.test(r.contentType ?? "")) return { status: "error", reason: "not_html: the home page is not HTML, so it could not be inspected", evidence: { pages } };
          got.push(r);
        }
        const user = analysePage(got[0].body, ctx.host);
        const crawler = analysePage(got[1].body, ctx.host);
        const findings = compromiseFindings(ctx.host, user, crawler);
        return {
          status: "ok", findings,
          evidence: {
            pages, externalScriptHosts: user.scriptHosts.length, inlineScripts: user.inlineScripts,
            ...(got.some((r) => r.truncated) ? { note: `Only the first ${EGRESS_MAX_BODY / 1024} KB of the page was inspected.` } : {}),
            scope: "Home page only; external scripts are not downloaded. Heuristic: absence of signs is not proof of a clean site.",
          },
        };
      } catch (e) {
        if (e instanceof EgressError) return { status: "error", reason: `egress:${e.code}`, evidence: { pages } };
        throw e;
      }
    },
  };
}
