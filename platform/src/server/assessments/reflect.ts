import { randomBytes } from "node:crypto";
import { EgressError, guardedGet, type FetchResult } from "../net/egress";
import type { CheckAdapter, CheckContext, CheckResult, FindingCandidate } from "./checks";

/**
 * pt.reflect (automated penetration test, step 2, class A2: verified owners who turned on intrusive checks only).
 *  1. Crawl: same host only, GET only, at most MAX_PAGES pages and two levels from the home page, collecting links and
 *     GET forms that carry query parameters. Paths and parameters that could change state (logout, delete, cart,
 *     checkout, account, admin, nonces, tokens...) are never requested.
 *  2. Reflected XSS: one parameter at a time gets a harmless marker (letters plus a made-up <ruya…> tag, no script).
 *     A finding needs the marker back unescaped in an HTML response, so a browser would parse it as markup.
 *  3. Open redirect: redirect-like parameters get https://redirect-check.ruyashield.example/ (a reserved, unreachable
 *     domain). A finding needs a 3xx whose Location points to that host. Redirects are never followed.
 * At most 5 requests a second, at most 4 KB read per response for tests (64 KB for crawled pages), no POST, no
 * credentials. Fails closed: if the home page cannot be read, or most test requests fail, the result is an error.
 */

export const MAX_PAGES = 30;
export const MAX_TESTS = 25;
export const PAGE_BYTES = 65536;
const TEST_BYTES = 4096;
const GAP_MS = 200;
export const REDIRECT_PROBE_HOST = "redirect-check.ruyashield.example";

const UNSAFE_PATH = /logout|log-out|signout|sign-out|delete|remove|unsubscribe|cart|checkout|basket|order|payment|pay\b|account|profile|admin|wp-login|wp-admin|login|register|reset|password|\.(?:jpe?g|png|gif|webp|svg|ico|css|js|pdf|zip|gz|mp4|woff2?)(?:$|\?)/i;
const UNSAFE_PARAM = /^(?:_?wpnonce|nonce|token|csrf|_token|action|add-to-cart|remove_item|delete|password|pass|pwd|email|key|session|sid)$/i;
const REDIRECT_PARAM = /^(?:url|uri|redirect|redirect_to|redirect_uri|redirecturl|return|return_to|returnurl|returnto|next|goto|go|dest|destination|continue|target|to|out|r|u|link|forward)$/i;

export type Fetch = (url: string, ctx: CheckContext, bytes: number) => Promise<FetchResult>;
const defaultFetch: Fetch = (url, ctx, bytes) =>
  guardedGet(url, { ...ctx.egress, onHop: ctx.onHop, timeoutMs: Math.min(ctx.timeoutMs, 8000), truncateAt: bytes, accept: "text/html, */*;q=0.5", followRedirects: false, tlsLenient: true });

export interface Candidate { url: URL; param: string }

/** Same-host links and GET-form targets with query parameters, found in one page. Pure. */
export function linksIn(html: string, page: URL): { pages: URL[]; candidates: Candidate[] } {
  const pages: URL[] = [];
  const candidates: Candidate[] = [];
  const resolve = (href: string) => { try { const u = new URL(href.replace(/&amp;/g, "&"), page); u.hash = ""; return u; } catch { return null; } };
  const keep = (u: URL | null) => !!u && u.hostname === page.hostname && /^https?:$/.test(u.protocol) && !UNSAFE_PATH.test(u.pathname + u.search);
  for (const m of html.matchAll(/<a\s[^>]*href\s*=\s*["']([^"'#]+)["']/gi)) {
    const u = resolve(m[1]);
    if (!keep(u)) continue;
    pages.push(u!);
    for (const p of u!.searchParams.keys()) if (!UNSAFE_PARAM.test(p)) candidates.push({ url: u!, param: p });
  }
  for (const f of html.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/gi)) {
    const method = /method\s*=\s*["']?post/i.test(f[1]) ? "post" : "get";
    if (method !== "get") continue;
    const u = resolve(/action\s*=\s*["']([^"']*)["']/i.exec(f[1])?.[1] || page.href);
    if (!keep(u)) continue;
    const names = [...f[2].matchAll(/<(?:input|select|textarea)\b[^>]*name\s*=\s*["']([^"']+)["'][^>]*>/gi)]
      .filter((i) => !/type\s*=\s*["']?(?:hidden|password|submit|file)/i.test(i[0])).map((i) => i[1]);
    for (const name of names) if (!UNSAFE_PARAM.test(name)) { const t = new URL(u!); t.searchParams.set(name, "test"); candidates.push({ url: t, param: name }); }
  }
  return { pages, candidates };
}

/** Whether the marker came back as markup (not HTML-escaped) in an HTML response. Pure. */
export const reflectsUnescaped = (r: FetchResult, marker: string) => /html/i.test(r.contentType ?? "") && r.body.includes(`<${marker}>`);

/** Whether a response redirects to the probe host. Pure. */
export function redirectsToProbe(r: FetchResult): boolean {
  if (r.status < 300 || r.status >= 400) return false;
  const loc = String(r.headers.location ?? "").trim();
  try { return new URL(loc.startsWith("//") ? `https:${loc}` : loc).hostname === REDIRECT_PROBE_HOST; } catch { return false; }
}

/** Same-host crawl, at most MAX_PAGES pages and two levels deep. homeFailed is the home page's 429/5xx status, if any. */
export async function crawlSite(home: URL, get: (url: string) => Promise<FetchResult>): Promise<{ crawled: number; homeFailed: number | null; candidates: Map<string, Candidate> }> {
  const queue: { url: URL; depth: number }[] = [{ url: home, depth: 0 }];
  const seenPages = new Set<string>();
  const candidates = new Map<string, Candidate>();
  let crawled = 0;
  while (queue.length && crawled < MAX_PAGES) {
    const { url, depth } = queue.shift()!;
    const key = url.origin + url.pathname + url.search;
    if (seenPages.has(key)) continue;
    seenPages.add(key);
    const r = await get(url.href);
    crawled++;
    if (crawled === 1 && (r.status === 429 || r.status >= 500)) return { crawled, homeFailed: r.status, candidates };
    if (r.status !== 200 || !/html/i.test(r.contentType ?? "")) continue;
    const found = linksIn(r.body, url);
    for (const c of found.candidates) candidates.set(`${c.url.origin}${c.url.pathname}|${c.param}`, c);
    if (depth < 2) for (const p of found.pages) queue.push({ url: p, depth: depth + 1 });
  }
  return { crawled, homeFailed: null, candidates };
}

export function createReflectAdapter(fetch: Fetch = defaultFetch, marker: () => string = () => `ruya${randomBytes(5).toString("hex")}`): CheckAdapter {
  return {
    id: "pt.reflect@1", checkKey: "pt.reflect", target: "host",
    async run(ctx): Promise<CheckResult> {
      const sleep = ctx.sleep ?? ((ms: number) => new Promise((r) => setTimeout(r, ms)));
      let sent = 0;
      const get = async (url: string, bytes: number) => { if (sent++) await sleep(GAP_MS); return fetch(url, ctx, bytes); };
      const home = new URL(`https://${ctx.host}/`);
      const out: FindingCandidate[] = [];
      let crawled = 0;
      try {
        // 1. Crawl.
        const crawl = await crawlSite(home, (u) => get(u, PAGE_BYTES));
        crawled = crawl.crawled;
        if (crawl.homeFailed) return { status: "error", reason: `http_${crawl.homeFailed}`, evidence: { crawled } };
        const candidates = crawl.candidates;

        // 2 and 3. One parameter at a time; redirect-like parameters get the redirect probe as well.
        const tests = [...candidates.values()].slice(0, MAX_TESTS);
        let failures = 0; let requests = 0;
        for (const c of tests) {
          const m = marker();
          const xss = new URL(c.url); xss.searchParams.set(c.param, `${m}<${m}>`);
          const r = await get(xss.href, TEST_BYTES); requests++;
          if (r.status === 429 || r.status >= 500) failures++;
          else if (reflectsUnescaped(r, m)) {
            out.push({ issueKey: "reflected_xss", title: `Reflected cross-site scripting in parameter "${c.param}" (${c.url.pathname})`, severity: "medium", confidence: "likely",
              location: `${c.url.origin}${c.url.pathname}?${c.param}=`.slice(0, 300),
              evidence: { parameter: c.param, path: c.url.pathname, status: r.status, contentType: r.contentType?.slice(0, 80) ?? null, markerReflectedAsMarkup: true },
              remediation: `Escape "${c.param}" for the place it is printed (esc_html / esc_attr in WordPress, htmlspecialchars in PHP, the template engine's default escaping elsewhere) and add a Content-Security-Policy that blocks inline scripts. Re-test after the fix.` });
          }
          if (REDIRECT_PARAM.test(c.param)) {
            const redir = new URL(c.url); redir.searchParams.set(c.param, `https://${REDIRECT_PROBE_HOST}/`);
            const rr = await get(redir.href, TEST_BYTES); requests++;
            if (rr.status === 429 || rr.status >= 500) failures++;
            else if (redirectsToProbe(rr)) {
              out.push({ issueKey: "open_redirect", title: `Open redirect through parameter "${c.param}" (${c.url.pathname})`, severity: "medium",
                location: `${c.url.origin}${c.url.pathname}?${c.param}=`.slice(0, 300),
                evidence: { parameter: c.param, path: c.url.pathname, status: rr.status, redirectsToOutsideHost: true },
                remediation: `Only redirect to paths on your own site or to an allow-list of hosts (wp_safe_redirect in WordPress). Never redirect to a full URL taken from "${c.param}". Re-test after the fix.` });
            }
          }
        }
        if (requests >= 4 && failures * 2 > requests) return { status: "error", reason: "too_many_failed_requests", evidence: { crawled, requests, failures } };
        return { status: "ok", findings: out, evidence: { crawled, parametersTested: tests.length, requests, failures } };
      } catch (e) {
        if (e instanceof EgressError) return { status: "error", reason: e.code === "network" ? "host_unreachable" : e.code, evidence: { error: e.message.slice(0, 200), crawled } };
        throw e;
      }
    },
  };
}
