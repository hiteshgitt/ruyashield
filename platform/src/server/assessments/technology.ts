import https from "node:https";
import { EgressError, guardedGet, type FetchResult } from "../net/egress";
import type { CheckAdapter, CheckContext, FindingCandidate } from "./checks";

// web.technology@1: what the site is built with, from ONE request to the home page (headers, cookies, the
// generator tag and script/style paths; nothing is executed and no other path is requested). The stack is kept
// in the evidence (the asset page and Zealot read it); findings are raised only for software that is known to
// be risky: WordPress behind the current release, an end-of-life PHP, and jQuery older than 3.5.
//
// The only other request is to api.wordpress.org for the current WordPress version (reference data; nothing
// about the asset is sent), and only when the site is WordPress with a visible version.

export interface Technology { name: string; category: "platform" | "framework" | "language" | "server" | "cdn" | "library" | "analytics"; version: string | null; evidence: string }

type Headers = Record<string, string | string[] | undefined>;
const one = (h: Headers, k: string) => { const v = h[k]; return Array.isArray(v) ? v.join(", ") : v ?? ""; };

const READ_BYTES = 256 * 1024;
const PHP_SUPPORTED_FROM: [number, number] = [8, 2]; // 8.1 and older are past end of life (php.net/supported-versions)

/** Every technology the response shows, de-duplicated by name (first evidence wins). */
export function detectTechnologies(h: Headers, html: string): Technology[] {
  const out = new Map<string, Technology>();
  const add = (name: string, category: Technology["category"], version: string | null, evidence: string) => {
    if (!out.has(name)) out.set(name, { name, category, version, evidence });
  };
  const server = one(h, "server");
  const powered = one(h, "x-powered-by");
  const cookies = one(h, "set-cookie");
  let m: RegExpMatchArray | null;

  // Platforms
  if ((m = html.match(/<meta[^>]+name=["']generator["'][^>]+content=["']WordPress\s*([\d.]+)?/i))) add("WordPress", "platform", m[1] ?? null, "generator meta tag");
  else if (/\/wp-content\/|\/wp-includes\//i.test(html)) add("WordPress", "platform", null, "wp-content paths");
  if ((m = html.match(/<meta[^>]+name=["']generator["'][^>]+content=["']Drupal\s*([\d.]+)?/i)) || /X-Drupal|drupal-settings-json/i.test(html + one(h, "x-drupal-cache") + one(h, "x-generator"))) add("Drupal", "platform", m?.[1] ?? null, "generator / Drupal markers");
  if ((m = html.match(/<meta[^>]+name=["']generator["'][^>]+content=["']Joomla!?\s*([\d.]+)?/i))) add("Joomla", "platform", m[1] ?? null, "generator meta tag");
  if (/cdn\.shopify\.com|Shopify\.theme/i.test(html) || one(h, "x-shopify-stage")) add("Shopify", "platform", null, "Shopify assets");
  if (/static\.wixstatic\.com|wix-bolt/i.test(html)) add("Wix", "platform", null, "Wix assets");
  if (/static1\.squarespace\.com|Squarespace/i.test(html)) add("Squarespace", "platform", null, "Squarespace assets");
  if ((m = html.match(/<meta[^>]+name=["']generator["'][^>]+content=["']Ghost\s*([\d.]+)?/i))) add("Ghost", "platform", m[1] ?? null, "generator meta tag");
  if (/Mage\.Cookies|\/static\/version\d+\/frontend\//i.test(html)) add("Magento", "platform", null, "Magento static paths");

  // Frameworks
  if (/__NEXT_DATA__|\/_next\/static\//.test(html) || /Next\.js/i.test(powered)) add("Next.js", "framework", null, "Next.js build assets");
  if (/__NUXT__|\/_nuxt\//.test(html)) add("Nuxt", "framework", null, "Nuxt build assets");
  if (/laravel_session=/i.test(cookies)) add("Laravel", "framework", null, "laravel_session cookie");
  if (/csrftoken=/i.test(cookies) && /csrfmiddlewaretoken/i.test(html)) add("Django", "framework", null, "Django CSRF token");
  if (/_rails_session|csrf-param["'][^>]+authenticity_token/i.test(cookies + html)) add("Ruby on Rails", "framework", null, "Rails session / CSRF meta");
  if ((m = one(h, "x-aspnet-version").match(/([\d.]+)/)) || /ASP\.NET/i.test(powered) || /ASP\.NET_SessionId/i.test(cookies)) add("ASP.NET", "framework", m?.[1] ?? null, "ASP.NET headers / cookie");
  if (/^Express$/i.test(powered.trim())) add("Express", "framework", null, "X-Powered-By: Express");

  // Language
  if ((m = powered.match(/PHP\/([\d.]+)/i))) add("PHP", "language", m[1], "X-Powered-By header");
  else if (/PHPSESSID=/i.test(cookies) || out.has("WordPress") || out.has("Laravel") || out.has("Drupal") || out.has("Joomla")) add("PHP", "language", null, "PHP application");

  // Server and CDN
  if ((m = server.match(/nginx(?:\/([\d.]+))?/i))) add("nginx", "server", m[1] ?? null, "Server header");
  if ((m = server.match(/Apache(?:\/([\d.]+))?/i))) add("Apache", "server", m[1] ?? null, "Server header");
  if (/LiteSpeed/i.test(server)) add("LiteSpeed", "server", null, "Server header");
  if ((m = server.match(/Microsoft-IIS\/([\d.]+)/i))) add("IIS", "server", m[1], "Server header");
  if (one(h, "cf-ray") || /cloudflare/i.test(server)) add("Cloudflare", "cdn", null, "cf-ray header");
  if (one(h, "x-vercel-id")) add("Vercel", "cdn", null, "x-vercel-id header");
  if (one(h, "x-amz-cf-id")) add("Amazon CloudFront", "cdn", null, "x-amz-cf-id header");
  if (/fastly/i.test(one(h, "x-served-by") + one(h, "via"))) add("Fastly", "cdn", null, "x-served-by / via header");
  if (/akamai/i.test(server + one(h, "x-akamai-transformed"))) add("Akamai", "cdn", null, "Akamai headers");
  if (one(h, "x-nf-request-id")) add("Netlify", "cdn", null, "x-nf-request-id header");

  // Libraries and analytics
  if ((m = html.match(/jquery[.-]?(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js/i)) || (m = html.match(/jquery(?:\.min)?\.js\?ver=(\d+\.\d+(?:\.\d+)?)/i))) add("jQuery", "library", m[1], "script path");
  else if (/jquery(\.min)?\.js/i.test(html)) add("jQuery", "library", null, "script path");
  if (/googletagmanager\.com\/gtm\.js/i.test(html)) add("Google Tag Manager", "analytics", null, "GTM script");
  if (/googletagmanager\.com\/gtag\/js|google-analytics\.com/i.test(html)) add("Google Analytics", "analytics", null, "gtag script");
  return [...out.values()];
}

const parse = (v: string | null) => (v ? v.split(".").map((x) => Number(x) || 0) : null);
const older = (a: number[], b: number[]) => {
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const x = a[i] ?? 0, y = b[i] ?? 0;
    if (x !== y) return x < y;
  }
  return false;
};

/** Findings for risky versions. `latestWordPress` is the current release, or null when unknown. */
export function technologyFindings(url: string, tech: Technology[], latestWordPress: string | null): FindingCandidate[] {
  const out: FindingCandidate[] = [];
  const wp = tech.find((t) => t.name === "WordPress");
  if (wp?.version && latestWordPress && older(parse(wp.version)!, parse(latestWordPress)!)) {
    const a = parse(wp.version)!, b = parse(latestWordPress)!;
    const behindMinor = a[0] < b[0] || b[1] - a[1] >= 2;
    out.push({
      issueKey: "wordpress_outdated", title: `WordPress ${wp.version} is out of date (latest ${latestWordPress})`,
      severity: behindMinor ? "high" : "medium", location: url,
      evidence: { detected: wp.version, latest: latestWordPress, source: wp.evidence },
      remediation: `Update WordPress to ${latestWordPress} (Dashboard > Updates), after a backup. Older releases miss security fixes; turn on automatic minor updates.`,
    });
  }
  const php = tech.find((t) => t.name === "PHP" && t.version);
  if (php?.version) {
    const v = parse(php.version)!;
    if (older([v[0], v[1]], PHP_SUPPORTED_FROM)) {
      out.push({
        issueKey: "php_end_of_life", title: `PHP ${v[0]}.${v[1]} is past end of life`, severity: "medium", location: url,
        evidence: { detected: php.version, supportedFrom: PHP_SUPPORTED_FROM.join("."), source: php.evidence },
        remediation: `Upgrade to a supported PHP version (${PHP_SUPPORTED_FROM.join(".")} or newer) in your hosting panel, after testing the site on it. End-of-life PHP gets no security fixes.`,
      });
    }
  }
  const jq = tech.find((t) => t.name === "jQuery" && t.version);
  if (jq?.version && older(parse(jq.version)!, [3, 5, 0])) {
    out.push({
      issueKey: "jquery_outdated", title: `jQuery ${jq.version} has known cross-site scripting flaws`, severity: "medium", confidence: "likely",
      location: url, evidence: { detected: jq.version, fixedIn: "3.5.0", advisories: ["CVE-2020-11022", "CVE-2020-11023"], source: jq.evidence },
      remediation: "Update jQuery to 3.5.0 or newer (for WordPress, update the theme or plugin that loads this copy). Check pages that pass user input to .html(), .append() and similar calls.",
    });
  }
  return out;
}

export type LatestWordPress = () => Promise<string | null>;
/** Current WordPress release from api.wordpress.org; null when it cannot be read (no finding is raised then). */
export const fetchLatestWordPress: LatestWordPress = () => new Promise((resolve) => {
  // node:https rather than fetch: fetch gives each address 250 ms to connect, which fails on slow links.
  const req = https.get("https://api.wordpress.org/core/version-check/1.7/", { timeout: 8000, autoSelectFamilyAttemptTimeout: 2000 } as https.RequestOptions, (res) => {
    if (res.statusCode !== 200) { res.resume(); return resolve(null); }
    let body = "";
    res.setEncoding("utf8");
    res.on("data", (d: string) => { body += d; if (body.length > 64 * 1024) req.destroy(); });
    res.on("end", () => {
      try {
        const data = JSON.parse(body) as { offers?: { version?: string; response?: string }[] };
        const v = data.offers?.find((o) => o.response === "upgrade" || o.response === "latest")?.version ?? data.offers?.[0]?.version ?? null;
        resolve(v && /^\d+\.\d+(\.\d+)?$/.test(v) ? v : null);
      } catch { resolve(null); }
    });
  });
  req.on("timeout", () => req.destroy());
  req.on("error", () => resolve(null));
});

export type PageFetch = (url: string, ctx: CheckContext) => Promise<FetchResult>;
const defaultFetch: PageFetch = (url, ctx) => guardedGet(url, { ...ctx.egress, onHop: ctx.onHop, timeoutMs: Math.min(ctx.timeoutMs, 15000), accept: "text/html,*/*;q=0.5", tlsLenient: true, truncateAt: READ_BYTES });

export function createTechnologyAdapter(deps: { fetch?: PageFetch; latestWordPress?: LatestWordPress } = {}): CheckAdapter {
  const get = deps.fetch ?? defaultFetch;
  const latest = deps.latestWordPress ?? fetchLatestWordPress;
  return {
    id: "web.technology@1", checkKey: "web.technology",
    async run(c) {
      const url = `https://${c.host}/`;
      let r: FetchResult;
      try {
        r = await get(url, c);
      } catch (e) {
        if (e instanceof EgressError) return { status: "error", reason: e.code, evidence: {} };
        throw e;
      }
      if (r.status >= 500) return { status: "error", reason: `http_${r.status}`, evidence: { status: r.status } };
      const html = r.body ?? "";
      const technologies = detectTechnologies(r.headers as Headers, html);
      const wp = technologies.find((t) => t.name === "WordPress" && t.version);
      const latestWordPress = wp ? await latest() : null;
      return {
        status: "ok",
        findings: technologyFindings(r.finalUrl, technologies, latestWordPress),
        evidence: { finalUrl: r.finalUrl, status: r.status, technologies, latestWordPress },
      };
    },
  };
}
