import type { FetchLike } from "./deps";
import type { CheckAdapter, CheckResult, FindingCandidate } from "./checks";

/**
 * web.blocklist (class P): is this host on a public malware / phishing blocklist?
 *  - Google Safe Browsing Lookup API v4 (key: GOOGLE_SAFE_BROWSING_KEY). Being listed means Chrome, Firefox and
 *    Safari show a red warning page to visitors. Google's terms allow non-commercial use only; commercial products
 *    need the paid Google Web Risk API.
 *  - abuse.ch URLhaus host lookup (key: URLHAUS_AUTH_KEY): malware download URLs reported on this host.
 *  - Only the host name and its two home-page URLs leave the box. Nothing is sent to, or fetched from, the asset.
 *  - Fails closed: no key configured, an HTTP error, a timeout or a malformed answer is an error, never "not listed".
 *    Every configured source must answer; one failing source makes the whole check an error.
 */

export const SAFE_BROWSING_HOST = "safebrowsing.googleapis.com";
export const URLHAUS_HOST = "urlhaus-api.abuse.ch";
const MAX_RESPONSE_BYTES = 256 * 1024;

export interface BlocklistKeys { safeBrowsing?: string; urlhaus?: string }
const envKeys = (): BlocklistKeys => ({
  safeBrowsing: process.env.GOOGLE_SAFE_BROWSING_KEY?.trim() || undefined,
  urlhaus: process.env.URLHAUS_AUTH_KEY?.trim() || undefined,
});

class BlocklistError extends Error {}
const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

async function call(fetchImpl: FetchLike, host: string, url: string, init: { method: string; headers: Record<string, string>; body: string }, timeoutMs: number, tag: string): Promise<unknown> {
  const u = new URL(url);
  if (u.protocol !== "https:" || u.host !== host) throw new BlocklistError(`${tag}_egress_not_allowed`);
  let res;
  try { res = await fetchImpl(u.toString(), { ...init, redirect: "error", signal: AbortSignal.timeout(timeoutMs) }); }
  catch { throw new BlocklistError(`${tag}_unreachable`); }
  // Never put the response body or the URL (it can carry the key) into the reason.
  if (!res.ok) throw new BlocklistError(`${tag}_http_${res.status}`);
  const text = await res.text();
  if (text.length > MAX_RESPONSE_BYTES) throw new BlocklistError(`${tag}_response_too_large`);
  try { return JSON.parse(text); } catch { throw new BlocklistError(`${tag}_malformed_response`); }
}

const SB_TYPES = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"] as const;
const SB_LABEL: Record<string, string> = {
  MALWARE: "malware", SOCIAL_ENGINEERING: "phishing / deceptive content", UNWANTED_SOFTWARE: "unwanted software", POTENTIALLY_HARMFUL_APPLICATION: "harmful applications",
};

export async function safeBrowsingLookup(fetchImpl: FetchLike, key: string, host: string, timeoutMs: number): Promise<string[]> {
  const urls = [`https://${host}/`, `http://${host}/`];
  const r = await call(fetchImpl, SAFE_BROWSING_HOST, `https://${SAFE_BROWSING_HOST}/v4/threatMatches:find?key=${encodeURIComponent(key)}`, {
    method: "POST", headers: { "content-type": "application/json", "user-agent": "RuyaShield-blocklist/1" },
    body: JSON.stringify({
      client: { clientId: "ruyashield", clientVersion: "1" },
      threatInfo: { threatTypes: SB_TYPES, platformTypes: ["ANY_PLATFORM"], threatEntryTypes: ["URL"], threatEntries: urls.map((url) => ({ url })) },
    }),
  }, timeoutMs, "safe_browsing");
  if (!isObj(r)) throw new BlocklistError("safe_browsing_malformed_response");
  if (r.matches === undefined) return [];
  if (!Array.isArray(r.matches)) throw new BlocklistError("safe_browsing_malformed_response");
  const types = new Set<string>();
  for (const m of r.matches) {
    if (!isObj(m) || typeof m.threatType !== "string") throw new BlocklistError("safe_browsing_malformed_response");
    types.add(m.threatType);
  }
  return [...types].sort();
}

export interface UrlhausHit { online: number; total: number; threats: string[]; firstSeen: string | null; reference: string | null }

export async function urlhausLookup(fetchImpl: FetchLike, key: string, host: string, timeoutMs: number): Promise<UrlhausHit | null> {
  const r = await call(fetchImpl, URLHAUS_HOST, `https://${URLHAUS_HOST}/v1/host/`, {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", "auth-key": key, "user-agent": "RuyaShield-blocklist/1" },
    body: new URLSearchParams({ host }).toString(),
  }, timeoutMs, "urlhaus");
  if (!isObj(r) || typeof r.query_status !== "string") throw new BlocklistError("urlhaus_malformed_response");
  if (r.query_status === "no_results") return null;
  if (r.query_status !== "ok") throw new BlocklistError(`urlhaus_${r.query_status.replace(/[^a-z_]/gi, "").slice(0, 40)}`);
  const list = Array.isArray(r.urls) ? r.urls.filter(isObj) : [];
  const threats = [...new Set(list.map((u) => u.threat).filter((t): t is string => typeof t === "string"))].map((t) => t.slice(0, 60)).sort().slice(0, 10);
  const dates = list.map((u) => u.date_added).filter((d): d is string => typeof d === "string").sort();
  const total = typeof r.url_count === "string" || typeof r.url_count === "number" ? Number(r.url_count) || list.length : list.length;
  const ref = typeof r.urlhaus_reference === "string" && r.urlhaus_reference.startsWith("https://urlhaus.abuse.ch/") ? r.urlhaus_reference.slice(0, 200) : null;
  return { online: list.filter((u) => u.url_status === "online").length, total, threats, firstSeen: dates[0]?.slice(0, 10) ?? null, reference: ref };
}

export function createBlocklistAdapter(deps: { fetch?: FetchLike; keys?: () => BlocklistKeys } = {}): CheckAdapter {
  return {
    id: "web.blocklist@1", checkKey: "web.blocklist", target: "host",
    async run(ctx): Promise<CheckResult> {
      const host = ctx.host.toLowerCase();
      const keys = (deps.keys ?? envKeys)();
      const sources = [keys.safeBrowsing && "google_safe_browsing", keys.urlhaus && "urlhaus"].filter(Boolean) as string[];
      if (!sources.length) {
        return { status: "error", reason: "blocklist_not_configured", evidence: { note: "Set GOOGLE_SAFE_BROWSING_KEY and/or URLHAUS_AUTH_KEY on the server to enable this check. Until then this host's blocklist status is unknown, not clean." } };
      }
      const fetchImpl = deps.fetch ?? (globalThis.fetch as unknown as FetchLike);
      const timeout = Math.min(ctx.timeoutMs, 15_000);
      const findings: FindingCandidate[] = [];
      const evidence: Record<string, unknown> = { sources };
      try {
        if (keys.safeBrowsing) {
          const types = await safeBrowsingLookup(fetchImpl, keys.safeBrowsing, host, timeout);
          evidence.safeBrowsing = { listed: types.length > 0, threatTypes: types };
          for (const t of types) {
            const severe = t === "MALWARE" || t === "SOCIAL_ENGINEERING";
            findings.push({
              issueKey: `safe_browsing.${t.toLowerCase()}`.slice(0, 80), title: `Google Safe Browsing flags this site for ${SB_LABEL[t] ?? t.toLowerCase()}`,
              severity: severe ? "critical" : "high", confidence: "confirmed", location: host,
              evidence: { source: "google_safe_browsing", threatType: t },
              remediation: "Browsers are showing visitors a red warning page. Find and remove the malicious content (check the 'Signs of compromise' and 'Exposed files' results, recently changed files, admin accounts and plugins), rotate credentials, then request a review in Google Search Console > Security issues. The listing is removed only after Google re-checks the site.",
            });
          }
        }
        if (keys.urlhaus) {
          const hit = await urlhausLookup(fetchImpl, keys.urlhaus, host, timeout);
          evidence.urlhaus = hit ? { listed: true, online: hit.online, total: hit.total, threats: hit.threats } : { listed: false };
          if (hit) {
            const active = hit.online > 0;
            findings.push({
              issueKey: active ? "urlhaus.active" : "urlhaus.historic", confidence: "confirmed", location: host,
              title: active ? `URLhaus lists ${hit.online} live malware URL${hit.online === 1 ? "" : "s"} on this host` : "URLhaus has past malware reports for this host (none online now)",
              severity: active ? "critical" : "medium",
              evidence: { source: "urlhaus", online: hit.online, total: hit.total, threats: hit.threats, firstSeen: hit.firstSeen, ...(hit.reference ? { reference: hit.reference } : {}) },
              remediation: active
                ? "Malware is being served from this host right now. Take the listed files offline, find how they were uploaded (vulnerable plugin, stolen credentials, open upload form), rotate credentials and patch. URLhaus marks URLs offline automatically once they stop responding."
                : "These URLs no longer respond, but the host was used to spread malware before. Confirm the entry point was closed and the credentials used at the time were rotated.",
            });
          }
        }
      } catch (e) {
        if (e instanceof BlocklistError) return { status: "error", reason: e.message, evidence };
        throw e;
      }
      return { status: "ok", findings, evidence };
    },
  };
}
