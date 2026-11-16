import { lookupRecords } from "../net/egress";
import type { CheckAdapter, CheckContext, CheckResult, FindingCandidate } from "./checks";
import type { FetchLike } from "./deps";

/**
 * discovery.ct (scanner M5): what Certificate Transparency logs say about a domain.
 *  - Class P: the target is never contacted. The only egress is HTTPS to crt.sh (Cert Spotter as fallback), plus the
 *    CAA lookup the dns.caa check already does.
 *  - Results are cached for 24 hours per domain and calls to each CT source are spaced out, so repeated scans do not
 *    hammer a free public service.
 *  - The main output is a list of subdomains seen in certificates (evidence.suggestedHosts). They are only suggestions:
 *    nothing is scanned until someone adds one as an asset and proves ownership.
 *  - Findings: wildcard certificates (info) and certificates from a CA that the domain's CAA records do not allow (low).
 *  - Fails closed: if neither CT source answers with valid data, or CAA cannot be read, the check is an error.
 */

export interface CtEntry { id: string; issuer: string; caaDomains?: string[]; names: string[]; notBefore: string; notAfter: string }
export interface CtCacheRow { source: CtSource; fetchedAt: Date; entries: CtEntry[]; truncated: boolean }
export interface CtCache {
  get(domain: string): Promise<CtCacheRow | null>;
  put(domain: string, row: CtCacheRow): Promise<void>;
}
export type CtSource = "crt.sh" | "certspotter";

export const CACHE_TTL_MS = 24 * 3600_000;
const ALLOWED_HOSTS = new Set(["crt.sh", "api.certspotter.com"]);
const MAX_RESPONSE_CHARS = 20 * 1024 * 1024;
const MAX_ENTRIES = 5000;
const MAX_SUGGESTIONS = 500;
const MAX_CERTSPOTTER_PAGES = 5;
const DEFAULT_SPACING_MS = 5000;
const HOSTNAME = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/;

export class CtError extends Error {}

// ---------- issuer → CAA identifiers ----------

/** Known public CAs and the CAA "issue" values that authorize them. Order matters: ZeroSSL certificates name Sectigo too. */
export const CAS: readonly { key: string; label: string; re: RegExp; caa: readonly string[] }[] = [
  { key: "letsencrypt", label: "Let's Encrypt", re: /let'?s ?encrypt|internet security research group/i, caa: ["letsencrypt.org"] },
  { key: "zerossl", label: "ZeroSSL", re: /zerossl/i, caa: ["sectigo.com", "zerossl.com"] },
  { key: "sectigo", label: "Sectigo / Comodo", re: /sectigo|comodo|usertrust/i, caa: ["sectigo.com", "comodoca.com", "comodo.com", "usertrust.com", "trust-provider.com"] },
  { key: "digicert", label: "DigiCert", re: /digicert|geotrust|rapidssl|thawte|symantec/i, caa: ["digicert.com", "symantec.com", "geotrust.com", "rapidssl.com", "thawte.com", "digicert.ne.jp"] },
  { key: "globalsign", label: "GlobalSign", re: /globalsign/i, caa: ["globalsign.com"] },
  { key: "google", label: "Google Trust Services", re: /google trust services/i, caa: ["pki.goog", "google.com"] },
  { key: "amazon", label: "Amazon", re: /amazon/i, caa: ["amazon.com", "amazontrust.com", "awstrust.com", "amazonaws.com", "aws.amazon.com"] },
  { key: "godaddy", label: "GoDaddy / Starfield", re: /go ?daddy|starfield/i, caa: ["godaddy.com", "starfieldtech.com"] },
  { key: "entrust", label: "Entrust", re: /entrust/i, caa: ["entrust.net", "affirmtrust.com"] },
  { key: "buypass", label: "Buypass", re: /buypass/i, caa: ["buypass.com", "buypass.no"] },
  { key: "sslcom", label: "SSL.com", re: /ssl\.com|ssl corporation/i, caa: ["ssl.com"] },
];

export function caOf(e: Pick<CtEntry, "issuer" | "caaDomains">): { key: string; label: string; caa: string[] } | null {
  const known = CAS.find((c) => c.re.test(e.issuer));
  if (known) return { key: known.key, label: known.label, caa: [...known.caa] };
  // Cert Spotter tells us the CA's CAA domains directly, even for CAs not in the table.
  if (e.caaDomains?.length) {
    const key = e.caaDomains[0].toLowerCase().replace(/[^a-z0-9.-]/g, "").slice(0, 60);
    return key ? { key, label: e.issuer, caa: e.caaDomains.map((d) => d.toLowerCase()) } : null;
  }
  return null;
}

// ---------- CAA ----------

export interface CaaPolicy { name: string; records: string[]; issue: string[] | null; issuewild: string[] | null }

/** Parses "flags tag value" records. A tag that is absent is null (unrestricted); ";" alone is an empty set (no CA). */
export function parseCaa(name: string, records: string[]): CaaPolicy {
  let issue: string[] | null = null, issuewild: string[] | null = null;
  for (const r of records) {
    const m = /^\s*\d+\s+(\S+)\s*(.*)$/.exec(r);
    if (!m) continue;
    const tag = m[1].toLowerCase();
    if (tag !== "issue" && tag !== "issuewild") continue;
    const domain = m[2].replace(/^"|"$/g, "").split(";")[0].trim().toLowerCase();
    if (tag === "issue") { issue ??= []; if (domain) issue.push(domain); }
    else { issuewild ??= []; if (domain) issuewild.push(domain); }
  }
  return { name, records, issue, issuewild };
}

/** The CA domains allowed for a certificate, or null when CAA does not restrict it (RFC 8659 §4.2, §4.3). */
export function allowedFor(p: CaaPolicy, wildcard: boolean): string[] | null {
  return wildcard ? (p.issuewild ?? p.issue) : p.issue;
}

async function caaPolicy(c: CheckContext): Promise<CaaPolicy | { error: string; name: string }> {
  const labels = c.host.split(".");
  for (let i = 0; i < labels.length - 1; i++) {
    const name = labels.slice(i).join(".");
    const r = await lookupRecords(name, "CAA", c.dns);
    if ("error" in r) return { error: r.error, name };
    if (r.records.length) return parseCaa(name, r.records);
  }
  return { name: c.host, records: [], issue: null, issuewild: null };
}

// ---------- CT sources ----------

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
const str = (v: unknown) => (typeof v === "string" ? v : typeof v === "number" ? String(v) : "");
const iso = (v: unknown) => { const t = Date.parse(str(v).replace(/(T\d\d:\d\d:\d\d)(\.\d+)?$/, "$1$2Z")); return Number.isFinite(t) ? new Date(t).toISOString() : ""; };

export function parseCrtSh(json: unknown): CtEntry[] {
  if (!Array.isArray(json)) throw new CtError("crtsh_malformed_response");
  const seen = new Map<string, CtEntry>();
  for (const r of json) {
    if (!isObj(r)) throw new CtError("crtsh_malformed_response");
    const names = new Set([...str(r.name_value).split("\n"), str(r.common_name)].map((n) => n.trim().toLowerCase()).filter(Boolean));
    const e: CtEntry = { id: str(r.id), issuer: str(r.issuer_name), names: [...names], notBefore: iso(r.not_before), notAfter: iso(r.not_after) };
    if (!e.id || !e.notAfter || !e.notBefore) throw new CtError("crtsh_malformed_response");
    // The precertificate and the final certificate are logged separately; they share issuer and serial.
    const key = r.serial_number ? `${e.issuer}|${str(r.serial_number)}` : e.id;
    if (!seen.has(key)) seen.set(key, e);
  }
  return [...seen.values()];
}

export function parseCertSpotter(json: unknown): CtEntry[] {
  if (!Array.isArray(json)) throw new CtError("certspotter_malformed_response");
  return json.map((r) => {
    if (!isObj(r) || !Array.isArray(r.dns_names)) throw new CtError("certspotter_malformed_response");
    const issuer = isObj(r.issuer) ? r.issuer : {};
    const e: CtEntry = {
      id: str(r.id), issuer: str(issuer.friendly_name) || str(issuer.name),
      caaDomains: Array.isArray(issuer.caa_domains) ? issuer.caa_domains.map(str).filter(Boolean) : undefined,
      names: [...new Set(r.dns_names.map((n) => str(n).trim().toLowerCase()).filter(Boolean))],
      notBefore: iso(r.not_before), notAfter: iso(r.not_after),
    };
    if (!e.id || !e.notAfter || !e.notBefore) throw new CtError("certspotter_malformed_response");
    return e;
  });
}

const lastCall = new Map<string, number>();

async function getJson(fetchImpl: FetchLike, url: URL, timeoutMs: number, tag: string): Promise<unknown> {
  if (url.protocol !== "https:" || !ALLOWED_HOSTS.has(url.host)) throw new CtError("egress_not_allowed");
  let res;
  try {
    res = await fetchImpl(url.toString(), {
      method: "GET", redirect: "error", signal: AbortSignal.timeout(timeoutMs),
      headers: { accept: "application/json", "user-agent": "RuyaShield-ct/1" },
    });
  } catch { throw new CtError(`${tag}_unreachable`); }
  if (!res.ok) throw new CtError(`${tag}_http_${res.status}`);
  const text = await res.text();
  if (text.length > MAX_RESPONSE_CHARS) throw new CtError(`${tag}_response_too_large`);
  try { return JSON.parse(text); } catch { throw new CtError(`${tag}_malformed_response`); }
}

// ---------- findings ----------

const isValidAt = (e: CtEntry, t: number) => Date.parse(e.notBefore) <= t && t < Date.parse(e.notAfter);

export function ctFindings(host: string, entries: CtEntry[], caa: CaaPolicy, now: Date): FindingCandidate[] {
  const t = now.getTime();
  const valid = entries.filter((e) => isValidAt(e, t));
  const out: FindingCandidate[] = [];

  const wild = valid.filter((e) => e.names.some((n) => n.startsWith("*.")));
  if (wild.length) {
    const names = [...new Set(wild.flatMap((e) => e.names.filter((n) => n.startsWith("*."))))].sort();
    out.push({
      issueKey: "wildcard-cert", title: "Wildcard certificates are in use", severity: "info", location: host,
      evidence: { names: names.slice(0, 50), certificates: wild.length, issuers: [...new Set(wild.map((e) => e.issuer))].slice(0, 10), latestExpiry: wild.map((e) => e.notAfter).sort().pop() },
      remediation: "A wildcard certificate covers every subdomain, so its private key is valuable: if it leaks from any one server, all subdomains can be impersonated. Keep the key on as few servers as possible, or use per-host certificates where automation makes that cheap.",
    });
  }

  // CAA is checked at issuance; we can only compare against today's records, so this is "likely", not confirmed.
  const bad = new Map<string, { label: string; caa: string[]; allowed: string[]; certs: CtEntry[] }>();
  for (const e of valid) {
    const allowed = allowedFor(caa, e.names.some((n) => n.startsWith("*.")));
    if (!allowed) continue;
    const ca = caOf(e);
    if (!ca) continue; // reported in evidence.unmappedIssuers; we cannot tell which CAA value it needs
    if (ca.caa.some((d) => allowed.includes(d))) continue;
    const b = bad.get(ca.key) ?? { label: ca.label, caa: ca.caa, allowed, certs: [] };
    b.certs.push(e);
    bad.set(ca.key, b);
  }
  for (const [key, b] of [...bad.entries()].sort(([a], [z]) => a.localeCompare(z))) {
    out.push({
      issueKey: `unknown-issuer.${key}`, title: `Certificate issued by ${b.label}, which your CAA records do not allow`, severity: "low", confidence: "likely", location: host,
      evidence: {
        ca: b.label, caIdentifiers: b.caa, caaName: caa.name, caaAllowed: b.allowed, certificates: b.certs.length,
        certIds: b.certs.map((e) => e.id).slice(0, 10), names: [...new Set(b.certs.flatMap((e) => e.names))].slice(0, 20),
        issuers: [...new Set(b.certs.map((e) => e.issuer))].slice(0, 5),
      },
      remediation: `Find out who requested these certificates. If nobody on your team did, treat it as a possible compromise: revoke them with the CA and check DNS and hosting access. If they are legitimate (for example a CDN or SaaS provider), add a CAA record for the CA, e.g. 0 issue "${b.caa[0]}", so that the policy matches reality.`,
    });
  }
  return out.slice(0, 50);
}

/** Subdomains of host seen in certificates (wildcards reduced to their base), excluding host itself. */
export function suggestedHosts(host: string, entries: CtEntry[]): string[] {
  const out = new Set<string>();
  for (const e of entries) for (const raw of e.names) {
    const n = raw.replace(/^\*\./, "").replace(/\.$/, "");
    if (n !== host && n.endsWith(`.${host}`) && HOSTNAME.test(n)) out.add(n);
  }
  return [...out].sort().slice(0, MAX_SUGGESTIONS);
}

// ---------- adapter ----------

function dbCache(): CtCache {
  return {
    async get(domain) {
      const { db } = await import("../db/client");
      const { ctCache } = await import("../db/schema");
      const { eq } = await import("drizzle-orm");
      const r = (await db.select().from(ctCache).where(eq(ctCache.domain, domain)))[0];
      return r ? { source: r.source as CtSource, fetchedAt: r.fetchedAt, entries: r.entries as CtEntry[], truncated: r.truncated } : null;
    },
    async put(domain, row) {
      const { db } = await import("../db/client");
      const { ctCache } = await import("../db/schema");
      const v = { source: row.source, fetchedAt: row.fetchedAt, entries: row.entries, truncated: row.truncated };
      await db.insert(ctCache).values({ domain, ...v }).onConflictDoUpdate({ target: ctCache.domain, set: v });
    },
  };
}

export function createCtAdapter(deps: { fetch?: FetchLike; cache?: CtCache; minSpacingMs?: number } = {}): CheckAdapter {
  const spacing = deps.minSpacingMs ?? DEFAULT_SPACING_MS;
  return {
    id: "discovery.ct@1", checkKey: "discovery.ct", target: "host",
    async run(c): Promise<CheckResult> {
      const host = c.host.toLowerCase();
      const now = c.now?.() ?? new Date();
      const sleep = c.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
      const fetchImpl = deps.fetch ?? (globalThis.fetch as unknown as FetchLike);
      const cache = deps.cache ?? dbCache();
      const perCall = Math.max(5000, Math.min(45_000, Math.floor(c.timeoutMs * 0.45)));

      const caa = await caaPolicy(c);
      if ("error" in caa) return { status: "error", reason: `dns_${caa.error}`, evidence: { name: caa.name } };

      let row: CtCacheRow | null = null, cached = false;
      try { row = await cache.get(host); } catch { row = null; }
      if (row && now.getTime() - row.fetchedAt.getTime() < CACHE_TTL_MS) cached = true;
      else row = null;

      const failures: Record<string, string> = {};
      const spaced = async <T>(src: string, fn: () => Promise<T>) => {
        const wait = (lastCall.get(src) ?? 0) + spacing - Date.now();
        if (wait > 0) await sleep(wait);
        try { return await fn(); } finally { lastCall.set(src, Date.now()); }
      };
      if (!row) {
        try {
          const url = new URL("https://crt.sh/");
          url.searchParams.set("q", `%.${host}`);
          url.searchParams.set("output", "json");
          const entries = parseCrtSh(await spaced("crt.sh", () => getJson(fetchImpl, url, perCall, "crtsh")));
          row = { source: "crt.sh", fetchedAt: now, ...cap(entries) };
        } catch (e) { failures["crt.sh"] = e instanceof CtError ? e.message : "crtsh_error"; }
      }
      if (!row) {
        try {
          const all: CtEntry[] = [];
          let after = "";
          for (let page = 0; ; page++) {
            if (page >= MAX_CERTSPOTTER_PAGES) throw new CtError("certspotter_too_many_pages");
            const url = new URL("https://api.certspotter.com/v1/issuances");
            url.searchParams.set("domain", host);
            url.searchParams.set("include_subdomains", "true");
            url.searchParams.append("expand", "dns_names");
            url.searchParams.append("expand", "issuer");
            if (after) url.searchParams.set("after", after);
            const batch = parseCertSpotter(await spaced("certspotter", () => getJson(fetchImpl, url, perCall, "certspotter")));
            all.push(...batch);
            if (!batch.length || batch.length < 100) break;
            after = batch[batch.length - 1].id;
          }
          row = { source: "certspotter", fetchedAt: now, ...cap(all) };
        } catch (e) { failures.certspotter = e instanceof CtError ? e.message : "certspotter_error"; }
      }
      if (!row) return { status: "error", reason: "ct_unavailable", evidence: { failures } };
      if (!cached) { try { await cache.put(host, row); } catch { /* a cache miss next time is harmless */ } }

      const findings = ctFindings(host, row.entries, caa, now);
      const issuers = new Map<string, number>();
      for (const e of row.entries) if (isValidAt(e, now.getTime())) issuers.set(e.issuer, (issuers.get(e.issuer) ?? 0) + 1);
      const unmapped = [...issuers.keys()].filter((i) => !caOf({ issuer: i, caaDomains: row!.entries.find((e) => e.issuer === i)?.caaDomains }));
      return {
        status: "ok", findings,
        evidence: {
          source: row.source, cached, fetchedAt: row.fetchedAt.toISOString(), truncated: row.truncated, ...(Object.keys(failures).length ? { failures } : {}),
          certificates: row.entries.length, validCertificates: [...issuers.values()].reduce((a, b) => a + b, 0),
          issuers: Object.fromEntries([...issuers.entries()].sort((a, b) => b[1] - a[1]).slice(0, 20)),
          unmappedIssuers: unmapped.slice(0, 10),
          caa: { name: caa.name, records: caa.records },
          suggestedHosts: suggestedHosts(host, row.entries),
        },
      };
    },
  };
}

/** Keeps the newest MAX_ENTRIES certificates; older ones matter least for both findings and discovery. */
function cap(entries: CtEntry[]): { entries: CtEntry[]; truncated: boolean } {
  if (entries.length <= MAX_ENTRIES) return { entries, truncated: false };
  return { entries: [...entries].sort((a, b) => b.notBefore.localeCompare(a.notBefore)).slice(0, MAX_ENTRIES), truncated: true };
}
