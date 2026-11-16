import { createHash } from "node:crypto";
import { isIP } from "node:net";
import type { FetchLike } from "../assessments/deps";
import { splitPath } from "./classify";
import type { AttackType } from "./classify";

/**
 * Pulls firewall events for one Cloudflare zone through the GraphQL Analytics API (firewallEventsAdaptive).
 * Token: the customer's API token with only "Zone > Analytics > Read" on that zone. Read-only; nothing is changed on
 * Cloudflare. Fails closed: any HTTP, GraphQL or shape error throws CloudflareError and the source shows as "error",
 * never as "no attacks".
 */
export const CF_HOST = "api.cloudflare.com";
export const CF_URL = `https://${CF_HOST}/client/v4/graphql`;
const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;
export const PAGE_LIMIT = 1000;
/** Free plans keep firewall events for about 3 days (paid plans keep longer); never ask further back than this. */
export const MAX_LOOKBACK_MS = 24 * 3_600_000;

/** `detail` is Cloudflare's own error text, cleaned of anything token-like; it goes to the worker log only. */
export class CloudflareError extends Error {
  constructor(code: string, readonly detail?: string) { super(code); }
}
const clean = (m: string) => m.replace(/[A-Za-z0-9_-]{24,}/g, "[redacted]").replace(/\s+/g, " ").slice(0, 300);

export interface CfEvent {
  occurredAt: Date; ip: string; country: string | null; asn: number | null; asOrg: string | null;
  action: string; attackType: AttackType; ruleId: string | null; method: string | null; path: string | null;
  userAgent: string | null; host: string | null; dedupeKey: string;
}

const QUERY = `query RuyaFirewallEvents($zone: String!, $since: Time!, $until: Time!, $limit: Int!, $host: String!) {
  viewer { zones(filter: { zoneTag: $zone }) {
    firewallEventsAdaptive(filter: { datetime_gt: $since, datetime_leq: $until, clientRequestHTTPHost: $host }, limit: $limit, orderBy: [datetime_ASC]) {
      action source ruleId rayName datetime clientIP clientCountryName clientAsn clientASNDescription
      clientRequestHTTPHost clientRequestHTTPMethodName clientRequestPath userAgent
    }
  } }
}`;

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const str = (v: unknown, max: number) => (typeof v === "string" && v ? v.slice(0, max) : null);

export function typeFor(action: string, source: string): AttackType {
  const s = source.toLowerCase();
  if (s.includes("ratelimit")) return "rate_limit";
  if (s.includes("bic") || s.includes("bot") || s === "uablock") return "bot";
  if (/challenge/i.test(action)) return "challenge";
  if (/block|drop/i.test(action)) return "waf_block";
  return "other";
}

export function parseEvents(body: unknown): CfEvent[] {
  if (!isObj(body)) throw new CloudflareError("cloudflare_malformed_response");
  if (Array.isArray(body.errors) && body.errors.length) {
    const msg = body.errors.map((e) => (isObj(e) && typeof e.message === "string" ? e.message : "")).join(" ");
    const d = clean(msg);
    if (/authentication|not authorized|permission|access/i.test(msg)) throw new CloudflareError("cloudflare_not_authorized", d);
    if (/limit|quota|too many/i.test(msg)) throw new CloudflareError("cloudflare_rate_limited", d);
    if (/zone/i.test(msg)) throw new CloudflareError("cloudflare_zone_not_found", d);
    throw new CloudflareError("cloudflare_graphql_error", d);
  }
  const zones = isObj(body.data) && isObj(body.data.viewer) ? body.data.viewer.zones : undefined;
  if (!Array.isArray(zones)) throw new CloudflareError("cloudflare_malformed_response");
  // An empty list means this token cannot see the zone: wrong zone ID, or the token is scoped to another zone.
  if (zones.length === 0) throw new CloudflareError("cloudflare_zone_not_visible", "zones list empty for this token and zone ID");
  const rows = isObj(zones[0]) ? zones[0].firewallEventsAdaptive : undefined;
  if (!Array.isArray(rows)) throw new CloudflareError("cloudflare_malformed_response");
  const out: CfEvent[] = [];
  for (const r of rows) {
    if (!isObj(r) || typeof r.datetime !== "string" || typeof r.clientIP !== "string" || typeof r.action !== "string") {
      throw new CloudflareError("cloudflare_malformed_response");
    }
    const at = new Date(r.datetime);
    if (Number.isNaN(at.getTime()) || !isIP(r.clientIP)) continue;
    const cc = typeof r.clientCountryName === "string" && /^[A-Z]{2}$/.test(r.clientCountryName) && r.clientCountryName !== "XX" && r.clientCountryName !== "T1"
      ? r.clientCountryName : null;
    const asn = typeof r.clientAsn === "string" || typeof r.clientAsn === "number" ? Number(r.clientAsn) : NaN;
    const source = typeof r.source === "string" ? r.source : "";
    const ray = str(r.rayName, 40);
    out.push({
      occurredAt: at, ip: r.clientIP, country: cc, asn: Number.isInteger(asn) && asn > 0 ? asn : null, asOrg: str(r.clientASNDescription, 120),
      action: r.action.slice(0, 40), attackType: typeFor(r.action, source), ruleId: str(r.ruleId, 80),
      method: str(r.clientRequestHTTPMethodName, 10), path: typeof r.clientRequestPath === "string" ? splitPath(r.clientRequestPath) : null,
      userAgent: str(r.userAgent, 200), host: str(r.clientRequestHTTPHost, 253),
      dedupeKey: createHash("sha256").update(`${ray ?? ""}|${r.datetime}|${r.clientIP}|${r.ruleId ?? ""}|${r.action}`).digest("hex").slice(0, 40),
    });
  }
  return out;
}

/**
 * Only events for the verified asset's host are requested (and re-checked here): a zone can carry other hostnames the
 * customer has not verified with us, and their visitors' data must not be stored.
 */
export async function fetchFirewallEvents(fetchImpl: FetchLike, token: string, zoneId: string, since: Date, until: Date, host: string, timeoutMs = 20_000): Promise<CfEvent[]> {
  if (!/^[a-f0-9]{32}$/.test(zoneId)) throw new CloudflareError("cloudflare_zone_id_invalid");
  const h = host.trim().toLowerCase();
  if (!/^[a-z0-9.-]{1,253}$/.test(h)) throw new CloudflareError("cloudflare_host_invalid");
  const u = new URL(CF_URL);
  if (u.protocol !== "https:" || u.host !== CF_HOST) throw new CloudflareError("cloudflare_egress_not_allowed");
  let res;
  try {
    res = await fetchImpl(u.toString(), {
      method: "POST", redirect: "error", signal: AbortSignal.timeout(timeoutMs),
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json", "user-agent": "RuyaShield-attacks/1" },
      body: JSON.stringify({ query: QUERY, variables: { zone: zoneId, since: since.toISOString(), until: until.toISOString(), limit: PAGE_LIMIT, host: h } }),
    });
  } catch { throw new CloudflareError("cloudflare_unreachable"); }
  // Never put the token or body in the reason.
  if (res.status === 401 || res.status === 403) throw new CloudflareError("cloudflare_not_authorized");
  if (res.status === 429) throw new CloudflareError("cloudflare_rate_limited");
  if (!res.ok) throw new CloudflareError(`cloudflare_http_${res.status}`);
  const text = await res.text();
  if (text.length > MAX_RESPONSE_BYTES) throw new CloudflareError("cloudflare_response_too_large");
  let body: unknown;
  try { body = JSON.parse(text); } catch { throw new CloudflareError("cloudflare_malformed_response"); }
  return parseEvents(body).filter((e) => e.host !== null && e.host.toLowerCase() === h);
}
