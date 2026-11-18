// Cloudflare response-header fixes (safe apply at the edge). The customer's API token needs only
// "Zone → Zone → Read" and "Zone → Transform Rules → Edit" on one zone. Hard rules, enforced here and by a static test:
//  - RuyaShield touches exactly one rule per site: the one whose ref is ruyashield_headers_<asset>. It never edits,
//    reorders or deletes any other rule, and never replaces an existing ruleset (PUT only creates the phase's
//    entrypoint when the zone has none yet);
//  - the rule only matches the verified host (http.host eq "<host>"), and only sets the headers the customer ticked;
//  - undo deletes that one rule. Errors carry a code, never the token or Cloudflare's body.

export const CF_API = process.env.RUYA_CLOUDFLARE_API_URL || "https://api.cloudflare.com/client/v4";
const PHASE = "http_response_headers_transform";
const ZONE = /^[a-f0-9]{32}$/;
const HOST = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

export class EdgeError extends Error {
  constructor(public readonly code: string, public readonly status = 422, message?: string) { super(message ?? code); }
}

export type FetchFn = (url: string, init: RequestInit) => Promise<Response>;
let fetchImpl: FetchFn = (u, i) => fetch(u, i);
/** Tests only. */
export function setCloudflareFetch(f: FetchFn | null) { fetchImpl = f ?? ((u, i) => fetch(u, i)); }

/** The fixes RuyaShield can apply, each tied to the findings it resolves. CSP is never applied blindly: it breaks sites. */
export const HEADER_FIXES = [
  { key: "hsts", header: "Strict-Transport-Security", value: "max-age=31536000", issues: ["missing_hsts", "weak_hsts"],
    note: "Browsers will only use HTTPS for this host for a year. Subdomains are not included." },
  { key: "nosniff", header: "X-Content-Type-Options", value: "nosniff", issues: ["missing_nosniff"],
    note: "Safe on almost every site." },
  { key: "frame", header: "X-Frame-Options", value: "SAMEORIGIN", issues: ["missing_frame_protection"],
    note: "Other websites can no longer show your pages inside a frame. Leave unticked if partners embed your site." },
  { key: "referrer", header: "Referrer-Policy", value: "strict-origin-when-cross-origin", issues: ["unsafe_referrer_policy"],
    note: "Other sites see only your domain, not full page addresses." },
] as const;
export type FixKey = (typeof HEADER_FIXES)[number]["key"];
export const FIX_KEYS = HEADER_FIXES.map((f) => f.key) as FixKey[];

export const ruleRef = (assetId: string) => `ruyashield_headers_${assetId.replace(/-/g, "").slice(0, 32)}`;

export function assertZoneId(zoneId: string) {
  if (!ZONE.test(zoneId)) throw new EdgeError("cloudflare_zone_id_invalid", 422, "The zone ID is the 32-character code on the zone's Overview page in Cloudflare.");
}
export function assertToken(token: string) {
  if (!/^[A-Za-z0-9_-]{30,200}$/.test(token)) throw new EdgeError("cloudflare_token_invalid", 422, "That does not look like a Cloudflare API token.");
}

type CfBody<T> = { success?: boolean; errors?: { code?: number; message?: string }[]; result?: T };

async function cf<T>(token: string, method: string, path: string, body?: unknown): Promise<{ status: number; body: CfBody<T> }> {
  let res: Response;
  try {
    res = await fetchImpl(`${CF_API}${path}`, {
      method, redirect: "error", signal: AbortSignal.timeout(20_000),
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json", "user-agent": "RuyaShield-edge/1" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new EdgeError("cloudflare_unreachable", 503, "Cloudflare could not be reached. Try again in a minute.");
  }
  let parsed: CfBody<T> = {};
  try { parsed = (await res.json()) as CfBody<T>; } catch { parsed = {}; }
  if (res.status === 401) throw new EdgeError("cloudflare_not_authorized", 422, "Cloudflare rejected the token. It may have expired or been revoked.");
  if (res.status === 403) throw new EdgeError("cloudflare_forbidden", 422, "The token is missing a permission. It needs Zone → Zone → Read and Zone → Transform Rules → Edit on this zone.");
  if (res.status === 429) throw new EdgeError("cloudflare_rate_limited", 429, "Cloudflare's rate limit was reached. Try again later.");
  return { status: res.status, body: parsed };
}

const failed = (code: string, status: number) => new EdgeError(code, 503, `Cloudflare answered ${status}.`);

/** The zone's name, after checking the token can read it. The asset's host must belong to this zone. */
export async function inspectZone(token: string, zoneId: string, host: string): Promise<{ zoneName: string }> {
  assertZoneId(zoneId);
  const h = host.toLowerCase();
  if (!HOST.test(h)) throw new EdgeError("host_invalid", 422, "This asset's host cannot be used in a Cloudflare rule.");
  const r = await cf<{ name?: string }>(token, "GET", `/zones/${zoneId}`);
  if (r.status === 404 || !r.body.success) throw new EdgeError("cloudflare_zone_not_found", 422, "Cloudflare has no zone with that ID for this token.");
  const name = String(r.body.result?.name ?? "").toLowerCase();
  if (!name || !(h === name || h.endsWith(`.${name}`))) {
    throw new EdgeError("cloudflare_zone_mismatch", 422, `${h} is not part of the Cloudflare zone ${name || "you gave"}.`);
  }
  // Can the token see the response-header rules? 200 (rules exist) and 404 (none yet) both mean yes.
  const e = await cf(token, "GET", `/zones/${zoneId}/rulesets/phases/${PHASE}/entrypoint`);
  if (e.status !== 200 && e.status !== 404) throw failed("cloudflare_rules_unreadable", e.status);
  return { zoneName: name };
}

type Rule = { id?: string; ref?: string };
type Ruleset = { id?: string; rules?: Rule[] };

async function entrypoint(token: string, zoneId: string): Promise<Ruleset | null> {
  const r = await cf<Ruleset>(token, "GET", `/zones/${zoneId}/rulesets/phases/${PHASE}/entrypoint`);
  if (r.status === 404) return null;
  if (r.status !== 200 || !r.body.success || !r.body.result?.id) throw failed("cloudflare_rules_unreadable", r.status);
  return r.body.result;
}

export function buildRule(assetId: string, host: string, fixes: FixKey[]) {
  const h = host.toLowerCase();
  if (!HOST.test(h)) throw new EdgeError("host_invalid");
  const chosen = HEADER_FIXES.filter((f) => fixes.includes(f.key));
  if (!chosen.length) throw new EdgeError("no_fixes_selected", 422, "Tick at least one header to apply.");
  return {
    ref: ruleRef(assetId),
    description: `RuyaShield security headers for ${h} (managed by RuyaShield; undo it there)`,
    expression: `(http.host eq "${h}")`,
    action: "rewrite",
    enabled: true,
    action_parameters: { headers: Object.fromEntries(chosen.map((f) => [f.header, { operation: "set", value: f.value }])) },
  };
}

/** Creates or updates RuyaShield's one rule for this asset. Returns the rule id. */
export async function applyHeaderRule(token: string, zoneId: string, assetId: string, host: string, fixes: FixKey[]): Promise<{ rulesetId: string; ruleId: string }> {
  assertZoneId(zoneId);
  const rule = buildRule(assetId, host, fixes);
  const ep = await entrypoint(token, zoneId);
  if (!ep) {
    // The zone has no response-header rules at all: create the entrypoint holding only our rule.
    const r = await cf<Ruleset>(token, "PUT", `/zones/${zoneId}/rulesets/phases/${PHASE}/entrypoint`, { rules: [rule] });
    const made = r.body.result?.rules?.find((x) => x.ref === rule.ref);
    if (r.status !== 200 || !r.body.success || !r.body.result?.id || !made?.id) throw failed("cloudflare_apply_failed", r.status);
    return { rulesetId: r.body.result.id, ruleId: made.id };
  }
  const mine = ep.rules?.find((x) => x.ref === rule.ref);
  const r = mine?.id
    ? await cf<Ruleset>(token, "PATCH", `/zones/${zoneId}/rulesets/${ep.id}/rules/${mine.id}`, rule)
    : await cf<Ruleset>(token, "POST", `/zones/${zoneId}/rulesets/${ep.id}/rules`, rule);
  const after = r.body.result?.rules?.find((x) => x.ref === rule.ref);
  if (r.status !== 200 || !r.body.success || !after?.id) {
    const limit = (r.body.errors ?? []).some((e) => /limit|quota|exceeded/i.test(e.message ?? ""));
    if (limit) throw new EdgeError("cloudflare_rule_limit", 422, "This zone has reached Cloudflare's limit of response-header rules for its plan.");
    throw failed("cloudflare_apply_failed", r.status);
  }
  return { rulesetId: ep.id!, ruleId: after.id };
}

/** Deletes RuyaShield's rule for this asset, if it is there. Nothing else is touched. */
export async function removeHeaderRule(token: string, zoneId: string, assetId: string): Promise<boolean> {
  assertZoneId(zoneId);
  const ep = await entrypoint(token, zoneId);
  const mine = ep?.rules?.find((x) => x.ref === ruleRef(assetId));
  if (!ep || !mine?.id) return false;
  const r = await cf(token, "DELETE", `/zones/${zoneId}/rulesets/${ep.id}/rules/${mine.id}`);
  if (r.status !== 200 || !r.body.success) throw failed("cloudflare_undo_failed", r.status);
  return true;
}
