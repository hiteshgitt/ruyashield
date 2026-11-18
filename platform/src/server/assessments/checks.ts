import { createHash } from "node:crypto";
import { z } from "zod";
import type { Confidence, Severity } from "../db/schema";
import { EgressError, guardedGet, lookupRecords, tlsProbe, type DnsDeps, type EgressDeps } from "../net/egress";
import type { RepoSnapshot } from "../remediation/repo";
import { createOsvAdapter } from "./deps";
import { createSecretsAdapter } from "./secrets";
import { createExposedServicesAdapter } from "./ports";
import { createSastAdapter } from "./sast";
import { createIacAdapter } from "./iac";
import { createTechnologyAdapter } from "./technology";
import { createBlocklistAdapter } from "./blocklist";
import { createCtAdapter } from "./ct";
import { createTlsConfigAdapter } from "./tlsconfig";
import { createExposureAdapter } from "./exposure";
import { createContainerImageAdapter } from "./container";
import { createCompromiseAdapter } from "./compromise";
import { createCorsAdapter } from "./cors";
import { createTakeoverAdapter } from "./takeover";

/**
 * P2 check adapters (RS-SCAN-002). Every adapter is class P (DNS only) or A1 (a handful of ordinary,
 * non-intrusive GETs / a TLS handshake). No payloads, no fuzzing, no credential use. Class X checks
 * have no adapter at all, so they cannot run even if their catalogue row were enabled.
 */

// 0.8.1: http.security_headers and http.exposure still read sites whose certificate is untrusted or weak (tlsLenient).
// 0.9.0: http.security_headers also flags weak HSTS, a CSP that does not restrict scripts, unsafe Referrer-Policy,
//        version banners, and plain HTTP served without a redirect to HTTPS.
// 0.10.0: container.image scans the base images of repository Dockerfiles (syft inventory + OSV).
// 0.11.0: tls.config probes RC4, 3DES, DES and EXPORT suites with an out-of-process legacy OpenSSL client when installed.
// 0.13.0: code.iac (Terraform/Kubernetes/Compose/Dockerfile/GitHub Actions misconfigurations), web.blocklist (Safe Browsing, URLhaus);
// 0.12.0: http.compromise (passive signs of injected scripts, miners, SEO spam, cloaking), http.cors, dns.takeover;
//         http.security_headers reads at most 512 bytes of body.
export const ENGINE_VERSION = "ruya-checks/0.14.0";

export interface CheckContext {
  host: string;
  /** The scope guard hook for this check. Every outbound request goes through it. */
  onHop: (url: URL) => Promise<void>;
  egress: Omit<EgressDeps, "onHop">;
  dns: DnsDeps;
  timeoutMs: number;
  sleep?: (ms: number) => Promise<void>;
  now?: () => Date;
  /** Present only for repository assets: a read-only snapshot of the default branch. */
  repo?: RepoSnapshot;
}

/** What a check runs against. Host checks reach the asset over the network; repository checks read a snapshot. */
export type CheckTarget = "host" | "repository";

export interface FindingCandidate {
  issueKey: string;
  title: string;
  severity: Severity;
  /** How sure the check is; omitted means confirmed (the P2 checks observe directly). */
  confidence?: Confidence;
  location: string;
  evidence: Record<string, unknown>;
  remediation: string;
}

/** What one check observed. A check that could not observe what it needs reports an error, never "no findings". */
export type CheckResult =
  | { status: "ok"; findings: FindingCandidate[]; evidence: Record<string, unknown> }
  | { status: "error"; reason: string; evidence: Record<string, unknown> };

export interface CheckAdapter { id: string; checkKey: string; target?: CheckTarget; run(ctx: CheckContext): Promise<CheckResult> }

export const targetOf = (a: CheckAdapter): CheckTarget => a.target ?? "host";
export const targetForKind = (kind: string): CheckTarget => (kind === "repository" ? "repository" : "host");

const candidate = z.object({
  issueKey: z.string().regex(/^[a-z0-9_.-]{1,80}$/),
  title: z.string().min(1).max(200),
  severity: z.enum(["info", "low", "medium", "high", "critical"]),
  confidence: z.enum(["confirmed", "likely", "suspected", "unknown"]).optional(),
  location: z.string().min(1).max(300),
  evidence: z.record(z.string(), z.unknown()),
  remediation: z.string().max(1000),
});
const resultSchema = z.discriminatedUnion("status", [
  z.object({ status: z.literal("ok"), findings: z.array(candidate).max(50), evidence: z.record(z.string(), z.unknown()) }),
  z.object({ status: z.literal("error"), reason: z.string().max(200), evidence: z.record(z.string(), z.unknown()) }),
]);

/** Validates adapter output. Malformed output is an error, so a broken adapter can never look like a clean result. */
export function normalizeResult(raw: unknown): CheckResult {
  const r = resultSchema.safeParse(raw);
  return r.success ? r.data : { status: "error", reason: "malformed_output", evidence: {} };
}

export function fingerprint(checkKey: string, location: string, issueKey: string): string {
  return createHash("sha256").update(`${checkKey}|${location}|${issueKey}`).digest("hex");
}

const DAY = 86_400_000;
const osv = createOsvAdapter();
const secrets = createSecretsAdapter();

// ---------- TLS certificate ----------

export function tlsFindings(host: string, info: { validTo: string; authorized: boolean; authorizationError: string | null; issuer: string | null }, now: Date): FindingCandidate[] {
  const out: FindingCandidate[] = [];
  const loc = `${host}:443`;
  const expires = new Date(info.validTo);
  if (Number.isNaN(expires.getTime())) {
    out.push({ issueKey: "cert_expiry_unreadable", title: "Certificate expiry date could not be read", severity: "medium", location: loc, evidence: { validTo: info.validTo }, remediation: "Check the certificate served on port 443." });
  } else {
    const days = (expires.getTime() - now.getTime()) / DAY;
    const ev = { validTo: expires.toISOString(), daysRemaining: Math.floor(days), issuer: info.issuer };
    if (days < 0) {
      out.push({ issueKey: "cert_expired", title: "TLS certificate has expired", severity: "high", location: loc, evidence: ev, remediation: "Renew the certificate now and enable automatic renewal." });
    } else if (days < 10) {
      out.push({ issueKey: "cert_expiring", title: "TLS certificate expires within 10 days", severity: "medium", location: loc, evidence: ev, remediation: "Renew the certificate and confirm automatic renewal works." });
    } else if (days < 30) {
      out.push({ issueKey: "cert_expiring", title: "TLS certificate expires within 30 days", severity: "low", location: loc, evidence: ev, remediation: "Plan renewal, or confirm automatic renewal is configured." });
    }
  }
  if (!info.authorized) {
    out.push({ issueKey: "cert_untrusted", title: "TLS certificate is not trusted", severity: "medium", location: loc, evidence: { error: info.authorizationError, issuer: info.issuer }, remediation: "Serve a certificate from a publicly trusted CA that matches the host name, with the full chain." });
  }
  return out;
}

const tls: CheckAdapter = {
  id: "tls.cert_expiry@1", checkKey: "tls.cert_expiry",
  async run(c) {
    const info = await tlsProbe(c.host, { ...c.egress, onHop: c.onHop, timeoutMs: c.timeoutMs });
    return { status: "ok", findings: tlsFindings(c.host, info, (c.now ?? (() => new Date()))()), evidence: { validTo: info.validTo, issuer: info.issuer, authorized: info.authorized, address: info.pinnedAddress } };
  },
};

// ---------- HTTP security headers ----------

type Headers = Record<string, string | string[] | undefined>;
const HSTS_MIN_AGE = 15_552_000;

/** Why a CSP fails to restrict scripts: the effective script policy (script-src, else default-src) is missing or too open. */
export function cspScriptWeakness(csp: string): string[] {
  const dirs = new Map<string, string[]>();
  for (const part of csp.split(";")) {
    const [name, ...vals] = part.trim().toLowerCase().split(/\s+/);
    if (name && !dirs.has(name)) dirs.set(name, vals);
  }
  const src = dirs.get("script-src") ?? dirs.get("default-src");
  if (!src) return ["no_script_src"];
  const out: string[] = [];
  // 'unsafe-inline' is ignored by browsers when a nonce or hash is present, so only flag it without one.
  if (src.includes("'unsafe-inline'") && !src.some((v) => /^'(nonce-|sha256-|sha384-|sha512-)/.test(v))) out.push("unsafe_inline");
  if (src.some((v) => v === "*" || v === "http:" || v === "https:" || v === "data:")) out.push("wildcard_source");
  return out;
}

/** Plain-HTTP behaviour: a site that answers on http:// without sending visitors to https:// can be downgraded. */
export function httpRedirectFindings(host: string, r: { finalUrl: string; status: number } | null): FindingCandidate[] {
  if (!r || r.finalUrl.startsWith("https:") || r.status >= 400) return [];
  return [{ issueKey: "http_no_redirect", title: "Plain HTTP is served without redirecting to HTTPS", severity: "medium", location: `http://${host}/`,
    evidence: { status: r.status, finalUrl: r.finalUrl }, remediation: "Redirect every http:// request to https:// with a 301 (nginx: return 301 https://$host$request_uri;), and send HSTS so browsers stop trying HTTP." }];
}
const one = (h: Headers, k: string) => { const v = h[k]; return Array.isArray(v) ? v.join(", ") : v; };

export function headerFindings(url: string, h: Headers): FindingCandidate[] {
  const out: FindingCandidate[] = [];
  const add = (issueKey: string, title: string, severity: Severity, remediation: string, evidence: Record<string, unknown> = {}) =>
    out.push({ issueKey, title, severity, location: url, evidence, remediation });
  if (url.startsWith("https:") && !one(h, "strict-transport-security")) add("missing_hsts", "Strict-Transport-Security header missing", "medium", "Send Strict-Transport-Security: max-age=31536000; includeSubDomains on HTTPS responses.");
  const csp = one(h, "content-security-policy");
  if (!csp) add("missing_csp", "Content-Security-Policy header missing", "medium", "Define a Content-Security-Policy, starting in report-only mode if needed.");
  if ((one(h, "x-content-type-options") ?? "").toLowerCase() !== "nosniff") add("missing_nosniff", "X-Content-Type-Options: nosniff missing", "low", "Send X-Content-Type-Options: nosniff.");
  if (!one(h, "x-frame-options") && !/frame-ancestors/i.test(csp ?? "")) add("missing_frame_protection", "No clickjacking protection (X-Frame-Options or CSP frame-ancestors)", "low", "Send CSP frame-ancestors 'self' (or X-Frame-Options: DENY/SAMEORIGIN).");
  // HSTS present but too short to protect returning visitors (under 180 days, or max-age=0 which switches it off).
  const hsts = one(h, "strict-transport-security");
  if (url.startsWith("https:") && hsts) {
    const m = /max-age\s*=\s*"?(\d+)/i.exec(hsts);
    const age = m ? Number(m[1]) : null;
    if (age === null || age < HSTS_MIN_AGE) add("weak_hsts", "Strict-Transport-Security max-age is too short", "low", "Set max-age to at least 15552000 (180 days); 31536000 (one year) is typical.", { maxAge: age });
  }
  // CSP present but scripts are not actually restricted.
  if (csp) {
    const weak = cspScriptWeakness(csp);
    if (weak.length) add("weak_csp", "Content-Security-Policy does not restrict scripts", "medium", "Remove 'unsafe-inline' and wildcard sources (*, http:, https:, data:) from script-src / default-src. Use nonces or hashes for inline scripts.", { weaknesses: weak });
  }
  const rp = (one(h, "referrer-policy") ?? "").toLowerCase().split(",").map((x) => x.trim()).filter(Boolean).pop();
  if (rp === "unsafe-url" || rp === "no-referrer-when-downgrade") add("unsafe_referrer_policy", "Referrer-Policy sends full URLs to other sites", "low", "Use Referrer-Policy: strict-origin-when-cross-origin (or no-referrer).", { policy: rp });
  // Software versions advertised in banners make it trivial to match the server to known CVEs.
  const banners: Record<string, string> = {};
  for (const k of ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]) {
    const v = one(h, k);
    if (v && /\d+\.\d+/.test(v)) banners[k] = v.slice(0, 100);
  }
  if (Object.keys(banners).length) add("version_disclosure", "Server reveals software versions in response headers", "low", "Hide version numbers: nginx server_tokens off; Apache ServerTokens Prod + ServerSignature Off; PHP expose_php = Off; remove X-Powered-By / X-AspNet-Version in the framework or proxy.", { headers: banners });
  const cookies = ([] as string[]).concat(h["set-cookie"] ?? []);
  for (const raw of cookies) {
    const name = raw.split("=")[0].trim().slice(0, 60);
    const attrs = raw.split(";").slice(1).map((a) => a.trim().toLowerCase());
    // Evidence keeps the cookie name and attributes only, never its value.
    const ev = { cookie: name, attributes: attrs.map((a) => a.split("=")[0]) };
    if (url.startsWith("https:") && !attrs.includes("secure")) add(`cookie_no_secure.${name.toLowerCase()}`, `Cookie ${name} is missing the Secure attribute`, "medium", "Set the Secure attribute on cookies served over HTTPS.", ev);
    if (!attrs.includes("httponly")) add(`cookie_no_httponly.${name.toLowerCase()}`, `Cookie ${name} is missing the HttpOnly attribute`, "low", "Set HttpOnly unless client-side script must read the cookie.", ev);
    if (!attrs.some((a) => a.startsWith("samesite="))) add(`cookie_no_samesite.${name.toLowerCase()}`, `Cookie ${name} has no SameSite attribute`, "low", "Set SameSite=Lax (or Strict) explicitly.", ev);
  }
  return out.map((f) => ({ ...f, issueKey: f.issueKey.replace(/[^a-z0-9_.-]/g, "_").slice(0, 80) }));
}

const MAX_RETRY_AFTER_MS = 5000;

const headers: CheckAdapter = {
  id: "http.security_headers@1", checkKey: "http.security_headers",
  async run(c) {
    const url = `https://${c.host}/`;
    // Only the headers are judged, so the body is cut at 512 bytes (a large home page used to fail with too_large).
    const deps = { ...c.egress, onHop: c.onHop, timeoutMs: c.timeoutMs, accept: "text/html,*/*;q=0.5", tlsLenient: true, truncateAt: 512 };
    let r = await guardedGet(url, deps);
    if (r.status === 429 || r.status === 503) {
      // One polite backoff, honoring Retry-After up to a cap; then report what we got rather than retrying harder.
      const ra = Number(one(r.headers, "retry-after"));
      await (c.sleep ?? ((ms) => new Promise((res) => setTimeout(res, ms))))(Number.isFinite(ra) && ra > 0 ? Math.min(ra * 1000, MAX_RETRY_AFTER_MS) : 2000);
      r = await guardedGet(url, deps);
    }
    if (r.status === 429 || r.status === 503 || r.status >= 500) return { status: "error", reason: `http_${r.status}`, evidence: { status: r.status, finalUrl: r.finalUrl } };
    // One plain-HTTP request. Port 80 being closed or unreachable is fine (nothing to downgrade to), so it is not an error.
    let plain: { finalUrl: string; status: number } | null = null;
    let httpProbe = "unreachable";
    try {
      plain = await guardedGet(`http://${c.host}/`, deps);
      httpProbe = plain.finalUrl.startsWith("https:") ? "redirects_to_https" : `served_${plain.status}`;
    } catch (e) {
      // A redirect to another host (e.g. https://www.) is outside the scope guard, so it is not followed or judged.
      if (e instanceof EgressError && e.code === "redirect_refused") httpProbe = "redirects_off_host";
      else if (!(e instanceof EgressError) || (e.code !== "network" && e.code !== "timeout")) throw e;
    }
    return {
      status: "ok", findings: [...headerFindings(r.finalUrl, r.headers), ...httpRedirectFindings(c.host, plain)],
      // checkedLocations: every URL this run actually judged, so a re-test can resolve http_no_redirect (located at
      // http://host/) only when the plain-HTTP probe really got an answer.
      evidence: { status: r.status, finalUrl: r.finalUrl, redirects: r.redirects, address: r.pinnedAddress, httpProbe, checkedLocations: plain ? [r.finalUrl, `http://${c.host}/`] : [r.finalUrl] },
    };
  },
};

// ---------- DNS: SPF / DMARC ----------

export function emailFindings(host: string, txt: string[], dmarc: string[]): FindingCandidate[] {
  const out: FindingCandidate[] = [];
  const spf = txt.filter((t) => /^v=spf1(\s|$)/i.test(t.trim()));
  if (!spf.length) out.push({ issueKey: "spf_missing", title: "No SPF record", severity: "medium", location: host, evidence: {}, remediation: "Publish an SPF record listing your mail senders, ending in -all or ~all (or v=spf1 -all if the domain sends no mail)." });
  else if (spf.length > 1) out.push({ issueKey: "spf_multiple", title: "Multiple SPF records (SPF permerror)", severity: "medium", location: host, evidence: { records: spf }, remediation: "Merge into a single v=spf1 record." });
  else if (/(^|\s)\+?all(\s|$)/i.test(spf[0]) && !/(^|\s)[-~?]all(\s|$)/i.test(spf[0])) out.push({ issueKey: "spf_pass_all", title: "SPF allows any sender (+all)", severity: "high", location: host, evidence: { record: spf[0] }, remediation: "Replace +all with -all or ~all." });
  const d = dmarc.filter((t) => /^v=DMARC1(\s*;|$)/i.test(t.trim()));
  if (!d.length) out.push({ issueKey: "dmarc_missing", title: "No DMARC record", severity: "medium", location: `_dmarc.${host}`, evidence: {}, remediation: "Publish _dmarc TXT v=DMARC1; p=none; rua=… then move to quarantine/reject." });
  else if (/(^|;)\s*p\s*=\s*none\s*(;|$)/i.test(d[0])) out.push({ issueKey: "dmarc_p_none", title: "DMARC policy is p=none (monitoring only)", severity: "low", location: `_dmarc.${host}`, evidence: { record: d[0] }, remediation: "Once reports look clean, move to p=quarantine or p=reject." });
  return out;
}

const email: CheckAdapter = {
  id: "dns.email_posture@1", checkKey: "dns.email_posture",
  async run(c) {
    const [txt, dm] = await Promise.all([lookupRecords(c.host, "TXT", c.dns), lookupRecords(`_dmarc.${c.host}`, "TXT", c.dns)]);
    if ("error" in txt) return { status: "error", reason: `dns_${txt.error}`, evidence: { name: c.host } };
    if ("error" in dm) return { status: "error", reason: `dns_${dm.error}`, evidence: { name: `_dmarc.${c.host}` } };
    return { status: "ok", findings: emailFindings(c.host, txt.records, dm.records), evidence: { spf: txt.records.filter((t) => /^v=spf1/i.test(t)), dmarc: dm.records } };
  },
};

// ---------- DNS: CAA ----------

const caa: CheckAdapter = {
  id: "dns.caa@1", checkKey: "dns.caa",
  async run(c) {
    // RFC 8659: the relevant CAA set is the first one found walking up from the host. Stop before the TLD.
    const labels = c.host.split(".");
    for (let i = 0; i < labels.length - 1; i++) {
      const name = labels.slice(i).join(".");
      const r = await lookupRecords(name, "CAA", c.dns);
      if ("error" in r) return { status: "error", reason: `dns_${r.error}`, evidence: { name } };
      if (r.records.length) return { status: "ok", findings: [], evidence: { name, records: r.records } };
    }
    return { status: "ok", evidence: { records: [] }, findings: [{ issueKey: "caa_missing", title: "No CAA record restricts which CAs may issue certificates", severity: "low", location: c.host, evidence: {}, remediation: "Publish CAA records naming the CAs you use (e.g. 0 issue \"letsencrypt.org\")." }] };
  },
};

/** The executable catalogue. Anything not listed here cannot run, whatever the database says. */
export const ADAPTERS: ReadonlyMap<string, CheckAdapter> = new Map([tls, headers, email, caa, osv, secrets, createSastAdapter(), createExposedServicesAdapter(), createCtAdapter(), createTlsConfigAdapter(), createExposureAdapter(), createContainerImageAdapter(), createCompromiseAdapter(), createCorsAdapter(), createTakeoverAdapter(), createIacAdapter(), createBlocklistAdapter(), createTechnologyAdapter()].map((a) => [a.id, a]));
