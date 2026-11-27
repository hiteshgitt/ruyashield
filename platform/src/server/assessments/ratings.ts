// CVSS for findings that are not a published vulnerability (configuration, DNS, TLS, exposure, code and secrets
// findings). Each issue type has a standard CVSS v3.1 vector chosen by RuyaShield; it is used only when its score
// falls in the finding's current severity band, otherwise a per-severity reference vector is used, so a rated score
// never contradicts the severity a check or analyst assigned. Advisory vectors (dependency CVEs) always win.
import { cvss3Score } from "./deps";
import type { Severity } from "../db/schema";

const V = (m: string) => `CVSS:3.1/${m}`;

// Reference vectors per severity band: network reachable, no privileges, impact scaled to the band.
const BY_SEVERITY: Record<Severity, string> = {
  critical: V("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), // 9.8
  high: V("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),     // 7.5
  medium: V("AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"),   // 5.4
  low: V("AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"),      // 3.1
  info: V("AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N"),     // 0.0
};

// Issue types with a specific vector. Keys are "<checkKey>:<issueKey>" or "<checkKey>:<issueKey prefix>*".
const BY_ISSUE: Record<string, string> = {
  "http.security_headers:missing_hsts": V("AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N"),
  "http.security_headers:weak_hsts": V("AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N"),
  "http.security_headers:missing_csp": V("AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N"),
  "http.security_headers:weak_csp": V("AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N"),
  "http.security_headers:missing_frame_protection": V("AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"),
  "http.security_headers:missing_nosniff": V("AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N"),
  "http.security_headers:unsafe_referrer_policy": V("AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"),
  "http.security_headers:version_disclosure": V("AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
  "tls.cert_expiry:cert_expired": V("AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"),
  "tls.cert_expiry:cert_untrusted": V("AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:N"),
  "tls.config:*": V("AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N"),
  "http.cors:cors_reflects_origin_credentials": V("AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N"),
  "http.cors:cors_null_origin_credentials": V("AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N"),
  "http.cors:cors_wildcard_credentials": V("AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N"),
  "http.cors:*": V("AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"),
  "dns.takeover:*": V("AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:H/A:N"),
  "dns.email_posture:spf_pass_all": V("AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:H/A:N"),
  "dns.email_posture:*": V("AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"),
  "dns.caa:*": V("AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"),
  "net.exposed_services:*": V("AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"),
  "http.exposure:*": V("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
  "code.secrets:*": V("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
  "web.blocklist:*": V("AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
  "web.technology:*": V("AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"),
};

const band = (score: number): Severity => (score >= 9 ? "critical" : score >= 7 ? "high" : score >= 4 ? "medium" : score > 0 ? "low" : "info");

export interface Cvss { score: number | null; vector: string; source: "advisory" | "rated" }

/** The CVSS vector RuyaShield assigns to a finding type at this severity. */
export function ratedVector(checkKey: string, issueKey: string, severity: Severity): string {
  const specific = BY_ISSUE[`${checkKey}:${issueKey}`]
    ?? Object.entries(BY_ISSUE).find(([k]) => k.endsWith("*") && `${checkKey}:${issueKey}`.startsWith(k.slice(0, -1)))?.[1];
  if (specific) {
    const s = cvss3Score(specific);
    if (s !== null && band(s) === severity) return specific;
  }
  return BY_SEVERITY[severity] ?? BY_SEVERITY.medium;
}

/** A finding's CVSS: the advisory's stored vector, else the RuyaShield rating for its type and current severity. */
export function findingCvss(f: { cvssVector?: string | null; checkKey: string; issueKey: string; severity: Severity }): Cvss {
  if (f.cvssVector) return { score: cvss3Score(f.cvssVector), vector: f.cvssVector, source: "advisory" };
  const vector = ratedVector(f.checkKey, f.issueKey, f.severity);
  return { score: cvss3Score(vector), vector, source: "rated" };
}
