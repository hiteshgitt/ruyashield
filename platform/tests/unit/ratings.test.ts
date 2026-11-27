import { describe, expect, it } from "vitest";
import { cvss3Score } from "@/server/assessments/deps";
import { findingCvss, ratedVector } from "@/server/assessments/ratings";

const SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;
const band = (s: number) => (s >= 9 ? "critical" : s >= 7 ? "high" : s >= 4 ? "medium" : s > 0 ? "low" : "info");
const TYPES: [string, string][] = [
  ["http.security_headers", "missing_hsts"], ["http.security_headers", "missing_csp"], ["http.security_headers", "version_disclosure"],
  ["tls.cert_expiry", "cert_expired"], ["tls.config", "tls10_enabled"], ["http.cors", "cors_reflects_origin_credentials"],
  ["dns.takeover", "dangling_cname"], ["dns.email_posture", "dmarc_missing"], ["net.exposed_services", "port_3306"],
  ["http.exposure", "env_file"], ["code.secrets", "aws-access-key.x"], ["code.sast", "sql-injection.y"], ["web.blocklist", "urlhaus.active"],
];

describe("CVSS ratings", () => {
  it("always scores inside the finding's severity band", () => {
    for (const [check, issue] of TYPES) for (const sev of SEVERITIES) {
      const score = cvss3Score(ratedVector(check, issue, sev));
      expect(score, `${check}:${issue}@${sev}`).not.toBeNull();
      expect(band(score!), `${check}:${issue}@${sev}`).toBe(sev);
    }
  });
  it("uses the specific vector when it fits, and prefers the advisory's own vector", () => {
    expect(ratedVector("http.security_headers", "missing_frame_protection", "medium")).toBe("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N");
    const adv = findingCvss({ cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", checkKey: "deps.osv", issueKey: "vulnerable_dependency", severity: "critical" });
    expect(adv).toEqual({ score: 9.8, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", source: "advisory" });
    const rated = findingCvss({ cvssVector: null, checkKey: "http.security_headers", issueKey: "missing_hsts", severity: "low" });
    expect(rated.source).toBe("rated");
    expect(band(rated.score!)).toBe("low");
  });
});
