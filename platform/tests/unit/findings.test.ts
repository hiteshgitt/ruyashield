import { describe, expect, it } from "vitest";
import { canonicalJson, evidenceClass, redactEvidence, redactSecrets, sha256, verifyIntegrity } from "@/server/findings/evidence";
import { isOpen, systemTransitionAllowed, userTransition, userTransitionsFrom, USER_TRANSITIONS } from "@/server/findings/lifecycle";
import { priorityOf } from "@/server/findings/priority";
import { mentionedEmails } from "@/server/findings/findings";

describe("evidence", () => {
  it("removes credentials before storage", () => {
    const text = redactSecrets("GET / HTTP/1.1\nCookie: sid=abc123\nAuthorization: Bearer xyz\nAccept: */*", "text/plain");
    expect(text).not.toContain("abc123");
    expect(text).not.toContain("xyz");
    expect(text).toContain("Accept: */*");
    const json = JSON.parse(redactSecrets(JSON.stringify({ headers: { "set-cookie": "s=1", server: "nginx" }, apiKey: "k" }), "application/json"));
    expect(json).toEqual({ headers: { "set-cookie": "[REDACTED]", server: "nginx" }, apiKey: "[REDACTED]" });
  });

  it("masks personal data for display but keeps IPs and dates", () => {
    const out = redactEvidence("contact alice@example.com or +44 20 7946 0958 from 10.0.0.1 on 2026-10-30", "text/plain");
    expect(out).toContain("[REDACTED_EMAIL]");
    expect(out).toContain("[REDACTED_PHONE]");
    expect(out).toContain("10.0.0.1");
    expect(out).toContain("2026-10-30");
  });

  it("evidence class ignores volatile fields and key order", () => {
    expect(evidenceClass({ missing: ["hsts"], daysRemaining: 3 })).toBe(evidenceClass({ daysRemaining: 9, missing: ["hsts"] }));
    expect(evidenceClass({ missing: ["hsts"] })).not.toBe(evidenceClass({ missing: ["csp"] }));
    expect(canonicalJson({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
  });

  it("detects tampering", () => {
    const body = "observed";
    expect(verifyIntegrity({ body, sha256: sha256(body) })).toBe(true);
    expect(verifyIntegrity({ body: "observed!", sha256: sha256(body) })).toBe(false);
  });
});

describe("lifecycle", () => {
  it("users can never set resolved_verified, reopened or stale", () => {
    const targets = USER_TRANSITIONS.map((t) => t.to);
    for (const s of ["resolved_verified", "reopened", "stale"] as const) expect(targets).not.toContain(s);
  });

  it("marking a fix applied leaves the finding open", () => {
    expect(userTransition("mark_fix_applied", "in_remediation")?.to).toBe("fix_pending_verification");
    expect(isOpen("fix_pending_verification")).toBe(true);
  });

  it("rejects moves from the wrong status", () => {
    expect(userTransition("confirm", "new")).toBeNull();
    expect(userTransition("accept_risk", "new")).toBeNull();
    expect(userTransitionsFrom("resolved_verified")).toEqual([]);
  });

  it("only a verification may resolve; risk expiry returns to triage", () => {
    expect(systemTransitionAllowed("fix_pending_verification", "resolved_verified", "verified_fixed")).toBe(true);
    expect(systemTransitionAllowed("in_remediation", "resolved_verified", "verified_fixed")).toBe(false);
    expect(systemTransitionAllowed("accepted_risk", "triaged", "risk_expired")).toBe(true);
    expect(systemTransitionAllowed("confirmed", "stale", "not_seen")).toBe(false);
  });
});

describe("priority", () => {
  it("multiplies severity, confidence and criticality, defaulting to medium", () => {
    const p = priorityOf({ severity: "high", confidence: "confirmed" }, null);
    expect(p).toMatchObject({ score: 7.5, criticalityDefault: true, inputs: { criticality: "medium" } });
    expect(priorityOf({ severity: "high", confidence: "confirmed" }, "critical").score).toBe(11.25);
    expect(priorityOf({ severity: "critical", confidence: "suspected" }, "low").score).toBe(3.5);
  });
});

describe("mentions", () => {
  it("extracts @email mentions, deduplicated and lower-cased", () => {
    expect(mentionedEmails("ping @Bob@Example.com and @bob@example.com, cc (@ann@x.io)")).toEqual(["bob@example.com", "ann@x.io"]);
    expect(mentionedEmails("mail me at bob@example.com")).toEqual([]);
  });
});
