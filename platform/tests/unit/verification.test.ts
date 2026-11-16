import { describe, expect, it } from "vitest";
import { classify, mapResults, verifyFixProof } from "@/server/verification/verification";
import { fingerprint } from "@/server/assessments/checks";
import { canonicalJson, sha256 } from "@/server/findings/evidence";

const f = { location: "https://a.example.com/", fingerprint: fingerprint("http.security_headers", "https://a.example.com/", "hsts_missing") };
const hit = { issueKey: "hsts_missing", title: "x", severity: "medium" as const, location: "https://a.example.com/", evidence: {}, remediation: "" };

describe("verification verdicts", () => {
  it("fails when the same issue is seen again", () => {
    expect(classify(f, "http.security_headers", { status: "ok", findings: [hit], evidence: {} })).toBe("failed");
  });
  it("passes only when the same location was checked", () => {
    expect(classify(f, "http.security_headers", { status: "ok", findings: [], evidence: { finalUrl: "https://a.example.com/" } })).toBe("passed");
    expect(classify(f, "http.security_headers", { status: "ok", findings: [], evidence: { finalUrl: "https://a.example.com/login" } })).toBe("inconclusive");
  });
  it("passes a second URL only when the check lists it as judged", () => {
    const h = { location: "http://a.example.com/", fingerprint: fingerprint("http.security_headers", "http://a.example.com/", "http_no_redirect") };
    const ok = { status: "ok" as const, findings: [] };
    expect(classify(h, "http.security_headers", { ...ok, evidence: { finalUrl: "https://a.example.com/", checkedLocations: ["https://a.example.com/", "http://a.example.com/"] } })).toBe("passed");
    // Port 80 unreachable on re-test: the redirect was never observed, so nothing is concluded.
    expect(classify(h, "http.security_headers", { ...ok, evidence: { finalUrl: "https://a.example.com/", checkedLocations: ["https://a.example.com/"] } })).toBe("inconclusive");
  });
  it("treats a check error as an error, never a pass", () => {
    expect(classify(f, "http.security_headers", { status: "error", reason: "timeout", evidence: {} })).toBe("error");
  });
});

describe("verification outcome", () => {
  it.each([
    [[], "unverified"],
    [["passed"], "verified"],
    [["passed", "passed"], "verified"],
    [["passed", "failed"], "failed"],
    [["passed", "inconclusive"], "partially_verified"],
    [["passed", "error"], "partially_verified"],
    [["inconclusive"], "unverified"],
    [["error"], "unverified"],
    [["error", "inconclusive"], "unverified"],
  ] as const)("%j → %s", (v, out) => {
    expect(mapResults(v)).toBe(out);
  });
  it("never maps inconclusive or error results to verified", () => {
    for (const v of [["inconclusive"], ["error"], ["passed", "inconclusive"], ["passed", "error"]] as const) expect(mapResults(v)).not.toBe("verified");
  });
});

describe("FixProof integrity", () => {
  const content = { id: "11111111-1111-4111-8111-111111111111", seq: 2, version: 1, status: "verified", findingId: "f", verificationRunId: "r", prevSha256: "a".repeat(64) };
  const row = { ...content, content, sha256: sha256(canonicalJson(content)) } as unknown as Parameters<typeof verifyFixProof>[0];
  it("accepts an untouched record and checks the chain when the previous hash is known", () => {
    expect(verifyFixProof(row, { sha256: "a".repeat(64) })).toEqual({ ok: true, hash: true, fields: true, chain: true });
    expect(verifyFixProof(row, undefined)).toMatchObject({ ok: true, chain: null });
    expect(verifyFixProof(row, { sha256: "b".repeat(64) })).toMatchObject({ ok: false, chain: false });
  });
  it("detects edited content and mismatched columns", () => {
    expect(verifyFixProof({ ...row, content: { ...content, status: "failed" } } as typeof row, undefined)).toMatchObject({ ok: false, hash: false });
    expect(verifyFixProof({ ...row, status: "failed" } as typeof row, undefined)).toMatchObject({ ok: false, fields: false });
  });
});
