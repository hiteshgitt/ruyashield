import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { normalizeResult, type CheckContext } from "@/server/assessments/checks";
import { createExposureAdapter, isEnvFile, isGitHead, LISTING_DIRS, type Fetch } from "@/server/assessments/exposure";
import { EgressError, type FetchResult } from "@/server/net/egress";

const HOST = "shop.example.com";
const ctx = { host: HOST, timeoutMs: 30000, egress: {}, onHop: () => {} } as unknown as CheckContext;
const SOFT = "/ruya-soft404";
const res = (status: number, body = "", contentType: string | null = "text/html", truncated = false): FetchResult =>
  ({ status, body, contentType, truncated, redirects: 0, finalUrl: "", pinnedAddress: "203.0.113.10", headers: {} } as FetchResult);
const NOT_FOUND = res(404, "<h1>Not found</h1>");
const ENV = "# app\nDB_PASSWORD=hunter2-very-secret\nAPI_KEY=sk_live_abc\n";

/** Recorded responses by path; anything unlisted is a 404. */
function fake(pages: Record<string, FetchResult | Error>, calls: string[] = []): Fetch {
  return async (url) => {
    calls.push(url);
    const r = pages[new URL(url).pathname] ?? NOT_FOUND;
    if (r instanceof Error) throw r;
    return r;
  };
}
const run = async (pages: Record<string, FetchResult | Error>, calls?: string[]) => normalizeResult(await createExposureAdapter(fake(pages, calls), () => SOFT).run(ctx));

describe("exposed-file matchers", () => {
  it("recognise git HEAD files and env files only", () => {
    expect(isGitHead("ref: refs/heads/main\n")).toBe(true);
    expect(isGitHead("a".repeat(40))).toBe(true);
    expect(isGitHead("<!doctype html><title>ref: refs</title>")).toBe(false);
    expect(isEnvFile(ENV, "text/plain")).toBe(true);
    expect(isEnvFile("export APP_KEY=x", null)).toBe(true);
    expect(isEnvFile("APP_KEY=x", "text/html; charset=utf-8")).toBe(false);
    expect(isEnvFile("<html>", "text/plain")).toBe(false);
    expect(isEnvFile("lowercase=1", "text/plain")).toBe(false);
  });
});

describe("http.exposure adapter", () => {
  it("reports nothing for a clean site, probing each path once without following redirects", async () => {
    const calls: string[] = [];
    const r = await run({ "/": res(200, "<h1>Welcome</h1>"), "/.git/HEAD": res(302), "/.env": res(403) }, calls);
    expect(r).toMatchObject({ status: "ok", findings: [] });
    expect(calls).toEqual([SOFT, "/.git/HEAD", "/.env", ...LISTING_DIRS].map((p) => `https://${HOST}${p}`));
  });

  it("raises critical findings for .git and .env with evidence that never contains the file", async () => {
    const r = await run({ "/.git/HEAD": res(200, "ref: refs/heads/main\n", "text/plain"), "/.env": res(200, ENV, "application/octet-stream", true), "/uploads/": res(200, "<title>Index of /uploads</title><h1>Index of /uploads</h1>") });
    expect(r.status).toBe("ok");
    if (r.status !== "ok") return;
    expect(r.findings.map((f) => [f.issueKey, f.severity, f.location, f.confidence])).toEqual([
      ["git-exposed", "critical", `https://${HOST}/.git/HEAD`, undefined],
      ["env-exposed", "critical", `https://${HOST}/.env`, undefined],
      ["directory-listing", "low", `https://${HOST}/uploads/`, undefined],
    ]);
    const env = r.findings[1];
    expect(env.evidence).toEqual({ status: 200, contentType: "application/octet-stream", bytesRead: Buffer.byteLength(ENV), truncated: true, prefixSha256: createHash("sha256").update(ENV).digest("hex"), softNotFound: "404" });
    const stored = JSON.stringify(r);
    expect(stored).not.toContain("hunter2");
    expect(stored).not.toContain("sk_live");
    expect(stored).not.toContain("refs/heads/main");
    expect(env.remediation).toMatch(/rotate/i);
  });

  it("ignores catch-all pages identical to the soft-404 and downgrades confidence when the catch-all answers 200", async () => {
    const spa = res(200, "ref: refs/heads/main\nAPP_KEY=x\nIndex of /", "text/plain");
    expect(await run({ [SOFT]: spa, "/.git/HEAD": spa, "/.env": spa, "/": spa })).toMatchObject({ status: "ok", findings: [] });
    const r = await run({ [SOFT]: res(200, "<div id=app></div>"), "/.env": res(200, "APP_KEY=base64:x\n", "text/plain") });
    expect(r).toMatchObject({ status: "ok", findings: [{ issueKey: "env-exposed", confidence: "likely", evidence: { softNotFound: "200" } }] });
  });

  it("does not report HTML pages or non-200 answers as .env", async () => {
    expect(await run({ "/.env": res(200, "APP_KEY=x", "text/html") })).toMatchObject({ status: "ok", findings: [] });
    expect(await run({ "/.env": res(401, ENV, "text/plain") })).toMatchObject({ status: "ok", findings: [] });
  });

  it("fails closed on 5xx, 429 and network errors", async () => {
    expect(await run({ [SOFT]: res(503) })).toMatchObject({ status: "error", reason: "http_503" });
    expect(await run({ "/.env": res(429) })).toMatchObject({ status: "error", reason: "http_429" });
    expect(await run({ "/backup/": res(500) })).toMatchObject({ status: "error", reason: "http_500" });
    expect(await run({ "/.git/HEAD": new EgressError("network", "ECONNRESET") })).toMatchObject({ status: "error", reason: "host_unreachable" });
    expect(await run({ "/": new EgressError("timeout", "slow") })).toMatchObject({ status: "error", reason: "timeout" });
  });
});
