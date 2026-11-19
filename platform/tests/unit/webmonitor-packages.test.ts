import { describe, expect, it } from "vitest";
import { createWebMonitorPackagesAdapter, packageFindings, type StoredReport } from "@/server/webmonitor/packages";

const now = new Date("2026-11-19T12:00:00Z");
const report = (o: Partial<StoredReport> = {}): StoredReport => ({
  host: "shop.example.com", ecosystem: "npm", observedAt: new Date("2026-11-19T06:00:00Z"),
  packages: [{ name: "next", version: "16.4.3", severity: "moderate", ids: ["GHSA-mfr8-8qww-v76h", "GHSA-vc7v-qv4w-wrv8"], aliases: ["CVE-2026-119790"], fixed: "16.4.5", summary: "Info disclosure" }],
  ...o,
});
const ctx = { host: "shop.example.com", onHop: async () => {}, egress: {}, dns: {}, timeoutMs: 1000, now: () => now };

describe("webmonitor.packages", () => {
  it("one finding per vulnerable package, with CVE, fix and an upgrade command", () => {
    const [f] = packageFindings("shop.example.com", report());
    expect(f.issueKey).toBe("pkg.npm.next");
    expect(f.title).toBe("next 16.4.3 has a known vulnerability (CVE-2026-119790 and 1 more advisory)");
    expect(f.severity).toBe("medium");
    expect(f.remediation).toContain("npm install next@^16.4.5");
    expect(f.evidence).toMatchObject({ installed: "16.4.3", fixedIn: "16.4.5", advisories: ["GHSA-mfr8-8qww-v76h", "GHSA-vc7v-qv4w-wrv8"] });
  });

  it("no report means nothing to judge; a stale report is an error so findings stay open", async () => {
    expect(await createWebMonitorPackagesAdapter({ lookup: async () => null }).run(ctx)).toMatchObject({ status: "ok", findings: [] });
    const stale = await createWebMonitorPackagesAdapter({ lookup: async () => report({ observedAt: new Date("2026-11-15T00:00:00Z") }) }).run(ctx);
    expect(stale).toMatchObject({ status: "error", reason: "webmonitor_report_stale" });
    const fresh = await createWebMonitorPackagesAdapter({ lookup: async () => report() }).run(ctx);
    expect(fresh.status === "ok" && fresh.findings.length).toBe(1);
  });

  it("Composer packages get a composer command; packages without a fix say so", () => {
    const [f] = packageFindings("shop.example.com", report({ ecosystem: "packagist", packages: [{ name: "laravel/framework", version: "10.0.0", severity: "critical", ids: ["GHSA-x"], aliases: [], fixed: null, summary: null }] }));
    expect(f.severity).toBe("critical");
    expect(f.remediation).toContain("No fixed release of laravel/framework yet");
    expect(packageFindings("h", report({ ecosystem: "packagist", packages: [{ name: "a/b", version: "1.0.0", severity: "low", ids: ["GHSA-y"], aliases: [], fixed: "1.0.1", summary: null }] }))[0].remediation).toContain("composer require a/b:^1.0.1");
  });
});

describe("webmonitor.packages keys", () => {
  it("scoped and Composer names become valid finding keys", async () => {
    const { packageIssueKey } = await import("@/server/webmonitor/packages");
    expect(packageIssueKey("npm", "@Next/Font")).toBe("pkg.npm._next_font");
    expect(packageIssueKey("packagist", "laravel/framework")).toBe("pkg.packagist.laravel_framework");
    expect(packageIssueKey("npm", "x".repeat(200)).length).toBe(80);
  });
});
