import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { normalizeResult, type CheckContext } from "@/server/assessments/checks";
import {
  compareVersions, createOsvAdapter, cvss3Score, fixedVersion, lockfileParser, parseComposerLock, parseGemfileLock, parseGoSum,
  parsePackageLock, parsePnpmLock, parseRequirements, parseTomlPackages, parseYarnLock, severityOf, type FetchLike, type OsvVuln,
} from "@/server/assessments/deps";
import type { RepoSnapshot } from "@/server/remediation/repo";

// Recorded from api.osv.dev on 2026-11-09 (lodash 4.17.15 and 4.17.21).
const FIX = join(__dirname, "../fixtures/osv");
const fixture = (name: string) => readFileSync(join(FIX, name), "utf8");
const VULN_IDS = ["GHSA-29mw-wpgm-hmr9", "GHSA-35jh-r3h4-6jhm", "GHSA-p6mc-m468-83gw", "GHSA-r5fr-rjxr-66jc", "GHSA-xxjr-mmjv-4gpg"];
const vuln = (id: string) => JSON.parse(fixture(`${id}.json`)) as OsvVuln;

const lock = (deps: Record<string, string>) => JSON.stringify({
  name: "demo", lockfileVersion: 3, requires: true,
  packages: { "": { name: "demo", dependencies: deps }, ...Object.fromEntries(Object.entries(deps).map(([n, v]) => [`node_modules/${n}`, { version: v }])) },
});

function repo(files: Record<string, string>, commit = "a".repeat(40)): RepoSnapshot {
  return { externalId: "demo", commit, list: async () => Object.keys(files), read: async (p) => { if (!(p in files)) throw new Error("not_found"); return files[p]; } };
}

/** OSV stand-in answering from the recorded fixtures; records every URL so tests can assert egress. */
function fakeOsv(opts: { fail?: "network" | "http" | "malformed"; flaky?: number } = {}) {
  const calls: string[] = [];
  let flaky = opts.flaky ?? 0;
  const fetch: FetchLike = async (url, init) => {
    calls.push(`${init.method} ${url}`);
    if (opts.fail === "network") throw new TypeError("fetch failed", { cause: { code: "ETIMEDOUT" } });
    if (flaky > 0) { flaky--; throw new TypeError("fetch failed", { cause: { code: "ETIMEDOUT" } }); }
    if (opts.fail === "http") return { ok: false, status: 503, text: async () => "" };
    if (opts.fail === "malformed") return { ok: true, status: 200, text: async () => "<html>" };
    const u = new URL(url);
    if (u.pathname === "/v1/querybatch") {
      const recorded = JSON.parse(fixture("querybatch-lodash.json")).results as unknown[];
      const queries = JSON.parse(init.body!).queries as { package: { name: string }; version: string }[];
      return { ok: true, status: 200, text: async () => JSON.stringify({ results: queries.map((q) =>
        q.package.name !== "lodash" ? {} : q.version === "4.17.15" ? recorded[0] : q.version === "4.17.21" ? recorded[1] : {}) }) };
    }
    const id = u.pathname.split("/").pop()!;
    return { ok: true, status: 200, text: async () => fixture(`${id}.json`) };
  };
  return { fetch, calls };
}

const ctx = (r?: RepoSnapshot): CheckContext => ({
  host: "repo:demo", onHop: async () => { throw new Error("repository checks must not use the host scope guard"); },
  egress: {} as CheckContext["egress"], dns: {} as CheckContext["dns"], timeoutMs: 30_000, repo: r,
});

describe("lockfile parsers", () => {
  it("reads package-lock v3, skipping the root, links and non-registry versions", () => {
    const text = JSON.stringify({ lockfileVersion: 3, packages: {
      "": { name: "app" }, "node_modules/lodash": { version: "4.17.15" }, "node_modules/a/node_modules/@scope/b": { version: "1.2.3" },
      "node_modules/local": { link: true, resolved: "packages/local" }, "node_modules/gitdep": { version: "git+https://x/y.git#abc" }, "packages/local": { version: "0.0.1" },
    } });
    expect(parsePackageLock(text, "package-lock.json").packages).toEqual([
      { ecosystem: "npm", name: "lodash", version: "4.17.15" }, { ecosystem: "npm", name: "@scope/b", version: "1.2.3" },
    ]);
  });
  it("reads package-lock v1 nested dependencies", () => {
    const text = JSON.stringify({ lockfileVersion: 1, dependencies: { a: { version: "1.0.0", dependencies: { b: { version: "2.0.0" } } } } });
    expect(parsePackageLock(text, "x").packages.map((p) => `${p.name}@${p.version}`)).toEqual(["a@1.0.0", "b@2.0.0"]);
  });
  it("rejects lockfiles it cannot understand instead of reporting them empty", () => {
    expect(() => parsePackageLock("{nope", "package-lock.json")).toThrow(/not valid JSON/);
    expect(() => parsePackageLock("{}", "package-lock.json")).toThrow(/lockfileVersion/);
    expect(() => parseGoSum("garbage here", "go.sum")).toThrow(/go\.sum/);
    expect(() => parseComposerLock("{}", "composer.lock")).toThrow(/packages/);
    expect(() => parsePnpmLock("packages:\n", "pnpm-lock.yaml")).toThrow(/lockfileVersion/);
    expect(() => parseTomlPackages("[package]\nname = 'x'", "Cargo.lock", "crates.io")).toThrow(/package/);
  });
  it("reads yarn.lock v1 and berry", () => {
    const v1 = `# yarn lockfile v1\n\n"@babel/core@^7.0.0", "@babel/core@^7.1.0":\n  version "7.2.0"\n  resolved "https://x"\n\nlodash@^4.17.0:\n  version "4.17.15"\n`;
    expect(parseYarnLock(v1, "yarn.lock").packages).toEqual([{ ecosystem: "npm", name: "@babel/core", version: "7.2.0" }, { ecosystem: "npm", name: "lodash", version: "4.17.15" }]);
    const berry = `__metadata:\n  version: 6\n\n"lodash@npm:^4.17.0":\n  version: 4.17.21\n  resolution: "lodash@npm:4.17.21"\n`;
    expect(parseYarnLock(berry, "yarn.lock").packages).toEqual([{ ecosystem: "npm", name: "lodash", version: "4.17.21" }]);
  });
  it("reads pnpm-lock keys across versions", () => {
    const t = `lockfileVersion: '9.0'\n\npackages:\n\n  lodash@4.17.15:\n    resolution: {integrity: x}\n\n  '@types/node@20.1.0':\n    resolution: {}\n\n  /react-dom/18.2.0_react@18.2.0:\n    resolution: {}\n\nsnapshots:\n  x@1.0.0:\n    resolution: {}\n`;
    expect(parsePnpmLock(t, "pnpm-lock.yaml").packages.map((p) => `${p.name}@${p.version}`)).toEqual(["lodash@4.17.15", "@types/node@20.1.0", "react-dom@18.2.0"]);
  });
  it("only checks exact pins in requirements.txt and counts the rest", () => {
    const r = parseRequirements("# c\nDjango==3.2.1  # pinned\nrequests>=2\nflask\n-r other.txt\nPyYAML[extra]==5.3 ; python_version<'3.9'\ngit+https://x/y\n");
    expect(r.packages).toEqual([{ ecosystem: "PyPI", name: "django", version: "3.2.1" }, { ecosystem: "PyPI", name: "pyyaml", version: "5.3" }]);
    expect(r.unpinned).toBe(2);
  });
  it("reads poetry/Cargo, go.sum, composer and Gemfile locks", () => {
    expect(parseTomlPackages(`[[package]]\nname = "requests"\nversion = "2.19.0"\n\n[package.dependencies]\nx = "*"\n`, "poetry.lock", "PyPI")).toEqual([{ ecosystem: "PyPI", name: "requests", version: "2.19.0" }]);
    expect(parseTomlPackages(`version = 3\n\n[[package]]\nname = "app"\nversion = "0.1.0"\n\n[[package]]\nname = "smallvec"\nversion = "1.6.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n`, "Cargo.lock", "crates.io"))
      .toEqual([{ ecosystem: "crates.io", name: "smallvec", version: "1.6.0" }]);
    expect(parseGoSum("golang.org/x/text v0.3.5 h1:abc=\ngolang.org/x/text v0.3.5/go.mod h1:def=\n", "go.sum").packages).toEqual([{ ecosystem: "Go", name: "golang.org/x/text", version: "0.3.5" }]);
    expect(parseComposerLock(JSON.stringify({ packages: [{ name: "guzzlehttp/guzzle", version: "v7.4.0" }], "packages-dev": [{ name: "phpunit/phpunit", version: "9.5.0" }] }), "c").packages.map((p) => p.version)).toEqual(["7.4.0", "9.5.0"]);
    expect(parseGemfileLock("GEM\n  remote: https://rubygems.org/\n  specs:\n    nokogiri (1.10.0-x86_64-linux)\n      racc (~> 1.4)\n    rack (2.0.1)\n\nPLATFORMS\n  ruby\n", "Gemfile.lock").packages)
      .toEqual([{ ecosystem: "RubyGems", name: "nokogiri", version: "1.10.0" }, { ecosystem: "RubyGems", name: "rack", version: "2.0.1" }]);
  });
  it("ignores vendored lockfiles", () => {
    expect(lockfileParser("node_modules/x/package-lock.json")).toBeNull();
    expect(lockfileParser("vendor/a/composer.lock")).toBeNull();
    expect(lockfileParser("apps/web/package-lock.json")).not.toBeNull();
    expect(lockfileParser("requirements-dev.txt")).not.toBeNull();
  });
});

describe("severity and fixes", () => {
  it("scores CVSS 3.x vectors per the spec", () => {
    expect(cvss3Score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")).toBe(9.8);
    expect(cvss3Score("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H")).toBe(7.2);
    expect(cvss3Score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")).toBe(6.1);
    expect(cvss3Score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")).toBe(0);
    expect(cvss3Score("CVSS:4.0/AV:N")).toBeNull();
  });
  it("prefers the CVSS vector, falls back to the advisory label, and admits when it has neither", () => {
    expect(severityOf(vuln("GHSA-35jh-r3h4-6jhm"))).toBe("high");
    expect(severityOf(vuln("GHSA-29mw-wpgm-hmr9"))).toBe("medium");
    expect(severityOf({ id: "X", database_specific: { severity: "CRITICAL" } })).toBe("critical");
    expect(severityOf({ id: "X" })).toBeNull();
  });
  it("picks the lowest fix above the installed version for that exact package", () => {
    const pkg = { ecosystem: "npm" as const, name: "lodash", version: "4.17.15" };
    expect(fixedVersion(vuln("GHSA-p6mc-m468-83gw"), pkg)).toBe("4.17.19");
    expect(fixedVersion(vuln("GHSA-r5fr-rjxr-66jc"), pkg)).toBe("4.18.0");
    expect(fixedVersion({ id: "X", affected: [{ package: { ecosystem: "npm", name: "lodash" }, ranges: [{ events: [{ introduced: "0" }] }] }] }, pkg)).toBeNull();
    expect(compareVersions("4.17.9", "4.17.10")).toBeLessThan(0);
    expect(compareVersions("1.0.0-rc1", "1.0.0")).toBeLessThan(0);
  });
});

describe("deps.osv adapter", () => {
  it("raises one finding per vulnerable package, with advisories, fix and lockfile hash, and no host egress", async () => {
    const osv = fakeOsv();
    const files = { "package-lock.json": lock({ lodash: "4.17.15", leftpad: "1.0.0" }), "README.md": "x" };
    const r = normalizeResult(await createOsvAdapter({ fetch: osv.fetch }).run(ctx(repo(files))));
    expect(r.status).toBe("ok");
    if (r.status !== "ok") return;
    expect(r.findings).toHaveLength(1);
    const f = r.findings[0];
    expect(f).toMatchObject({ issueKey: "vulnerable_dependency", severity: "high", location: "package-lock.json#lodash@4.17.15" });
    expect(f.confidence).toBeUndefined();
    expect(f.title).toMatch(/^lodash 4\.17\.15: 5 known vulnerabilities/);
    expect(f.remediation).toMatch(/Upgrade lodash from 4\.17\.15 to 4\.18\.0 or later/);
    expect(f.evidence).toMatchObject({ fixedVersion: "4.18.0", lockfile: "package-lock.json", lockfileSha256: expect.stringMatching(/^[0-9a-f]{64}$/) });
    expect((f.evidence.advisories as { id: string }[]).map((a) => a.id).sort()).toEqual(VULN_IDS);
    expect(r.evidence).toMatchObject({ commit: "a".repeat(40), packagesChecked: 2, vulnerablePackages: 1, source: "osv.dev" });
    expect(osv.calls.every((c) => c.includes("https://api.osv.dev/v1/"))).toBe(true);
  });

  it("keeps the same fingerprint inputs when only unrelated packages change, and drops the finding once upgraded", async () => {
    const osv = fakeOsv();
    const a = createOsvAdapter({ fetch: osv.fetch });
    const before = await a.run(ctx(repo({ "package-lock.json": lock({ lodash: "4.17.15" }) })));
    const other = await a.run(ctx(repo({ "package-lock.json": lock({ lodash: "4.17.15", leftpad: "1.0.0" }) })));
    const after = await a.run(ctx(repo({ "package-lock.json": lock({ lodash: "4.18.1" }) })));
    expect(before.status === "ok" && other.status === "ok" && before.findings[0].location === other.findings[0].location).toBe(true);
    expect(after).toMatchObject({ status: "ok", findings: [] });
  });

  it("marks severity as likely when an advisory has no usable severity", async () => {
    const fetch: FetchLike = async (url) => ({ ok: true, status: 200, text: async () => url.endsWith("querybatch")
      ? JSON.stringify({ results: [{ vulns: [{ id: "OSV-2026-1" }] }] })
      : JSON.stringify({ id: "OSV-2026-1", summary: "s", affected: [{ package: { ecosystem: "npm", name: "x" }, ranges: [{ events: [{ introduced: "0" }, { fixed: "2.0.0" }] }] }] }) });
    const r = await createOsvAdapter({ fetch }).run(ctx(repo({ "package-lock.json": lock({ x: "1.0.0" }) })));
    expect(r).toMatchObject({ status: "ok", findings: [{ severity: "medium", confidence: "likely" }] });
  });

  it("reports a repo with no lockfiles as ok with nothing checked, and unpinned requirements as info", async () => {
    const osv = fakeOsv();
    expect(await createOsvAdapter({ fetch: osv.fetch }).run(ctx(repo({ "src/a.ts": "" })))).toMatchObject({ status: "ok", findings: [], evidence: { lockfiles: [], packagesChecked: 0 } });
    const r = await createOsvAdapter({ fetch: osv.fetch }).run(ctx(repo({ "requirements.txt": "flask\nrequests>=2\n" })));
    expect(r).toMatchObject({ status: "ok", findings: [{ issueKey: "unpinned_dependencies", severity: "info", location: "requirements.txt" }] });
    expect(osv.calls).toEqual([]);
  });

  it.each(["network", "http", "malformed"] as const)("fails closed when OSV is %s-broken", async (fail) => {
    const osv = fakeOsv({ fail });
    const r = await createOsvAdapter({ fetch: osv.fetch, retryDelayMs: 0 }).run(ctx(repo({ "package-lock.json": lock({ lodash: "4.17.15" }) })));
    expect(r.status).toBe("error");
    expect(r).toMatchObject({ reason: { network: "osv_unreachable", http: "osv_http_503", malformed: "osv_malformed_response" }[fail] });
    // Only connection failures are retried (3 attempts); an HTTP error or bad body is final.
    expect(osv.calls).toHaveLength(fail === "network" ? 3 : 1);
    if (fail === "network") expect(r).toMatchObject({ evidence: { detail: "TypeError:ETIMEDOUT" } });
  });

  it("retries a dropped connection and still reports the findings", async () => {
    const osv = fakeOsv({ flaky: 2 });
    const r = await createOsvAdapter({ fetch: osv.fetch, retryDelayMs: 0 }).run(ctx(repo({ "package-lock.json": lock({ lodash: "4.17.15" }) })));
    expect(r.status).toBe("ok");
    expect(r.status === "ok" && r.findings.length).toBeGreaterThan(0);
  });

  it("fails closed on an unparseable or unreadable lockfile, and without a snapshot", async () => {
    const osv = fakeOsv();
    const a = createOsvAdapter({ fetch: osv.fetch });
    expect(await a.run(ctx(repo({ "package-lock.json": "{oops" })))).toMatchObject({ status: "error", reason: "lockfile_unparseable", evidence: { lockfile: "package-lock.json" } });
    const broken: RepoSnapshot = { ...repo({}), list: async () => ["go.sum"], read: async () => { throw new Error("file_too_large"); } };
    expect(await a.run(ctx(broken))).toMatchObject({ status: "error", reason: "lockfile_unreadable" });
    expect(await a.run(ctx(undefined))).toMatchObject({ status: "error", reason: "no_repository_snapshot" });
    expect(osv.calls).toEqual([]);
  });

  it("errors instead of truncating past the finding cap", async () => {
    const fetch: FetchLike = async (url, init) => {
      if (url.endsWith("querybatch")) return { ok: true, status: 200, text: async () => JSON.stringify({ results: JSON.parse(init.body!).queries.map(() => ({ vulns: [{ id: "GHSA-p6mc-m468-83gw" }] })) }) };
      return { ok: true, status: 200, text: async () => fixture("GHSA-p6mc-m468-83gw.json") };
    };
    const deps = Object.fromEntries(Array.from({ length: 51 }, (_, i) => [`p${i}`, "1.0.0"]));
    expect(await createOsvAdapter({ fetch }).run(ctx(repo({ "package-lock.json": lock(deps) })))).toMatchObject({ status: "error", reason: "too_many_vulnerable_packages" });
  });

  it("follows OSV pagination tokens", async () => {
    let n = 0;
    const fetch: FetchLike = async (url, init) => {
      if (url.endsWith("querybatch")) {
        const q = JSON.parse(init.body!).queries[0];
        n++;
        return { ok: true, status: 200, text: async () => JSON.stringify({ results: [q.page_token ? { vulns: [{ id: "GHSA-r5fr-rjxr-66jc" }] } : { vulns: [{ id: "GHSA-p6mc-m468-83gw" }], next_page_token: "t1" }] }) };
      }
      return { ok: true, status: 200, text: async () => fixture(`${url.split("/").pop()}.json`) };
    };
    const r = await createOsvAdapter({ fetch }).run(ctx(repo({ "package-lock.json": lock({ lodash: "4.17.15" }) })));
    expect(n).toBe(2);
    expect(r.status === "ok" && (r.findings[0].evidence.advisories as unknown[]).length).toBe(2);
  });
});
