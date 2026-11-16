import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { normalizeResult, type CheckContext } from "@/server/assessments/checks";
import {
  SyftError, createContainerImageAdapter, distroEcosystem, isDockerfile, normalizeRef, parseFroms, parseSyftJson, type SyftRunner,
} from "@/server/assessments/container";
import type { FetchLike } from "@/server/assessments/deps";
import type { RepoSnapshot } from "@/server/remediation/repo";

const FIX = join(__dirname, "../fixtures");
const syftJson = readFileSync(join(FIX, "syft/node-old-bookworm.json"), "utf8");
const osvFix = (n: string) => readFileSync(join(FIX, "osv", n), "utf8");

function repo(files: Record<string, string>, commit = "c".repeat(40)): RepoSnapshot {
  return { externalId: "demo", commit, list: async () => Object.keys(files), read: async (p) => { if (!(p in files)) throw new Error("not_found"); return files[p]; } };
}
const ctx = (r: RepoSnapshot | undefined) => ({ repo: r, timeoutMs: 600_000 }) as unknown as CheckContext;

/** OSV stand-in: openssl (Debian:12) has a synthetic critical advisory, lodash answers from the recorded fixtures. */
function fakeOsv(opts: { fail?: boolean } = {}) {
  const calls: string[] = [];
  const opensslVuln = { id: "DEBIAN-CVE-2024-0001", aliases: [], severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }], affected: [] };
  const fetch: FetchLike = async (url, init) => {
    calls.push(`${init.method} ${url}`);
    if (opts.fail) return { ok: false, status: 503, text: async () => "" };
    const u = new URL(url);
    if (u.pathname === "/v1/querybatch") {
      const lodash = JSON.parse(osvFix("querybatch-lodash.json")).results[0];
      const qs = JSON.parse(init.body!).queries as { package: { ecosystem: string; name: string } }[];
      return { ok: true, status: 200, text: async () => JSON.stringify({ results: qs.map((q) =>
        q.package.name === "openssl" && q.package.ecosystem === "Debian:12" ? { vulns: [{ id: opensslVuln.id }] }
          : q.package.name === "lodash" ? lodash : {}) }) };
    }
    const id = decodeURIComponent(u.pathname.split("/").pop()!);
    return { ok: true, status: 200, text: async () => (id === opensslVuln.id ? JSON.stringify(opensslVuln) : osvFix(`${id}.json`)) };
  };
  return { fetch, calls };
}

function fakeSyft(out: string | Error = syftJson) {
  const calls: string[] = [];
  const run: SyftRunner = async (image, platform) => { calls.push(`${image} ${platform}`); if (out instanceof Error) throw out; return out; };
  return { run, calls };
}

describe("Dockerfile parsing", () => {
  it("recognises Dockerfile names and skips vendored paths", () => {
    expect(["Dockerfile", "docker/Dockerfile.prod", "Containerfile", "api.Dockerfile"].every(isDockerfile)).toBe(true);
    expect(["node_modules/x/Dockerfile", "Dockerfile.md.txt/x", "README.md", "dockerfile-notes.txt"].some(isDockerfile)).toBe(false);
  });

  it("takes real images, applies ARG defaults, skips stages and scratch", () => {
    const froms = parseFroms([
      "# syntax=docker/dockerfile:1",
      "ARG NODE=20.10",
      "ARG REG",
      "FROM --platform=linux/arm64 node:${NODE}-bookworm AS build",
      "RUN npm ci",
      "FROM build AS test",
      "FROM scratch",
      "FROM \\",
      "  gcr.io/distroless/nodejs20-debian12",
      "FROM $REG/app:1",
    ].join("\n"));
    expect(froms.map((f) => [f.line, f.image, f.platform, f.why ?? null])).toEqual([
      [4, "docker.io/library/node:20.10-bookworm", "linux/arm64", null],
      [8, "gcr.io/distroless/nodejs20-debian12", null, null],
      [10, null, null, "unresolved_arg"],
    ]);
  });

  it("normalises references and rejects malformed or option-like ones", () => {
    expect(normalizeRef("alpine")?.ref).toBe("docker.io/library/alpine");
    expect(normalizeRef("bitnami/redis:7.2")?.ref).toBe("docker.io/bitnami/redis:7.2");
    expect(normalizeRef(`ghcr.io/org/app@sha256:${"a".repeat(64)}`)?.digest).toMatch(/^sha256:/);
    expect(normalizeRef("localhost:5000/app:1")?.registry).toBe("localhost:5000");
    for (const bad of ["-oops", "UPPER/Case", "a b", "x@sha256:short", "node:$(id)"]) expect(normalizeRef(bad)).toBeNull();
  });

  it("maps distro releases to OSV ecosystems", () => {
    expect(distroEcosystem("debian", "12")).toBe("Debian:12");
    expect(distroEcosystem("alpine", "3.19.1")).toBe("Alpine:v3.19");
    expect(distroEcosystem("ubuntu", "22.04")).toBe("Ubuntu:22.04:LTS");
    expect(distroEcosystem("ubuntu", "23.10")).toBe("Ubuntu:23.10");
    expect(distroEcosystem("centos", "7")).toBeNull();
  });

  it("reads syft output by source package and counts what it cannot check", () => {
    const inv = parseSyftJson(syftJson);
    expect(inv.osEcosystem).toBe("Debian:12");
    expect(inv.packages.map((p) => `${p.ecosystem} ${p.name} ${p.version}`).sort()).toEqual([
      "Debian:12 bash 5.2.15-2", "Debian:12 openssl 3.0.11-1~deb12u1", "npm lodash 4.17.15",
    ]);
    expect(inv.unsupported).toBe(2);
    expect(() => parseSyftJson("{}")).toThrow();
  });
});

describe("container.image adapter", () => {
  const DOCKERFILE = "FROM node:20.10-bookworm\nRUN npm ci\n";

  it("reports a vulnerable base image with stable location, severity and evidence", async () => {
    const osv = fakeOsv(), syft = fakeSyft();
    const r = normalizeResult(await createContainerImageAdapter({ fetch: osv.fetch, syft: syft.run, retryDelayMs: 0 }).run(ctx(repo({ Dockerfile: DOCKERFILE }))));
    expect(r.status).toBe("ok");
    if (r.status !== "ok") return;
    expect(syft.calls).toEqual(["docker.io/library/node:20.10-bookworm linux/amd64"]);
    expect(osv.calls.every((c) => c.includes("https://api.osv.dev/"))).toBe(true);
    expect(r.findings).toHaveLength(1);
    const f = r.findings[0];
    expect(f.issueKey).toBe("vulnerable_base_image");
    expect(f.location).toBe("Dockerfile#docker.io/library/node:20.10-bookworm");
    expect(f.severity).toBe("critical");
    expect(f.evidence).toMatchObject({ line: 1, distro: "debian 12", vulnerablePackages: 2 });
    expect((f.evidence as { cves: string[] }).cves).toContain("CVE-2024-0001");
  });

  it("flags unpinned images and never contacts non-allowlisted registries", async () => {
    const syft = fakeSyft();
    const r = normalizeResult(await createContainerImageAdapter({ fetch: fakeOsv().fetch, syft: syft.run, retryDelayMs: 0 })
      .run(ctx(repo({ Dockerfile: "FROM nginx\nFROM 10.0.0.5:5000/internal/app:1\nFROM registry.corp.example/app:2\n" }))));
    expect(r.status).toBe("ok");
    if (r.status !== "ok") return;
    expect(syft.calls).toEqual(["docker.io/library/nginx linux/amd64"]);
    const keys = r.findings.map((f) => f.issueKey).sort();
    expect(keys).toEqual(["base_image_unpinned", "image_not_scanned", "image_not_scanned", "vulnerable_base_image"]);
  });

  it("is ok with no findings when the repository has no Dockerfile", async () => {
    const syft = fakeSyft();
    const r = await createContainerImageAdapter({ syft: syft.run }).run(ctx(repo({ "package.json": "{}" })));
    expect(r).toMatchObject({ status: "ok", findings: [] });
    expect(syft.calls).toEqual([]);
  });

  it.each([
    ["syft missing", new SyftError("syft_unavailable"), "syft_unavailable"],
    ["image pull failure", new SyftError("image_pull_failed", "manifest unknown"), "image_pull_failed"],
    ["timeout", new SyftError("syft_timeout"), "syft_timeout"],
  ])("fails closed on %s", async (_, err, reason) => {
    const r = await createContainerImageAdapter({ fetch: fakeOsv().fetch, syft: fakeSyft(err).run }).run(ctx(repo({ Dockerfile: DOCKERFILE })));
    expect(r).toMatchObject({ status: "error", reason });
  });

  it("fails closed on unparseable syft output and on OSV failure", async () => {
    expect(await createContainerImageAdapter({ fetch: fakeOsv().fetch, syft: fakeSyft("not json").run }).run(ctx(repo({ Dockerfile: DOCKERFILE }))))
      .toMatchObject({ status: "error", reason: "syft_output_unparseable" });
    expect(await createContainerImageAdapter({ fetch: fakeOsv({ fail: true }).fetch, syft: fakeSyft().run, retryDelayMs: 0 }).run(ctx(repo({ Dockerfile: DOCKERFILE }))))
      .toMatchObject({ status: "error", reason: "osv_http_503" });
  });

  it("errors without a repository snapshot", async () => {
    expect(await createContainerImageAdapter().run(ctx(undefined))).toMatchObject({ status: "error", reason: "no_repository_snapshot" });
  });
});
