import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import type { Severity } from "../db/schema";
import type { CheckAdapter, CheckResult, FindingCandidate } from "./checks";
import { OsvError, SEV_RANK, osvClient, severityOf, type Ecosystem, type FetchLike, type OsvVuln, type Pkg } from "./deps";

/**
 * container.image (scanner step 3): known vulnerabilities in the base images a repository's Dockerfiles build FROM.
 *  - Reads Dockerfiles from the read-only repository snapshot and takes their FROM image references. Nothing in
 *    the repository or the image is executed: syft reads the image's layers straight from the registry
 *    ("registry:" source, no Docker daemon, no container started) and lists the installed packages.
 *  - Only images on well-known public registries are pulled, anonymously (empty HOME and DOCKER_CONFIG, so no
 *    stored credentials are ever used). A FROM pointing anywhere else (a private or internal host, an IP) is
 *    never contacted; it is reported as "not scanned" so nothing is silently skipped.
 *  - Packages are looked up in OSV.dev (OS packages by distro release, plus language packages found in the image).
 *    Only {ecosystem, name, version} leaves the box.
 *  - One finding per Dockerfile + image reference, so fixing the FROM line and re-testing resolves exactly it.
 *  - Fails closed: syft missing, a pull/scan failure, a timeout, unparseable output or any OSV failure is an error.
 */

export const PUBLIC_REGISTRIES = new Set(["docker.io", "registry-1.docker.io", "ghcr.io", "quay.io", "gcr.io", "mcr.microsoft.com", "public.ecr.aws", "registry.k8s.io", "cgr.dev"]);
const MAX_DOCKERFILES = 20;
const MAX_IMAGES = 10;
const MAX_PACKAGES = 20_000;
const MAX_DETAILS = 400;
const MAX_SYFT_OUTPUT = 128 * 1024 * 1024;
const SYFT_TIMEOUT_MS = 240_000;
const OSV_PARALLEL = 4;
const VENDORED = /(^|\/)(node_modules|vendor|\.git|bower_components|third_party)\//;
const clip = (s: string, n: number) => (s.length > n ? s.slice(0, n - 1) + "…" : s);
const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);

export const CONTAINER_REMEDIATION = {
  vulnerable_base_image: "Rebuild on a patched base image: move the FROM line to the newest patch release of a supported line (or a slimmer variant such as -slim, -alpine or distroless, which ship fewer packages), add an OS upgrade step if you must stay on this tag (apt-get upgrade -y / apk upgrade --no-cache), pin the result by digest (image@sha256:…), rebuild and redeploy. Then re-test.",
  base_image_unpinned: "Pin the base image to an explicit version tag, ideally with its digest (e.g. node:22.11-slim@sha256:…), so every build uses the image that was scanned and updates are deliberate.",
  image_not_scanned: "This base image was not scanned: it comes from a registry outside the public allowlist, or its name depends on a build argument without a default. Scan it in your own registry (most registries offer image scanning), or give the ARG a default that names a public image.",
} as const;

// ---------- Dockerfile parsing ----------

export function isDockerfile(p: string): boolean {
  if (VENDORED.test(p)) return false;
  const b = path.posix.basename(p);
  return /^(Dockerfile|Containerfile)(\.[A-Za-z0-9_.-]+)?$/.test(b) || /\.(Dockerfile|dockerfile|containerfile)$/.test(b);
}

export interface FromRef { line: number; raw: string; image: string | null; platform: string | null; why?: "unresolved_arg" | "invalid_reference" }

/** FROM references that name a real image: build stages and scratch are skipped, ARG defaults declared before the first FROM are applied. */
export function parseFroms(text: string): FromRef[] {
  const lines = text.split(/\r?\n/);
  const logical: { line: number; text: string }[] = [];
  let buf = "", start = 0;
  lines.forEach((l, i) => {
    if (!buf && /^\s*#/.test(l)) return;
    if (!buf) start = i + 1;
    if (/\\\s*$/.test(l)) { buf += l.replace(/\\\s*$/, " "); return; }
    logical.push({ line: start, text: buf + l });
    buf = "";
  });
  if (buf) logical.push({ line: start, text: buf });

  const args = new Map<string, string>();
  const stages = new Set<string>();
  const out: FromRef[] = [];
  let seenFrom = false;
  for (const { line, text: t } of logical) {
    const m = /^\s*(\w+)\s+(.*)$/.exec(t);
    if (!m) continue;
    const kw = m[1].toUpperCase();
    if (kw === "ARG" && !seenFrom) {
      const a = /^([A-Za-z_][A-Za-z0-9_]*)(?:=("?)([^"\s]*)\2)?\s*$/.exec(m[2].trim());
      if (a && a[3] !== undefined && a[3] !== "") args.set(a[1], a[3]);
      continue;
    }
    if (kw !== "FROM") continue;
    seenFrom = true;
    const parts = m[2].trim().split(/\s+/);
    let platform: string | null = null;
    while (parts[0]?.startsWith("--")) { const f = parts.shift()!; if (f.startsWith("--platform=")) platform = f.slice(11); }
    const raw = parts[0] ?? "";
    const isStage = stages.has(raw.toLowerCase());
    if (parts[1]?.toLowerCase() === "as" && parts[2]) stages.add(parts[2].toLowerCase());
    if (!raw || raw.toLowerCase() === "scratch" || isStage) continue;
    let unresolved = false;
    const sub = (s: string) => s.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)/g, (_, a, b) => { const v = args.get(a ?? b); if (v === undefined) unresolved = true; return v ?? ""; });
    const image = sub(raw);
    if (platform) platform = /\$/.test(platform) ? null : platform;
    if (unresolved) { out.push({ line, raw, image: null, platform, why: "unresolved_arg" }); continue; }
    out.push(normalizeRef(image) ? { line, raw, image: normalizeRef(image)!.ref, platform } : { line, raw, image: null, platform, why: "invalid_reference" });
  }
  return out;
}

export interface ImageRef { ref: string; registry: string; repository: string; tag: string | null; digest: string | null }

/** Canonical "registry/repo[:tag][@digest]" with Docker Hub defaults applied, or null when the reference is not well formed. */
export function normalizeRef(s: string): ImageRef | null {
  if (s.length > 255 || s.startsWith("-") || !/^[a-z0-9][a-z0-9._\-/:@]*$/i.test(s)) return null;
  const [nameTag, digest = null] = s.split("@", 2) as [string, string | undefined];
  if (digest !== null && !/^sha256:[a-f0-9]{64}$/.test(digest)) return null;
  const slash = nameTag.lastIndexOf("/");
  const colon = nameTag.lastIndexOf(":");
  const tag = colon > slash ? nameTag.slice(colon + 1) : null;
  const name = colon > slash ? nameTag.slice(0, colon) : nameTag;
  if (tag !== null && !/^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/.test(tag)) return null;
  const first = name.split("/")[0];
  const hasRegistry = name.includes("/") && (first.includes(".") || first.includes(":") || first === "localhost");
  const registry = hasRegistry ? first.toLowerCase() : "docker.io";
  let repository = hasRegistry ? name.slice(first.length + 1) : name;
  if (registry === "docker.io" && !repository.includes("/")) repository = `library/${repository}`;
  if (!/^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$/.test(repository)) return null;
  return { ref: `${registry}/${repository}${tag ? `:${tag}` : ""}${digest ? `@${digest}` : ""}`, registry, repository, tag, digest };
}

// ---------- syft output -> OSV packages ----------

/** OSV ecosystem name for the image's distro release, or null when OSV has no data for it. */
export function distroEcosystem(id: string, versionID: string): Ecosystem | null {
  const v = versionID.trim();
  if (id === "debian" && /^\d+/.test(v)) return `Debian:${v.match(/^\d+/)![0]}`;
  if (id === "alpine" && /^\d+\.\d+/.test(v)) return `Alpine:v${v.match(/^\d+\.\d+/)![0]}`;
  if (id === "ubuntu" && /^\d{2}\.\d{2}$/.test(v)) return `Ubuntu:${v}${/^\d[02468]\.04$/.test(v) ? ":LTS" : ""}`;
  return null;
}

const LANG: Record<string, Ecosystem> = { npm: "npm", python: "PyPI", "go-module": "Go", "rust-crate": "crates.io", gem: "RubyGems", "php-composer": "Packagist" };

export interface ImageInventory { distro: string | null; osEcosystem: Ecosystem | null; packages: Pkg[]; total: number; unsupported: number }

export class SyftOutputError extends Error {}

/** Reads `syft -o syft-json` output. OS packages are looked up by source package, the unit OSV's distro advisories use. */
export function parseSyftJson(text: string): ImageInventory {
  let j: unknown;
  try { j = JSON.parse(text); } catch { throw new SyftOutputError("not json"); }
  if (!isObj(j) || !Array.isArray(j.artifacts)) throw new SyftOutputError("no artifacts array");
  const d = isObj(j.distro) ? j.distro : {};
  const distroId = typeof d.id === "string" ? d.id : "";
  const distroVer = typeof d.versionID === "string" ? d.versionID : "";
  const osEco = distroId ? distroEcosystem(distroId, distroVer) : null;
  const seen = new Map<string, Pkg>();
  let unsupported = 0;
  for (const a of j.artifacts) {
    if (!isObj(a) || typeof a.name !== "string" || typeof a.version !== "string" || typeof a.type !== "string") { unsupported++; continue; }
    const m = isObj(a.metadata) ? a.metadata : {};
    let pkg: Pkg | null = null;
    if (a.type === "deb" && osEco && !osEco.startsWith("Alpine")) {
      const src = typeof m.source === "string" && m.source ? m.source : a.name;
      const ver = typeof m.sourceVersion === "string" && m.sourceVersion ? m.sourceVersion : a.version;
      pkg = { ecosystem: osEco, name: src, version: ver };
    } else if (a.type === "apk" && osEco?.startsWith("Alpine")) {
      pkg = { ecosystem: osEco, name: typeof m.originPackage === "string" && m.originPackage ? m.originPackage : a.name, version: a.version };
    } else if (LANG[a.type] && a.version && a.version !== "(devel)") {
      pkg = { ecosystem: LANG[a.type], name: a.name, version: a.version.replace(/^v(?=\d)/, LANG[a.type] === "Go" ? "v" : "") };
    }
    if (!pkg || !pkg.version) { unsupported++; continue; }
    seen.set(`${pkg.ecosystem}|${pkg.name}|${pkg.version}`, pkg);
  }
  return { distro: distroId ? `${distroId} ${distroVer}`.trim() : null, osEcosystem: osEco, packages: [...seen.values()], total: j.artifacts.length, unsupported };
}

// ---------- syft runner ----------

export class SyftError extends Error {
  constructor(readonly code: "syft_unavailable" | "image_pull_failed" | "syft_timeout" | "syft_output_too_large" | "syft_failed", readonly detail = "") { super(code); }
}
export type SyftRunner = (image: string, platform: string, timeoutMs: number) => Promise<string>;

export const syftPath = (env: Record<string, string | undefined> = process.env) => env.RUYA_SYFT_BIN && path.isAbsolute(env.RUYA_SYFT_BIN) ? env.RUYA_SYFT_BIN : path.join(process.cwd(), "bin", "syft");

/** Runs syft without a shell, with no credentials, update checks or config files, bounded in time and output. */
export const defaultSyft: SyftRunner = async (image, platform, timeoutMs) => {
  const bin = syftPath();
  if (!existsSync(bin)) throw new SyftError("syft_unavailable");
  const home = await mkdtemp(path.join(tmpdir(), "ruya-syft-"));
  try {
    return await new Promise<string>((resolve, reject) => {
      execFile(bin, ["scan", `registry:${image}`, "--platform", platform, "-o", "syft-json", "-q"], {
        timeout: timeoutMs, maxBuffer: MAX_SYFT_OUTPUT, killSignal: "SIGKILL",
        env: {
          PATH: "/usr/bin:/bin", HOME: home, DOCKER_CONFIG: home, XDG_CONFIG_HOME: home, XDG_CACHE_HOME: home, TMPDIR: home,
          SYFT_CHECK_FOR_APP_UPDATE: "false", SYFT_REGISTRY_AUTH_AUTHORITY: "", SYFT_PARALLELISM: "2", NODE_ENV: "production",
        },
      }, (err, stdout, stderr) => {
        if (!err) return resolve(String(stdout));
        const e = err as NodeJS.ErrnoException & { killed?: boolean; code?: string | number };
        if (e.code === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER") return reject(new SyftError("syft_output_too_large"));
        if (e.killed) return reject(new SyftError("syft_timeout"));
        if (e.code === "ENOENT" || e.code === "EACCES") return reject(new SyftError("syft_unavailable"));
        const msg = String(stderr).replace(/\s+/g, " ").slice(-200);
        reject(new SyftError(/manifest unknown|not found|unauthorized|denied|no such host|could not fetch image|failed to get image/i.test(msg) ? "image_pull_failed" : "syft_failed", msg));
      });
    });
  } finally {
    await rm(home, { recursive: true, force: true });
  }
};

// ---------- adapter ----------

interface Target { file: string; line: number; ref: ImageRef; platform: string }

export function createContainerImageAdapter(deps: { fetch?: FetchLike; syft?: SyftRunner; retryDelayMs?: number } = {}): CheckAdapter {
  return {
    id: "container.image@1", checkKey: "container.image", target: "repository",
    async run(ctx): Promise<CheckResult> {
      const repo = ctx.repo;
      if (!repo) return { status: "error", reason: "no_repository_snapshot", evidence: {} };
      const base = { commit: repo.commit };
      let files: string[];
      try { files = (await repo.list()).filter(isDockerfile).sort(); } catch { return { status: "error", reason: "repository_unreadable", evidence: base }; }
      if (files.length > MAX_DOCKERFILES) return { status: "error", reason: "too_many_dockerfiles", evidence: { ...base, dockerfiles: files.length } };

      const findings: FindingCandidate[] = [];
      const targets: Target[] = [];
      const notScanned: { file: string; line: number; reference: string; why: string }[] = [];
      for (const f of files) {
        let text: string;
        try { text = await repo.read(f); } catch { return { status: "error", reason: "dockerfile_unreadable", evidence: { ...base, dockerfile: f } }; }
        for (const fr of parseFroms(text)) {
          const ref = fr.image ? normalizeRef(fr.image) : null;
          const why = !ref ? fr.why ?? "invalid_reference" : !PUBLIC_REGISTRIES.has(ref.registry) ? "registry_not_allowlisted" : null;
          if (why || !ref) { notScanned.push({ file: f, line: fr.line, reference: clip(fr.raw, 120), why: why ?? "invalid_reference" }); continue; }
          if (!targets.some((t) => t.file === f && t.ref.ref === ref.ref)) targets.push({ file: f, line: fr.line, ref, platform: fr.platform && /^linux\/[a-z0-9]+(\/v\d)?$/.test(fr.platform) ? fr.platform : "linux/amd64" });
        }
      }
      for (const n of notScanned) {
        findings.push({
          issueKey: "image_not_scanned", title: clip(`Base image not scanned: ${n.reference}`, 200), severity: "info", confidence: "unknown",
          location: clip(`${n.file}#${n.reference}`, 300), evidence: { dockerfile: n.file, line: n.line, reference: n.reference, reason: n.why },
          remediation: CONTAINER_REMEDIATION.image_not_scanned,
        });
      }
      for (const t of targets.filter((x) => !x.ref.digest && (!x.ref.tag || x.ref.tag === "latest"))) {
        findings.push({
          issueKey: "base_image_unpinned", title: clip(`Base image ${t.ref.ref} is not pinned to a version`, 200), severity: "info", confidence: "confirmed",
          location: clip(`${t.file}#${t.ref.ref}`, 300), evidence: { dockerfile: t.file, line: t.line, image: t.ref.ref, tag: t.ref.tag ?? "latest (implicit)" },
          remediation: CONTAINER_REMEDIATION.base_image_unpinned,
        });
      }
      const images = [...new Set(targets.map((t) => `${t.ref.ref}|${t.platform}`))];
      if (images.length > MAX_IMAGES) return { status: "error", reason: "too_many_images", evidence: { ...base, images: images.length } };
      const summary = { ...base, dockerfiles: files, notScanned };
      if (!images.length) return { status: "ok", findings, evidence: { ...summary, imagesScanned: [] } };

      // 1. Inventory every image with syft. Any failure stops the check: a missing image must not read as "clean".
      const syft = deps.syft ?? defaultSyft;
      const inv = new Map<string, ImageInventory>();
      const perImage = Math.max(10_000, Math.min(SYFT_TIMEOUT_MS, Math.floor((ctx.timeoutMs * 0.7) / images.length)));
      for (const key of images) {
        const [image, platform] = key.split("|");
        try {
          inv.set(key, parseSyftJson(await syft(image, platform, perImage)));
        } catch (e) {
          if (e instanceof SyftError) return { status: "error", reason: e.code, evidence: { ...summary, image, ...(e.detail ? { detail: clip(e.detail, 200) } : {}) } };
          if (e instanceof SyftOutputError) return { status: "error", reason: "syft_output_unparseable", evidence: { ...summary, image, detail: e.message } };
          throw e;
        }
      }
      const all = [...new Map([...inv.values()].flatMap((i) => i.packages).map((p) => [`${p.ecosystem}|${p.name}|${p.version}`, p])).values()];
      if (all.length > MAX_PACKAGES) return { status: "error", reason: "too_many_packages", evidence: { ...summary, packages: all.length } };
      const imageEvidence = images.map((k) => { const i = inv.get(k)!; return { image: k.split("|")[0], platform: k.split("|")[1], distro: i.distro, osvEcosystem: i.osEcosystem, packages: i.total, checked: i.packages.length, unsupported: i.unsupported }; });

      // 2. Look every package up in OSV.
      const osv = osvClient(deps.fetch ?? (globalThis.fetch as unknown as FetchLike), undefined, deps.retryDelayMs);
      try {
        const idsByKey = new Map<string, string[]>();
        if (all.length) (await osv.queryBatch(all)).forEach((ids, i) => idsByKey.set(`${all[i].ecosystem}|${all[i].name}|${all[i].version}`, ids));
        const allIds = [...new Set([...idsByKey.values()].flat())].sort();
        // Severity needs advisory details; past MAX_DETAILS the rest are counted, and the finding says its severity is a lower bound.
        const detailIds = allIds.slice(0, MAX_DETAILS);
        const details = new Map<string, OsvVuln>();
        for (let i = 0; i < detailIds.length; i += OSV_PARALLEL) {
          for (const v of await Promise.all(detailIds.slice(i, i + OSV_PARALLEL).map((id) => osv.vuln(id)))) details.set(v.id, v);
        }

        for (const t of targets) {
          const i = inv.get(`${t.ref.ref}|${t.platform}`)!;
          const vulnerable = i.packages.map((p) => ({ p, ids: idsByKey.get(`${p.ecosystem}|${p.name}|${p.version}`) ?? [] })).filter((x) => x.ids.length);
          if (!vulnerable.length) continue;
          const ids = [...new Set(vulnerable.flatMap((x) => x.ids))];
          const sevOf = (id: string): Severity | null => { const v = details.get(id); return v ? severityOf(v) : null; };
          const counts: Record<Severity | "unknown", number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 };
          for (const id of ids) counts[sevOf(id) ?? "unknown"]++;
          const worst = (["critical", "high", "medium", "low", "info"] as Severity[]).find((s) => counts[s] > 0) ?? null;
          const pkgRank = (x: { ids: string[] }) => Math.max(...x.ids.map((id) => SEV_RANK[sevOf(id) ?? "info"]));
          const top = vulnerable.sort((a, b) => pkgRank(b) - pkgRank(a) || b.ids.length - a.ids.length || a.p.name.localeCompare(b.p.name)).slice(0, 15);
          const cves = [...new Set(ids.flatMap((id) => [id, ...(details.get(id)?.aliases ?? [])])
            // Distro advisories embed the CVE in their own id (ALPINE-CVE-2022-37434) and often carry no aliases.
            .map((a) => /(?:^|-)(CVE-\d{4}-\d+)$/.exec(a)?.[1]).filter((a): a is string => !!a))].sort();
          findings.push({
            issueKey: "vulnerable_base_image",
            title: clip(`${t.ref.ref}: ${vulnerable.length} vulnerable package${vulnerable.length === 1 ? "" : "s"}, ${ids.length} known advisor${ids.length === 1 ? "y" : "ies"}${counts.critical + counts.high ? ` (${counts.critical} critical, ${counts.high} high)` : ""}`, 200),
            severity: worst ?? "medium",
            ...(counts.unknown || detailIds.length < allIds.length ? { confidence: "likely" as const } : {}),
            location: clip(`${t.file}#${t.ref.ref}`, 300),
            evidence: {
              dockerfile: t.file, line: t.line, image: t.ref.ref, platform: t.platform, distro: i.distro, osvEcosystem: i.osEcosystem,
              packagesInImage: i.total, packagesChecked: i.packages.length, vulnerablePackages: vulnerable.length, advisories: ids.length, bySeverity: counts,
              cves: cves.slice(0, 30), ...(cves.length > 30 ? { cvesOmitted: cves.length - 30 } : {}),
              topPackages: top.map((x) => ({ ecosystem: x.p.ecosystem, package: x.p.name, version: x.p.version, advisories: x.ids.slice(0, 5), worst: x.ids.map(sevOf).filter(Boolean).sort((a, b) => SEV_RANK[b!] - SEV_RANK[a!])[0] ?? null })),
              ...(detailIds.length < allIds.length ? { severityNote: `severity read from ${detailIds.length} of ${allIds.length} advisories; it is a lower bound` } : {}),
              source: "osv.dev",
            },
            remediation: CONTAINER_REMEDIATION.vulnerable_base_image,
          });
        }
        if (findings.length > 50) return { status: "error", reason: "too_many_findings", evidence: { ...summary, findings: findings.length } };
        findings.sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity] || a.location.localeCompare(b.location));
        return { status: "ok", findings, evidence: { ...summary, imagesScanned: imageEvidence, packagesChecked: all.length, advisories: allIds.length, source: "osv.dev" } };
      } catch (e) {
        return { status: "error", reason: e instanceof OsvError ? e.message : "osv_failed", evidence: { ...summary, imagesScanned: imageEvidence, ...(e instanceof OsvError && e.detail ? { detail: e.detail } : {}) } };
      }
    },
  };
}
