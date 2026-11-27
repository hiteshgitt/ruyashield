import { createHash } from "node:crypto";
import type { Severity } from "../db/schema";
import type { CheckAdapter, CheckResult, FindingCandidate } from "./checks";

/**
 * deps.osv (scanner M1): dependency vulnerabilities from lockfiles, looked up in OSV.dev.
 *  - Reads lockfiles from a read-only repository snapshot; nothing in the repository is executed.
 *  - The only egress is HTTPS to api.osv.dev, and only {ecosystem, name, version} is sent. No code leaves the box.
 *  - Fails closed: an unreadable/unparseable lockfile or any OSV failure is an error, never "no findings".
 *  - One finding per vulnerable package version, so the 50-finding cap holds for realistic repos; past it the
 *    check reports an error rather than silently dropping (and later auto-resolving) findings.
 */

export type Ecosystem = "npm" | "PyPI" | "Go" | "crates.io" | "Packagist" | "RubyGems"
  /** OS package ecosystems, used by container.image (OSV names them per distro release). */
  | `Debian:${string}` | `Alpine:v${string}` | `Ubuntu:${string}`;
export interface Pkg { ecosystem: Ecosystem; name: string; version: string }
export interface Lockfile { path: string; sha256: string; packages: Pkg[]; unpinned: number }

export class LockfileError extends Error {
  constructor(public readonly file: string, msg: string) { super(`${file}: ${msg}`); }
}

const MAX_LOCKFILES = 50;
const MAX_PACKAGES = 20_000;
const MAX_ADVISORIES = 400;
const MAX_FINDINGS = 50;
const OSV_BATCH = 1000;
const OSV_HOST = "api.osv.dev";
const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
const VENDORED = /(^|\/)(node_modules|vendor|\.git|bower_components)\//;

// ---------- lockfile parsers ----------

type Parser = (text: string, file: string) => { packages: Pkg[]; unpinned?: number };
const LOCKFILES: [RegExp, Parser][] = [
  [/(^|\/)package-lock\.json$/, parsePackageLock],
  [/(^|\/)npm-shrinkwrap\.json$/, parsePackageLock],
  [/(^|\/)yarn\.lock$/, parseYarnLock],
  [/(^|\/)pnpm-lock\.yaml$/, parsePnpmLock],
  [/(^|\/)requirements[^/]*\.txt$/, parseRequirements],
  [/(^|\/)poetry\.lock$/, (t, f) => ({ packages: parseTomlPackages(t, f, "PyPI") })],
  [/(^|\/)Cargo\.lock$/, (t, f) => ({ packages: parseTomlPackages(t, f, "crates.io") })],
  [/(^|\/)go\.sum$/, parseGoSum],
  [/(^|\/)composer\.lock$/, parseComposerLock],
  [/(^|\/)Gemfile\.lock$/, parseGemfileLock],
];

export function lockfileParser(path: string): Parser | null {
  if (VENDORED.test(path)) return null;
  return LOCKFILES.find(([re]) => re.test(path))?.[1] ?? null;
}

const json = (text: string, file: string) => {
  try { return JSON.parse(text) as unknown; } catch { throw new LockfileError(file, "not valid JSON"); }
};
const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
/** A concrete version (not a range, URL, path or git ref). */
const concrete = (v: unknown): v is string => typeof v === "string" && /^v?\d+(\.\d+)*([-+.][0-9A-Za-z.+-]*)?$/.test(v);

export function parsePackageLock(text: string, file: string) {
  const j = json(text, file);
  if (!isObj(j) || typeof j.lockfileVersion !== "number") throw new LockfileError(file, "missing lockfileVersion");
  const out: Pkg[] = [];
  if (isObj(j.packages)) {
    for (const [key, v] of Object.entries(j.packages)) {
      if (!key || !isObj(v) || v.link) continue; // "" is the root project; links point at workspace folders
      const i = key.lastIndexOf("node_modules/");
      if (i < 0) continue; // workspace package source folder
      const name = typeof v.name === "string" ? v.name : key.slice(i + "node_modules/".length);
      if (concrete(v.version)) out.push({ ecosystem: "npm", name, version: v.version });
    }
  } else if (isObj(j.dependencies)) {
    const walk = (deps: Record<string, unknown>, depth: number) => {
      if (depth > 64) throw new LockfileError(file, "dependency tree too deep");
      for (const [name, v] of Object.entries(deps)) {
        if (!isObj(v)) continue;
        if (concrete(v.version)) out.push({ ecosystem: "npm", name, version: v.version });
        if (isObj(v.dependencies)) walk(v.dependencies, depth + 1);
      }
    };
    walk(j.dependencies, 0);
  } else if (j.lockfileVersion > 0) {
    // A lockfile with no dependencies at all is valid (empty project).
  }
  return { packages: out };
}

/** yarn.lock v1 (classic) and v2+ (berry). */
export function parseYarnLock(text: string, file: string) {
  const out: Pkg[] = [];
  let names: string[] = [];
  for (const raw of text.split(/\r?\n/)) {
    if (!raw.trim() || raw.trimStart().startsWith("#")) continue;
    if (!/^\s/.test(raw)) {
      // header: "a@^1.0.0", a@~1.1.0:   or   "@scope/b@npm:^2.0.0":
      names = raw.replace(/:$/, "").split(/,\s*/).map((s) => s.trim().replace(/^"|"$/g, "")).filter((s) => s && s !== "__metadata")
        .map((spec) => { const at = spec.indexOf("@", spec.startsWith("@") ? 1 : 0); return at > 0 ? spec.slice(0, at) : ""; })
        .filter(Boolean);
      continue;
    }
    const m = /^ {2}version:?\s+"?([^"\s]+)"?\s*$/.exec(raw);
    if (m && names.length) {
      if (concrete(m[1])) for (const name of new Set(names)) out.push({ ecosystem: "npm", name, version: m[1] });
      names = [];
    }
  }
  if (!out.length && /\S/.test(text) && !/^# yarn lockfile|__metadata/m.test(text)) throw new LockfileError(file, "unrecognised yarn.lock format");
  return { packages: out };
}

/** pnpm-lock.yaml v5–v9: package keys under `packages:` (/name/1.2.3, /name@1.2.3, name@1.2.3, with optional peer suffixes). */
export function parsePnpmLock(text: string, file: string) {
  if (!/^lockfileVersion:/m.test(text)) throw new LockfileError(file, "missing lockfileVersion");
  const out: Pkg[] = [];
  let inPackages = false;
  for (const raw of text.split(/\r?\n/)) {
    if (/^\S/.test(raw)) { inPackages = /^packages:\s*$/.test(raw); continue; }
    if (!inPackages) continue;
    const m = /^ {2}['"]?\/?(@?[^\s'"]+?)['"]?:\s*$/.exec(raw);
    if (!m) continue;
    // Keys: "name@1.0.0(peer@x)" (v6+), "/name@1.0.0_peer@x" (v5.x), "/name/1.0.0_peer@x" (v5 and older). Peer suffixes are dropped.
    const key = m[1].replace(/\(.*$/, "");
    let name: string, version: string;
    const slash = /^((?:@[^/@]+\/)?[^/@]+)\/(\d[^/@_]*)(?:_.*)?$/.exec(key);
    if (slash) { name = slash[1]; version = slash[2]; } else {
      const at = key.indexOf("@", 1);
      if (at < 0) continue;
      name = key.slice(0, at); version = key.slice(at + 1).replace(/_.*$/, "");
    }
    if (concrete(version)) out.push({ ecosystem: "npm", name, version });
  }
  return { packages: out };
}

/** requirements*.txt: only exact pins (==) can be checked; everything else is counted as unpinned. */
export function parseRequirements(text: string) {
  const out: Pkg[] = [];
  let unpinned = 0;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/\s+#.*$/, "").replace(/^#.*$/, "").split(";")[0].trim();
    if (!line || line.startsWith("-") || /^[a-z]+\+?[a-z]*:\/\//i.test(line)) continue; // options, -r includes, URLs
    const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([^\s,]+)$/.exec(line);
    if (m && concrete(m[2])) out.push({ ecosystem: "PyPI", name: m[1].toLowerCase().replace(/[-_.]+/g, "-"), version: m[2] });
    else if (/^[A-Za-z0-9]/.test(line)) unpinned++;
  }
  return { packages: out, unpinned };
}

/** poetry.lock / Cargo.lock: [[package]] tables with name/version (and, for Cargo, a registry source). */
export function parseTomlPackages(text: string, file: string, ecosystem: Ecosystem): Pkg[] {
  if (!/^\[\[package\]\]/m.test(text)) {
    if (/\S/.test(text.replace(/^#.*$/gm, "").replace(/^version\s*=.*$/m, ""))) throw new LockfileError(file, "no [[package]] tables");
    return [];
  }
  const out: Pkg[] = [];
  for (const block of text.split(/^\[\[package\]\]\s*$/m).slice(1)) {
    const body = block.split(/^\[/m)[0];
    const get = (k: string) => new RegExp(`^${k}\\s*=\\s*"([^"]*)"`, "m").exec(body)?.[1];
    const name = get("name"), version = get("version"), source = get("source");
    if (!name || !version) throw new LockfileError(file, "package without name/version");
    if (ecosystem === "crates.io" && !source?.startsWith("registry+")) continue; // path/git crates are not on crates.io
    if (concrete(version)) out.push({ ecosystem, name, version });
  }
  return out;
}

export function parseGoSum(text: string, file: string) {
  const seen = new Map<string, Pkg>();
  for (const raw of text.split(/\r?\n/)) {
    if (!raw.trim()) continue;
    const m = /^(\S+)\s+(v\S+?)(\/go\.mod)?\s+h1:\S+$/.exec(raw.trim());
    if (!m) throw new LockfileError(file, "unrecognised go.sum line");
    const version = m[2].replace(/^v/, "").replace(/\+incompatible$/, "");
    seen.set(`${m[1]}@${version}`, { ecosystem: "Go", name: m[1], version });
  }
  return { packages: [...seen.values()] };
}

export function parseComposerLock(text: string, file: string) {
  const j = json(text, file);
  if (!isObj(j) || !Array.isArray(j.packages)) throw new LockfileError(file, "missing packages");
  const out: Pkg[] = [];
  for (const p of [...j.packages, ...(Array.isArray(j["packages-dev"]) ? j["packages-dev"] : [])]) {
    if (!isObj(p) || typeof p.name !== "string" || typeof p.version !== "string") continue;
    const version = p.version.replace(/^v/, "");
    if (concrete(version)) out.push({ ecosystem: "Packagist", name: p.name, version });
  }
  return { packages: out };
}

export function parseGemfileLock(text: string, file: string) {
  if (!/^GEM$/m.test(text) && /\S/.test(text)) throw new LockfileError(file, "missing GEM section");
  const out: Pkg[] = [];
  let inSpecs = false;
  for (const raw of text.split(/\r?\n/)) {
    if (/^\S/.test(raw)) { inSpecs = false; continue; }
    if (/^ {2}specs:\s*$/.test(raw)) { inSpecs = true; continue; }
    if (!inSpecs) continue;
    const m = /^ {4}([A-Za-z0-9._-]+) \(([^)]+)\)$/.exec(raw);
    if (m) { const version = m[2].replace(/-(x86|arm|aarch|universal|java|x64|mingw|mswin|darwin|linux).*$/, ""); if (concrete(version)) out.push({ ecosystem: "RubyGems", name: m[1], version }); }
  }
  return { packages: out };
}

// ---------- severity ----------

export const SEV_RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

/** CVSS v3.x base score from a vector string (FIRST spec §7). Returns null for anything it cannot score. */
export function cvss3Score(vector: string): number | null {
  const m = Object.fromEntries(vector.split("/").slice(1).map((p) => p.split(":")));
  if (!/^CVSS:3\.[01]$/.test(vector.split("/")[0])) return null;
  const W: Record<string, Record<string, number>> = {
    AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }, AC: { L: 0.77, H: 0.44 }, UI: { N: 0.85, R: 0.62 },
    C: { H: 0.56, L: 0.22, N: 0 }, I: { H: 0.56, L: 0.22, N: 0 }, A: { H: 0.56, L: 0.22, N: 0 },
  };
  const S = m.S;
  const PR = S === "C" ? { N: 0.85, L: 0.68, H: 0.5 }[m.PR as "N"] : { N: 0.85, L: 0.62, H: 0.27 }[m.PR as "N"];
  const v = (k: string) => W[k][m[k]];
  if ((S !== "U" && S !== "C") || [v("AV"), v("AC"), v("UI"), v("C"), v("I"), v("A"), PR].some((x) => x === undefined)) return null;
  const iss = 1 - (1 - v("C")) * (1 - v("I")) * (1 - v("A"));
  const impact = S === "U" ? 6.42 * iss : 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15;
  if (impact <= 0) return 0;
  const expl = 8.22 * v("AV") * v("AC") * PR! * v("UI");
  const roundUp = (x: number) => { const i = Math.round(x * 100000); return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10; };
  return roundUp(Math.min(S === "U" ? impact + expl : 1.08 * (impact + expl), 10));
}

const fromScore = (s: number): Severity => (s >= 9 ? "critical" : s >= 7 ? "high" : s >= 4 ? "medium" : s > 0 ? "low" : "info");
const LABEL: Record<string, Severity> = { CRITICAL: "critical", HIGH: "high", MODERATE: "medium", MEDIUM: "medium", LOW: "low" };

export interface OsvVuln {
  id: string; summary?: string; aliases?: string[];
  severity?: { type: string; score: string }[];
  database_specific?: { severity?: string };
  affected?: { package?: { ecosystem?: string; name?: string }; ranges?: { type?: string; events?: Record<string, string>[] }[]; versions?: string[]; database_specific?: { severity?: string }; ecosystem_specific?: { severity?: string } }[];
}

/** The advisory's CVSS: the highest-scoring v3.x vector, else a v4.0 vector (not scored here). */
export function cvssOf(v: OsvVuln): { score: number | null; vector: string } | null {
  let best: { score: number; vector: string } | null = null;
  for (const s of v.severity ?? []) {
    if (s.type !== "CVSS_V3") continue;
    const n = cvss3Score(s.score);
    if (n !== null && (!best || n > best.score)) best = { score: n, vector: s.score };
  }
  if (best) return best;
  const v4 = (v.severity ?? []).find((s) => s.type === "CVSS_V4" && /^CVSS:4\.0\//.test(s.score));
  return v4 ? { score: null, vector: v4.score } : null;
}

/** Severity from the CVSS v3 vector, else the advisory's own label. null = OSV gave no usable severity. */
export function severityOf(v: OsvVuln): Severity | null {
  for (const s of v.severity ?? []) {
    if (s.type === "CVSS_V3") { const n = cvss3Score(s.score); if (n !== null) return fromScore(n); }
  }
  const label = (v.database_specific?.severity ?? v.affected?.find((a) => a.database_specific?.severity)?.database_specific?.severity ?? v.affected?.find((a) => a.ecosystem_specific?.severity)?.ecosystem_specific?.severity ?? "").toUpperCase();
  return LABEL[label] ?? null;
}

/** Loose version order good enough to pick a "fixed in" version: numeric segments compare as numbers, pre-releases sort first. */
export function compareVersions(a: string, b: string): number {
  const split = (v: string) => { const [core, pre] = v.replace(/^v/, "").split(/[-+]/, 2); return { core: core.split(".").map((x) => parseInt(x, 10) || 0), pre }; };
  const x = split(a), y = split(b);
  for (let i = 0; i < Math.max(x.core.length, y.core.length); i++) { const d = (x.core[i] ?? 0) - (y.core[i] ?? 0); if (d) return d; }
  if (x.pre && !y.pre) return -1;
  if (!x.pre && y.pre) return 1;
  return (x.pre ?? "").localeCompare(y.pre ?? "");
}

/** The lowest published fix above the installed version for this package, or null when no fix is published. */
export function fixedVersion(v: OsvVuln, p: Pkg): string | null {
  const fixes = (v.affected ?? []).filter((a) => a.package?.name === p.name && a.package?.ecosystem === p.ecosystem)
    .flatMap((a) => (a.ranges ?? []).flatMap((r) => (r.events ?? []).map((e) => e.fixed).filter((f): f is string => !!f)))
    .filter((f) => compareVersions(f, p.version) > 0).sort(compareVersions);
  return fixes[0] ?? null;
}

// ---------- OSV client ----------

export type FetchLike = (url: string, init: { method: string; headers?: Record<string, string>; body?: string; redirect: "error"; signal?: AbortSignal }) => Promise<{ ok: boolean; status: number; text(): Promise<string> }>;

export class OsvError extends Error {
  constructor(message: string, readonly detail?: string) { super(message); }
}
/** Short, secret-free description of a network failure (error name plus the low-level code). */
const netDetail = (e: unknown) => {
  const err = e as { name?: string; cause?: { code?: string; name?: string } };
  return [err?.name, err?.cause?.code ?? err?.cause?.name].filter(Boolean).join(":").slice(0, 80) || "unknown";
};

/** Network attempts per OSV request. Read-only lookups, so retrying a failed connection is safe. */
const OSV_ATTEMPTS = 3;
/** Advisory-detail requests in flight at once. Bursts of fresh connections trip Node's 250 ms dual-stack connect window. */
const OSV_PARALLEL = 4;

/** Only https://api.osv.dev, no redirects, bounded body. Connection failures are retried; HTTP errors are not. */
export function osvClient(fetchImpl: FetchLike, timeoutMs = 15_000, retryDelayMs = 400) {
  const call = async (path: string, body?: unknown): Promise<unknown> => {
    const url = new URL(path, `https://${OSV_HOST}`);
    if (url.protocol !== "https:" || url.host !== OSV_HOST) throw new OsvError("egress_not_allowed");
    let res;
    for (let attempt = 1; ; attempt++) {
      try {
        res = await fetchImpl(url.toString(), {
          method: body === undefined ? "GET" : "POST", redirect: "error", signal: AbortSignal.timeout(timeoutMs),
          headers: { "content-type": "application/json", "user-agent": "RuyaShield-deps/1" }, body: body === undefined ? undefined : JSON.stringify(body),
        });
        break;
      } catch (e) {
        if (attempt >= OSV_ATTEMPTS) throw new OsvError("osv_unreachable", netDetail(e));
        await new Promise((r) => setTimeout(r, retryDelayMs * attempt));
      }
    }
    if (!res.ok) throw new OsvError(`osv_http_${res.status}`);
    const text = await res.text();
    if (text.length > MAX_RESPONSE_BYTES) throw new OsvError("osv_response_too_large");
    try { return JSON.parse(text); } catch { throw new OsvError("osv_malformed_response"); }
  };
  return {
    /** Advisory IDs per package, in input order. Follows per-query pagination. */
    async queryBatch(pkgs: Pkg[]): Promise<string[][]> {
      const out: string[][] = pkgs.map(() => []);
      let pending = pkgs.map((p, i) => ({ i, token: undefined as string | undefined }));
      for (let round = 0; pending.length; round++) {
        if (round > 10) throw new OsvError("osv_pagination_runaway");
        const next: typeof pending = [];
        for (let s = 0; s < pending.length; s += OSV_BATCH) {
          const chunk = pending.slice(s, s + OSV_BATCH);
          const r = await call("/v1/querybatch", { queries: chunk.map(({ i, token }) => ({ package: { ecosystem: pkgs[i].ecosystem, name: pkgs[i].name }, version: pkgs[i].version, ...(token ? { page_token: token } : {}) })) });
          const results = isObj(r) && Array.isArray(r.results) ? r.results : null;
          if (!results || results.length !== chunk.length) throw new OsvError("osv_malformed_response");
          results.forEach((res: unknown, k) => {
            if (!isObj(res)) throw new OsvError("osv_malformed_response");
            for (const v of Array.isArray(res.vulns) ? res.vulns : []) if (isObj(v) && typeof v.id === "string") out[chunk[k].i].push(v.id);
            if (typeof res.next_page_token === "string" && res.next_page_token) next.push({ i: chunk[k].i, token: res.next_page_token });
          });
        }
        pending = next;
      }
      return out;
    },
    async vuln(id: string): Promise<OsvVuln> {
      if (!/^[A-Za-z0-9._:-]{1,100}$/.test(id)) throw new OsvError("osv_malformed_response");
      const v = await call(`/v1/vulns/${encodeURIComponent(id)}`);
      if (!isObj(v) || v.id !== id) throw new OsvError("osv_malformed_response");
      return v as unknown as OsvVuln;
    },
  };
}

// ---------- findings ----------

const ISSUE_KEY = "vulnerable_dependency";
const display = (p: Pkg) => `${p.name} ${p.version}`;
const clip = (s: string, n: number) => (s.length > n ? s.slice(0, n - 1) + "…" : s);

export function dependencyFindings(lock: Lockfile, pkg: Pkg, vulns: OsvVuln[]): FindingCandidate {
  const rows = vulns.map((v) => ({ v, sev: severityOf(v), fixed: fixedVersion(v, pkg), cvss: cvssOf(v) }));
  // The finding carries the highest-scoring advisory's vector (a v4.0 vector only when none can be scored).
  const scored = rows.filter((r) => r.cvss?.score != null).sort((a, b) => b.cvss!.score! - a.cvss!.score!)[0];
  const cvssVector = (scored ?? rows.find((r) => r.cvss))?.cvss?.vector;
  const known = rows.filter((r) => r.sev);
  const worst = known.reduce<Severity | null>((w, r) => (!w || SEV_RANK[r.sev!] > SEV_RANK[w] ? r.sev : w), null);
  const unfixed = rows.filter((r) => !r.fixed).map((r) => r.v.id);
  const target = rows.map((r) => r.fixed).filter((f): f is string => !!f).sort(compareVersions).at(-1) ?? null;
  const cves = [...new Set(vulns.flatMap((v) => (v.aliases ?? []).filter((a) => a.startsWith("CVE-"))))];
  const ids = vulns.map((v) => v.id);
  const lead = clip(rows.sort((a, b) => SEV_RANK[b.sev ?? "medium"] - SEV_RANK[a.sev ?? "medium"])[0]?.v.summary ?? "", 90);
  const remediation = [
    target ? `Upgrade ${pkg.name} from ${pkg.version} to ${target} or later` + (unfixed.length ? `; no fix is published yet for ${unfixed.slice(0, 5).join(", ")}` : "") + ", then regenerate the lockfile."
      : `No fixed version of ${pkg.name} is published for ${ids.slice(0, 5).join(", ")}. Replace the package, or remove the vulnerable code path and record a risk acceptance.`,
    "Re-test after the change is on the default branch to confirm the finding resolves.",
  ].join(" ");
  return {
    issueKey: ISSUE_KEY,
    title: clip(`${display(pkg)}: ${vulns.length === 1 ? `${ids[0]}${lead ? ` — ${lead}` : ""}` : `${vulns.length} known vulnerabilities (${ids.slice(0, 3).join(", ")}${ids.length > 3 ? ", …" : ""})`}`, 200),
    severity: worst ?? "medium",
    ...(known.length === rows.length ? {} : { confidence: "likely" as const }),
    location: clip(`${lock.path}#${pkg.name}@${pkg.version}`, 300),
    evidence: {
      ecosystem: pkg.ecosystem, package: pkg.name, installedVersion: pkg.version, fixedVersion: target,
      lockfile: lock.path, lockfileSha256: lock.sha256, cves: cves.slice(0, 20),
      advisories: rows.slice(0, 20).map((r) => ({ id: r.v.id, aliases: (r.v.aliases ?? []).slice(0, 5), severity: r.sev, cvss: r.cvss?.score ?? null, fixed: r.fixed, summary: clip(r.v.summary ?? "", 200), url: `https://osv.dev/vulnerability/${r.v.id}` })),
      ...(rows.length > 20 ? { advisoriesOmitted: rows.length - 20 } : {}),
    },
    remediation: clip(remediation, 1000),
    ...(cvssVector && cvssVector.length <= 200 ? { cvssVector } : {}),
  };
}

// ---------- adapter ----------

export function createOsvAdapter(deps: { fetch?: FetchLike; retryDelayMs?: number } = {}): CheckAdapter {
  return {
    id: "deps.osv@1", checkKey: "deps.osv", target: "repository",
    async run(ctx): Promise<CheckResult> {
      const repo = ctx.repo;
      if (!repo) return { status: "error", reason: "no_repository_snapshot", evidence: {} };
      const base = { commit: repo.commit };
      let paths: string[];
      try { paths = (await repo.list()).filter((p) => lockfileParser(p)).sort(); } catch { return { status: "error", reason: "repository_unreadable", evidence: base }; }
      if (paths.length > MAX_LOCKFILES) return { status: "error", reason: "too_many_lockfiles", evidence: { ...base, lockfiles: paths.length } };

      const locks: Lockfile[] = [];
      for (const p of paths) {
        let text: string;
        try { text = await repo.read(p); } catch { return { status: "error", reason: "lockfile_unreadable", evidence: { ...base, lockfile: p } }; }
        try {
          const r = lockfileParser(p)!(text, p);
          const seen = new Set<string>();
          const packages = r.packages.filter((k) => { const key = `${k.ecosystem}|${k.name}|${k.version}`; return !seen.has(key) && !!seen.add(key); });
          locks.push({ path: p, sha256: createHash("sha256").update(text).digest("hex"), packages, unpinned: r.unpinned ?? 0 });
        } catch (e) {
          return { status: "error", reason: "lockfile_unparseable", evidence: { ...base, lockfile: p, detail: e instanceof LockfileError ? e.message.slice(0, 160) : "parse error" } };
        }
      }
      const summary = { ...base, lockfiles: locks.map((l) => ({ path: l.path, sha256: l.sha256, packages: l.packages.length, unpinned: l.unpinned })) };
      const all = locks.flatMap((l) => l.packages.map((p) => ({ l, p })));
      if (all.length > MAX_PACKAGES) return { status: "error", reason: "too_many_packages", evidence: { ...base, packages: all.length } };

      const findings: FindingCandidate[] = [];
      for (const l of locks.filter((x) => x.unpinned > 0)) {
        findings.push({
          issueKey: "unpinned_dependencies", title: `${l.unpinned} dependenc${l.unpinned === 1 ? "y is" : "ies are"} not pinned in ${l.path}`, severity: "info", confidence: "confirmed",
          location: clip(l.path, 300), evidence: { lockfile: l.path, lockfileSha256: l.sha256, unpinned: l.unpinned },
          remediation: "Only exact pins (==) can be checked for known vulnerabilities. Pin versions (e.g. with pip-compile or a lockfile) so every installed version is scanned.",
        });
      }
      if (!all.length) return { status: "ok", findings, evidence: { ...summary, packagesChecked: 0 } };

      const osv = osvClient(deps.fetch ?? (globalThis.fetch as unknown as FetchLike), undefined, deps.retryDelayMs);
      try {
        const unique = [...new Map(all.map(({ p }) => [`${p.ecosystem}|${p.name}|${p.version}`, p])).values()];
        const idsByKey = new Map<string, string[]>();
        (await osv.queryBatch(unique)).forEach((ids, i) => idsByKey.set(`${unique[i].ecosystem}|${unique[i].name}|${unique[i].version}`, ids));
        const vulnerable = all.filter(({ p }) => idsByKey.get(`${p.ecosystem}|${p.name}|${p.version}`)!.length);
        if (vulnerable.length + findings.length > MAX_FINDINGS) {
          return { status: "error", reason: "too_many_vulnerable_packages", evidence: { ...summary, vulnerablePackages: vulnerable.length } };
        }
        const ids = [...new Set(vulnerable.flatMap(({ p }) => idsByKey.get(`${p.ecosystem}|${p.name}|${p.version}`)!))];
        if (ids.length > MAX_ADVISORIES) return { status: "error", reason: "too_many_advisories", evidence: { ...summary, advisories: ids.length } };
        const details = new Map<string, OsvVuln>();
        for (let i = 0; i < ids.length; i += OSV_PARALLEL) {
          for (const v of await Promise.all(ids.slice(i, i + OSV_PARALLEL).map((id) => osv.vuln(id)))) details.set(v.id, v);
        }
        for (const { l, p } of vulnerable) findings.push(dependencyFindings(l, p, idsByKey.get(`${p.ecosystem}|${p.name}|${p.version}`)!.map((id) => details.get(id)!)));
        findings.sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity] || a.location.localeCompare(b.location));
        return { status: "ok", findings, evidence: { ...summary, packagesChecked: unique.length, vulnerablePackages: vulnerable.length, advisories: ids.length, source: "osv.dev" } };
      } catch (e) {
        return { status: "error", reason: e instanceof OsvError ? e.message : "osv_failed", evidence: { ...summary, ...(e instanceof OsvError && e.detail ? { detail: e.detail } : {}) } };
      }
    },
  };
}
