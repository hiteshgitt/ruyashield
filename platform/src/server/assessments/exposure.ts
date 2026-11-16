import { createHash, randomBytes } from "node:crypto";
import { EgressError, guardedGet, type FetchResult } from "../net/egress";
import type { CheckAdapter, CheckContext, CheckResult, FindingCandidate } from "./checks";

/**
 * http.exposure (scanner M6, class A1): a few ordinary GETs for files that should never be public.
 *  - /.git/HEAD (source code history), /.env (application secrets), and directory listings on / and a few common
 *    asset folders. Cookie flags are already reported by http.security_headers, so they are not repeated here.
 *  - At most 512 bytes of any response are read; the rest is never downloaded.
 *  - Evidence never contains file contents: only status, content type, byte count and a SHA-256 of the prefix.
 *  - Soft-404 guard: a random path is fetched first. A probe whose body is identical to that page is the site's
 *    catch-all page, not the file. If the catch-all answers 200, matches are reported as "likely", not confirmed.
 *  - Fails closed: a 5xx, 429 or network error on any probe is an error, never "nothing exposed".
 *  - Fingerprint = probed URL + issue key, so removing the file and re-testing resolves exactly that finding.
 */

export const PREFIX_BYTES = 512;
export const LISTING_DIRS = ["/", "/uploads/", "/images/", "/static/", "/assets/", "/backup/"] as const;

export type Fetch = (url: string, ctx: CheckContext) => Promise<FetchResult>;
const defaultFetch: Fetch = (url, ctx) =>
  guardedGet(url, { ...ctx.egress, onHop: ctx.onHop, timeoutMs: Math.min(ctx.timeoutMs, 5000), truncateAt: PREFIX_BYTES, accept: "*/*", followRedirects: false, tlsLenient: true });

const sha256 = (s: string) => createHash("sha256").update(s, "utf8").digest("hex");

export const isGitHead = (body: string) => /^(ref: refs\/[\w./-]+|[0-9a-f]{40}|[0-9a-f]{64})\s*$/.test(body.split(/\r?\n/)[0] ?? "");
export function isEnvFile(body: string, contentType: string | null): boolean {
  const ct = (contentType ?? "").toLowerCase();
  if (/html|json|xml|javascript|image\//.test(ct)) return false;
  const first = body.split(/\r?\n/).map((l) => l.trim()).find((l) => l && !l.startsWith("#"));
  return !!first && /^(export\s+)?[A-Z_][A-Z0-9_]*=/.test(first);
}
export const isDirectoryListing = (body: string) => /Index of \//.test(body);

const REMEDIATION = {
  "git-exposed": "Block web access to the .git directory (nginx: location ~ /\\.git { deny all; }; Apache: RedirectMatch 404 /\\.git) or deploy without it. Anyone can download your full source history from here, including any secrets ever committed: rotate credentials that were in the repository.",
  "env-exposed": "Remove the .env file from the web root (or block dotfiles: nginx location ~ /\\.(?!well-known) { deny all; }) and keep configuration outside the document root. Treat every secret in it as leaked: rotate database passwords, API keys and tokens now.",
  "directory-listing": "Turn off automatic directory listings (nginx: autoindex off; Apache: Options -Indexes) and add an index file or a 403 for folders that should not be browsable.",
} as const;

interface Observation { url: string; status: number; contentType: string | null; bytes: number; truncated: boolean; sha256: string; redirects: number }
const observe = (url: string, r: FetchResult): Observation =>
  ({ url, status: r.status, contentType: r.contentType ? r.contentType.slice(0, 80) : null, bytes: Buffer.byteLength(r.body, "utf8"), truncated: r.truncated, sha256: sha256(r.body), redirects: r.redirects });

export function createExposureAdapter(fetch: Fetch = defaultFetch, randomPath: () => string = () => `/ruya-${randomBytes(8).toString("hex")}-404check`): CheckAdapter {
  return {
    id: "http.exposure@1", checkKey: "http.exposure", target: "host",
    async run(ctx): Promise<CheckResult> {
      const base = `https://${ctx.host}`;
      const seen: Observation[] = [];
      const get = async (path: string) => {
        const r = await fetch(base + path, ctx);
        seen.push(observe(base + path, r));
        return r;
      };
      const failed = (r: FetchResult) => r.status === 429 || r.status >= 500;
      const out: FindingCandidate[] = [];
      try {
        const soft = await get(randomPath());
        if (failed(soft)) return { status: "error", reason: `http_${soft.status}`, evidence: { probes: seen } };
        const soft200 = soft.status === 200;
        const softHash = sha256(soft.body);

        const probe = async (path: string, issueKey: keyof typeof REMEDIATION, title: string, severity: FindingCandidate["severity"], matches: (r: FetchResult) => boolean) => {
          const r = await get(path);
          if (failed(r)) throw new ProbeFailed(r.status);
          // Only a direct 200 counts: a redirect to a login page or the home page is not the file.
          if (r.status !== 200 || r.redirects > 0 || !matches(r)) return;
          const o = seen[seen.length - 1];
          if (soft200 && o.sha256 === softHash) return; // the catch-all page, not the file
          out.push({
            issueKey, title, severity, location: base + path, ...(soft200 ? { confidence: "likely" as const } : {}),
            evidence: { status: o.status, contentType: o.contentType, bytesRead: o.bytes, truncated: o.truncated, prefixSha256: o.sha256, softNotFound: soft200 ? "200" : String(soft.status) },
            remediation: REMEDIATION[issueKey],
          });
        };

        await probe("/.git/HEAD", "git-exposed", "Git repository is publicly downloadable (/.git/HEAD)", "critical", (r) => isGitHead(r.body));
        await probe("/.env", "env-exposed", "Environment file with secrets is publicly readable (/.env)", "critical", (r) => isEnvFile(r.body, r.contentType));
        for (const d of LISTING_DIRS) {
          await probe(d, "directory-listing", `Directory listing is enabled at ${d}`, "low", (r) => isDirectoryListing(r.body));
        }
      } catch (e) {
        if (e instanceof ProbeFailed) return { status: "error", reason: `http_${e.status}`, evidence: { probes: seen } };
        if (e instanceof EgressError) return { status: "error", reason: e.code === "network" ? "host_unreachable" : e.code, evidence: { error: e.message.slice(0, 200), probes: seen } };
        throw e;
      }
      return { status: "ok", findings: out, evidence: { probes: seen.map(({ url, status, bytes, redirects }) => ({ url, status, bytes, redirects })) } };
    },
  };
}

class ProbeFailed extends Error { constructor(public status: number) { super(`http_${status}`); } }
