import { mkdir, mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { AppError } from "../errors";
import { assertSafeDiff, BRANCH_PREFIX, git, GitError, type Observed, type RepoRef } from "./repo";

// GitHub adapter (RS-REMED-004). The customer gives a fine-grained personal access token for one repository with
// Contents: read and write, Pull requests: read and write (Metadata: read is implied). Same hard rules as local_git:
//  - the only ref it creates is a new branch named ruyashield/… (create-only: GitHub refuses if it exists), and the
//    only ref it deletes is one of those branches, and only while it still points at the commit RuyaShield made;
//  - it never merges, never updates an existing ref and never pushes to the default branch: the change is a pull
//    request the customer reviews and merges;
//  - patches are checked and built in a cached partial clone (trees only; file contents are fetched on demand),
//    and the token never appears in a URL, argv, log line or error.

export const GITHUB_API = process.env.RUYA_GITHUB_API_URL || "https://api.github.com";
const GITHUB_GIT = process.env.RUYA_GITHUB_GIT_URL || "https://github.com";
const REPO = /^[A-Za-z0-9-]{1,39}\/[A-Za-z0-9._-]{1,100}$/;
const SHA = /^[0-9a-f]{40}$/;
const API_TIMEOUT_MS = 20_000;
const MAX_BLOB_BYTES = 10 * 1024 * 1024;

export type FetchFn = (url: string, init: RequestInit) => Promise<Response>;
let fetchImpl: FetchFn = (u, i) => fetch(u, i);
/** Tests only: route API calls to a fake. */
export function setGithubFetch(f: FetchFn | null) { fetchImpl = f ?? ((u, i) => fetch(u, i)); }

export function assertRepoName(externalId: string): [string, string] {
  if (!REPO.test(externalId) || externalId.endsWith(".git") || externalId.split("/")[1].startsWith(".")) {
    throw new AppError(422, "invalid_repository", "Use the repository as owner/name, for example acme/website.");
  }
  const [o, n] = externalId.split("/");
  return [o, n];
}

/** Fine-grained tokens only: a classic token cannot be limited to one repository. */
export function assertTokenShape(token: string) {
  if (/^gh[pousr]_/.test(token)) throw new AppError(422, "token_not_fine_grained", "Use a fine-grained token (it starts with github_pat_) limited to this one repository. Classic tokens reach every repository you can.");
  if (!/^github_pat_[A-Za-z0-9_]{20,255}$/.test(token)) throw new AppError(422, "token_invalid", "That does not look like a GitHub fine-grained token (github_pat_…).");
}

function tokenOf(r: RepoRef): string {
  if (!r.token) throw new AppError(503, "repository_unavailable", "The GitHub token for this repository could not be read.");
  return r.token;
}

const enc = (s: string) => s.split("/").map(encodeURIComponent).join("/");

/** One GitHub REST call. Errors carry a code, never the token or the response body. */
export async function api<T = unknown>(r: RepoRef, method: string, p: string, body?: unknown, accept = "application/vnd.github+json"): Promise<{ status: number; data: T }> {
  const [o, n] = assertRepoName(r.externalId);
  const url = `${GITHUB_API}/repos/${enc(o)}/${enc(n)}${p}`;
  let res: Response;
  try {
    res = await fetchImpl(url, {
      method, redirect: "error", signal: AbortSignal.timeout(API_TIMEOUT_MS),
      headers: {
        authorization: `Bearer ${tokenOf(r)}`, accept, "x-github-api-version": "2022-11-28", "user-agent": "RuyaShield-remediation/1",
        ...(body !== undefined ? { "content-type": "application/json" } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new AppError(503, "github_unreachable", "GitHub could not be reached. Try again in a minute.");
  }
  const text = await res.text();
  if (res.status === 401) throw new AppError(422, "github_token_rejected", "GitHub rejected the token. It may have expired or been revoked; connect the repository again with a new token.");
  if (res.status === 403 && /rate limit/i.test(text)) throw new AppError(429, "github_rate_limited", "GitHub's rate limit was reached. Try again later.");
  if (res.status === 403) throw new AppError(422, "github_forbidden", "The token is missing a permission. It needs Contents: read and write and Pull requests: read and write on this repository.");
  let data: unknown = text;
  if (accept.includes("json")) { try { data = text ? JSON.parse(text) : null; } catch { throw new AppError(503, "github_malformed_response", "GitHub sent an unexpected answer."); } }
  return { status: res.status, data: data as T };
}

const fail = (code: string, status: number) => new AppError(503, code, `GitHub answered ${status}.`);

/** Checks the token can reach the repository and write to it. Returns its default branch. */
export async function inspectRepository(r: RepoRef): Promise<{ defaultBranch: string; private: boolean; admin: boolean }> {
  const res = await api<{ default_branch?: string; private?: boolean; permissions?: { push?: boolean; admin?: boolean } }>(r, "GET", "");
  if (res.status === 404) throw new AppError(422, "github_repository_not_found", "GitHub has no such repository for this token. Check owner/name and that the token was given access to it.");
  if (res.status !== 200 || !res.data?.default_branch) throw fail("github_repository_unreadable", res.status);
  if (res.data.permissions && res.data.permissions.push === false) {
    throw new AppError(422, "github_forbidden", "The token can read this repository but not write to it. Give it Contents: read and write and Pull requests: read and write.");
  }
  return { defaultBranch: res.data.default_branch, private: !!res.data.private, admin: !!res.data.permissions?.admin };
}

export async function ghResolveCommit(r: RepoRef, ref: string): Promise<string> {
  const res = await api<string>(r, "GET", `/commits/${enc(ref)}`, undefined, "application/vnd.github.sha");
  const sha = typeof res.data === "string" ? res.data.trim() : "";
  if (res.status !== 200 || !SHA.test(sha)) throw new AppError(422, "unknown_ref", `The repository has no commit “${ref}”.`);
  return sha;
}

// ---------- cached clones ----------

const cacheRoot = () => process.env.RUYA_REPO_CACHE_DIR || path.join(tmpdir(), "ruyashield-repo-cache");
const locks = new Map<string, Promise<unknown>>();
/** One git operation per cache directory at a time in this process (git's own lock files cover other processes). */
function locked<T>(key: string, fn: () => Promise<T>): Promise<T> {
  const prev = locks.get(key) ?? Promise.resolve();
  const next = prev.catch(() => undefined).then(fn);
  locks.set(key, next.finally(() => { if (locks.get(key) === next) locks.delete(key); }));
  return next;
}

/** Credentials as a per-command config entry: not in the URL, the repository config or the process arguments. */
export function authEnv(r: RepoRef): Record<string, string> {
  const basic = Buffer.from(`x-access-token:${tokenOf(r)}`).toString("base64");
  return {
    GIT_CONFIG_COUNT: "2",
    GIT_CONFIG_KEY_0: `http.${GITHUB_GIT}/.extraheader`, GIT_CONFIG_VALUE_0: `Authorization: Basic ${basic}`,
    GIT_CONFIG_KEY_1: "core.hooksPath", GIT_CONFIG_VALUE_1: "/dev/null",
    GIT_ALLOW_PROTOCOL: GITHUB_GIT.startsWith("file:") ? "file" : "https",
  };
}
const remoteUrl = (r: RepoRef) => `${GITHUB_GIT}/${assertRepoName(r.externalId).join("/")}.git`;

async function hasCommit(dir: string, sha: string) {
  return git(dir, ["cat-file", "-e", `${sha}^{commit}`]).then(() => true, () => false);
}

/**
 * A bare clone holding `commit`. "trees" fetches commits and trees only (file contents arrive on demand, for patch
 * checks); "full" fetches the files too (for scanners that read most of them).
 */
export async function mirrorFor(r: RepoRef, commit: string, kind: "trees" | "full"): Promise<{ dir: string; env: Record<string, string> }> {
  if (!SHA.test(commit)) throw new AppError(422, "invalid_base_commit", "Invalid commit.");
  const key = (r.integrationId ?? r.externalId).replace(/[^A-Za-z0-9-]/g, "_");
  const dir = path.join(cacheRoot(), `${key}-${kind}.git`);
  const env = authEnv(r);
  await locked(dir, async () => {
    const exists = await stat(path.join(dir, "HEAD")).then(() => true, () => false);
    if (!exists) {
      await mkdir(cacheRoot(), { recursive: true, mode: 0o700 });
      await rm(dir, { recursive: true, force: true });
      const filter = kind === "trees" ? ["--filter=blob:none"] : [];
      await git(cacheRoot(), ["clone", "--quiet", "--bare", "--depth=1", "--no-tags", ...filter, "--", remoteUrl(r), dir], { env, timeoutMs: 120_000 });
    }
    if (await hasCommit(dir, commit)) return;
    const filter = kind === "trees" ? ["--filter=blob:none"] : [];
    try {
      await git(dir, ["fetch", "--quiet", "--depth=1", "--no-tags", ...filter, "origin", commit], { env, timeoutMs: 120_000 });
    } catch (e) {
      throw new AppError(422, "unknown_ref", `GitHub did not provide commit ${commit.slice(0, 12)}${e instanceof GitError ? `: ${e.stderr.split("\n")[0].slice(0, 160)}` : ""}.`);
    }
  });
  return { dir, env };
}

/** The patched tree, written into the mirror's object store (nothing else in the mirror changes). */
export async function ghBuildTree(r: RepoRef, base: string, diff: string): Promise<{ dir: string; env: Record<string, string>; tree: string }> {
  const m = await mirrorFor(r, base, "trees");
  const tmp = await mkdtemp(path.join(tmpdir(), "ruya-idx-"));
  const env = { ...m.env, GIT_INDEX_FILE: path.join(tmp, "index") };
  try {
    await git(m.dir, ["read-tree", base], { env });
    await git(m.dir, ["apply", "--cached", "--whitespace=nowarn", "-"], { env, input: diff });
    return { ...m, tree: (await git(m.dir, ["write-tree"], { env })).trim() };
  } finally {
    await rm(tmp, { recursive: true, force: true });
  }
}

// ---------- the change: branch + pull request, never a merge ----------

type Pull = { number: number; html_url: string; state: string; merged_at: string | null; merge_commit_sha: string | null; head?: { sha?: string } };

async function findPull(r: RepoRef, branch: string): Promise<Pull | null> {
  const owner = assertRepoName(r.externalId)[0];
  const res = await api<Pull[]>(r, "GET", `/pulls?state=all&per_page=5&head=${encodeURIComponent(`${owner}:${branch}`)}`);
  if (res.status !== 200 || !Array.isArray(res.data)) throw fail("github_pulls_unreadable", res.status);
  return res.data[0] ?? null;
}

async function branchSha(r: RepoRef, branch: string): Promise<string | null> {
  const res = await api<{ object?: { sha?: string } }>(r, "GET", `/git/ref/heads/${enc(branch)}`);
  if (res.status === 404) return null;
  const sha = res.data?.object?.sha;
  if (res.status !== 200 || !sha || !SHA.test(sha)) throw fail("github_ref_unreadable", res.status);
  return sha;
}

export async function ghOpenChange(r: RepoRef, c: { base: string; diff: string; branch: string; message: string }): Promise<{ headSha: string; url: string }> {
  if (!c.branch.startsWith(BRANCH_PREFIX)) throw new AppError(422, "invalid_branch", "Invalid branch.");
  assertSafeDiff(c.diff);
  if (/^GIT binary patch/m.test(c.diff)) throw new AppError(422, "invalid_patch", "Binary patches are not sent to GitHub.");

  // At-least-once delivery: a branch from an earlier attempt is adopted (only RuyaShield makes ruyashield/… branches,
  // and the name carries the plan id and version).
  let head = await branchSha(r, c.branch);
  if (!head) {
    const { dir, env, tree } = await ghBuildTree(r, c.base, c.diff);
    const baseTree = (await git(dir, ["rev-parse", `${c.base}^{tree}`], { env })).trim();
    // Changed paths: <old mode> <new mode> <old sha> <new sha> <status>\t<path>
    const out = await git(dir, ["diff-tree", "-r", "-z", "--no-renames", baseTree, tree], { env });
    const parts = out.split("\0").filter((x, i, a) => !(x === "" && i === a.length - 1));
    const entries: { path: string; mode: string; type: "blob"; sha: string | null }[] = [];
    for (let i = 0; i + 1 < parts.length; i += 2) {
      const m = /^:(\d{6}) (\d{6}) ([0-9a-f]{40}) ([0-9a-f]{40}) ([AMDT])$/.exec(parts[i]);
      const p = parts[i + 1];
      if (!m || !p) throw new AppError(422, "invalid_patch", "The patch produced an unexpected change.");
      if (m[5] === "D") { entries.push({ path: p, mode: m[1], type: "blob", sha: null }); continue; }
      if (m[2] !== "100644" && m[2] !== "100755") throw new AppError(422, "invalid_patch", "Only regular files can be changed.");
      const size = Number((await git(dir, ["cat-file", "-s", m[4]], { env })).trim());
      if (size > MAX_BLOB_BYTES) throw new AppError(422, "invalid_patch", `${p} is too large to send.`);
      const content = await git(dir, ["cat-file", "blob", m[4]], { env, encoding: "buffer", maxBuffer: MAX_BLOB_BYTES + 1024 }) as unknown as Buffer;
      const blob = await api<{ sha?: string }>(r, "POST", "/git/blobs", { content: Buffer.from(content).toString("base64"), encoding: "base64" });
      if (blob.status !== 201 || blob.data?.sha !== m[4]) throw fail("github_blob_failed", blob.status);
      entries.push({ path: p, mode: m[2], type: "blob", sha: m[4] });
    }
    if (!entries.length) throw new AppError(422, "invalid_patch", "The patch changes nothing.");
    const t = await api<{ sha?: string }>(r, "POST", "/git/trees", { base_tree: baseTree, tree: entries });
    if (t.status !== 201 || t.data?.sha !== tree) throw fail("github_tree_failed", t.status);
    const commit = await api<{ sha?: string }>(r, "POST", "/git/commits", { message: c.message, tree, parents: [c.base] });
    if (commit.status !== 201 || !commit.data?.sha) throw fail("github_commit_failed", commit.status);
    // Create-only: GitHub answers 422 if the ref exists, so an existing branch is never moved.
    const ref = await api(r, "POST", "/git/refs", { ref: `refs/heads/${c.branch}`, sha: commit.data.sha });
    if (ref.status === 422) {
      head = await branchSha(r, c.branch);
      if (!head) throw fail("github_ref_failed", ref.status);
    } else if (ref.status !== 201) {
      throw fail("github_ref_failed", ref.status);
    } else {
      head = commit.data.sha;
    }
  }

  const existing = await findPull(r, c.branch);
  if (existing) return { headSha: head, url: existing.html_url };
  const [title, ...rest] = c.message.split("\n");
  const pr = await api<Pull>(r, "POST", "/pulls", { title: title.slice(0, 250), head: c.branch, base: r.defaultBranch, body: rest.join("\n").trim(), draft: false });
  if (pr.status !== 201 || !pr.data?.html_url) throw fail("github_pull_failed", pr.status);
  return { headSha: head, url: pr.data.html_url };
}

/** Reads GitHub itself: the pull request says whether it was merged (any merge method) or closed. */
export async function ghObserveChange(r: RepoRef, c: { branch: string; headSha: string }): Promise<Observed> {
  const pr = await findPull(r, c.branch);
  if (pr?.merged_at) return { state: "merged", mergeSha: pr.merge_commit_sha && SHA.test(pr.merge_commit_sha) ? pr.merge_commit_sha : c.headSha };
  if (pr && pr.state === "open") return { state: "open" };
  if (pr) return { state: "closed" };
  return (await branchSha(r, c.branch)) ? { state: "open" } : { state: "closed" };
}

/** Removes a branch RuyaShield created, only while it still points at RuyaShield's commit. */
export async function ghDeleteBranch(r: RepoRef, branch: string, expectSha: string): Promise<void> {
  if (!branch.startsWith(BRANCH_PREFIX) || !SHA.test(expectSha)) throw new AppError(422, "invalid_branch", "Invalid branch.");
  const cur = await branchSha(r, branch);
  if (cur !== expectSha) return;
  const res = await api(r, "DELETE", `/git/refs/heads/${enc(branch)}`);
  if (res.status !== 204 && res.status !== 422) throw fail("github_ref_delete_failed", res.status);
}

/** Patched source for the sandbox in a temp directory, without repository internals. */
export async function ghCheckoutForSandbox(r: RepoRef, base: string, diff: string): Promise<{ dir: string; cleanup: () => Promise<void> } | { error: string }> {
  assertSafeDiff(diff);
  const tmp = await mkdtemp(path.join(tmpdir(), "ruya-sbx-"));
  const work = path.join(tmp, "work");
  const cleanup = () => rm(tmp, { recursive: true, force: true });
  const env = authEnv(r);
  try {
    await git(tmp, ["init", "--quiet", "--", work], { env });
    await git(work, ["fetch", "--quiet", "--depth=1", "--no-tags", "--", remoteUrl(r), base], { env, timeoutMs: 180_000 });
    await git(work, ["checkout", "--quiet", "--detach", "FETCH_HEAD"], { env });
  } catch (e) {
    await cleanup();
    return { error: e instanceof GitError ? `checkout_failed: ${e.stderr.split("\n")[0].slice(0, 200)}` : "checkout_failed" };
  }
  try {
    await git(work, ["apply", "--whitespace=nowarn", "-"], { env, input: diff });
  } catch (e) {
    await cleanup();
    return { error: e instanceof GitError ? `apply_failed: ${e.stderr.split("\n")[0]}` : "apply_failed" };
  }
  await rm(path.join(work, ".git"), { recursive: true, force: true });
  return { dir: work, cleanup };
}
