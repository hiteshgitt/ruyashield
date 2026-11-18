import { execFile } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { AppError } from "../errors";
import { open } from "../attacks/secretbox";
import { ghCheckoutForSandbox, ghDeleteBranch, ghObserveChange, ghOpenChange, ghResolveCommit, mirrorFor } from "./github";

// Provisional repository adapter: a local git repository under RUYA_LOCAL_REPO_ROOT (blueprint §9, RS-REM-004).
// It stands in for a hosted provider so the approval → change → observation flow is real end to end; it does not
// claim GitLab support. Repositories of type "github" are handled by ./github.ts under the same rules. Hard rules, enforced here and by a static test:
//  - it only ever creates or deletes branches named ruyashield/…, and never moves an existing ref;
//  - it never merges, never pushes to the default branch and never touches a working tree (plumbing only);
//  - git runs without a shell, with prompts and system config disabled and a timeout.

export const BRANCH_PREFIX = "ruyashield/";
const ZERO = "0".repeat(40);
const SHA = /^[0-9a-f]{40}$/;
const GIT_TIMEOUT_MS = 30_000;
const MAX_OUTPUT = 4 * 1024 * 1024;

export interface RepoRef {
  externalId: string;
  defaultBranch: string;
  /** Absent means local_git (the original adapter). */
  type?: "local_git" | "github";
  integrationId?: string;
  /** github only: the opened (decrypted) token, never stored or logged. */
  token?: string;
}
const isGithub = (r: RepoRef) => r.type === "github";

export const repoTokenAad = (orgId: string, integrationId: string) => `repo_integration:${orgId}:${integrationId}`;

/** The adapter reference for a stored integration; a GitHub token is opened only here, for the call at hand. */
export function refForIntegration(i: { id: string; orgId: string; type: string; externalId: string; defaultBranch: string; tokenEnc?: string | null }): RepoRef {
  const base = { externalId: i.externalId, defaultBranch: i.defaultBranch, integrationId: i.id };
  if (i.type !== "github") return base;
  let token: string | undefined;
  try { token = i.tokenEnc ? open(i.tokenEnc, repoTokenAad(i.orgId, i.id)) : undefined; } catch { token = undefined; }
  return { ...base, type: "github", token };
}

export function repoRoot(env: Record<string, string | undefined> = process.env): string | null {
  const r = env.RUYA_LOCAL_REPO_ROOT;
  return r && path.isAbsolute(r) ? path.resolve(r) : null;
}

/** The repository directory, confined to the configured root. */
export function repoPath(externalId: string, root = repoRoot()): string {
  if (!root) throw new AppError(503, "repository_unavailable", "No repository root is configured on this server.");
  if (!/^[A-Za-z0-9._-]{1,100}$/.test(externalId) || externalId === "." || externalId === "..") throw new AppError(422, "invalid_repository", "Invalid repository identifier.");
  const p = path.resolve(root, externalId);
  if (path.dirname(p) !== root) throw new AppError(422, "invalid_repository", "Invalid repository identifier.");
  return p;
}

export class GitError extends Error {
  constructor(public readonly args: string[], public readonly stderr: string) { super(`git ${args[0]} failed`); }
}

export function git(cwd: string, args: string[], opts: { input?: string; env?: Record<string, string>; maxBuffer?: number; timeoutMs?: number; encoding?: "buffer" } = {}): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = execFile("git", args, {
      cwd, timeout: opts.timeoutMs ?? GIT_TIMEOUT_MS, maxBuffer: opts.maxBuffer ?? MAX_OUTPUT, killSignal: "SIGKILL",
      ...(opts.encoding === "buffer" ? { encoding: "buffer" as const } : {}),
      env: {
        NODE_ENV: process.env.NODE_ENV, PATH: process.env.PATH ?? "/usr/bin:/bin", HOME: tmpdir(), GIT_TERMINAL_PROMPT: "0", GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null",
        GIT_AUTHOR_NAME: "RuyaShield", GIT_AUTHOR_EMAIL: "remediation@ruyashield.local",
        GIT_COMMITTER_NAME: "RuyaShield", GIT_COMMITTER_EMAIL: "remediation@ruyashield.local", ...opts.env,
      },
    }, (err: Error | null, stdout: string | Buffer, stderr: string | Buffer) => (err ? reject(new GitError(args, String(stderr).slice(0, 2000)))
      : resolve(opts.encoding === "buffer" ? stdout as unknown as string : String(stdout))));
    if (opts.input !== undefined) child.stdin?.end(opts.input);
  });
}

/** Rejects diffs that touch git internals, symlinks or submodules before git ever sees them. */
export function assertSafeDiff(diff: string) {
  if (!diff.trim()) throw new AppError(422, "invalid_patch", "The patch is empty.");
  for (const line of diff.split("\n")) {
    const m = /^(?:diff --git a\/(\S+) b\/(\S+)|(?:---|\+\+\+) [ab]\/(\S+)|rename (?:from|to) (\S+)|copy (?:from|to) (\S+))/.exec(line);
    if (m) {
      for (const p of m.slice(1).filter(Boolean)) {
        if (p.split("/").some((seg) => seg === ".git" || seg === "..") || p.startsWith("/")) throw new AppError(422, "invalid_patch", `The patch touches a forbidden path: ${p}`);
      }
    }
    if (/^(new|old|deleted) (file )?mode 1[26]0000/.test(line) || /^index \S+ 1[26]0000/.test(line)) {
      throw new AppError(422, "invalid_patch", "Patches that create symlinks or submodules are not accepted.");
    }
  }
}

export async function resolveCommit(r: RepoRef, ref: string): Promise<string> {
  if (!/^[A-Za-z0-9._/-]{1,100}$/.test(ref) || ref.startsWith("-") || ref.includes("..")) throw new AppError(422, "invalid_ref", "Invalid ref.");
  if (isGithub(r)) return ghResolveCommit(r, ref);
  try {
    return (await git(repoPath(r.externalId), ["rev-parse", "--verify", "--quiet", `${ref}^{commit}`])).trim();
  } catch {
    throw new AppError(422, "unknown_ref", `The repository has no commit “${ref}”.`);
  }
}

/** Builds the patched tree in a throwaway index; the repository's own index and working tree are untouched. */
async function buildTree(dir: string, base: string, diff: string, extraEnv: Record<string, string> = {}): Promise<string> {
  const tmp = await mkdtemp(path.join(tmpdir(), "ruya-idx-"));
  const env = { ...extraEnv, GIT_INDEX_FILE: path.join(tmp, "index") };
  try {
    await git(dir, ["read-tree", base], { env });
    await git(dir, ["apply", "--cached", "--whitespace=nowarn", "-"], { env, input: diff });
    return (await git(dir, ["write-tree"], { env })).trim();
  } finally {
    await rm(tmp, { recursive: true, force: true });
  }
}

/** Does the patch apply cleanly on that commit? Returns the reason it does not. */
export async function checkPatch(r: RepoRef, base: string, diff: string): Promise<{ ok: true } | { ok: false; reason: string }> {
  if (!SHA.test(base)) return { ok: false, reason: "invalid_base_commit" };
  assertSafeDiff(diff);
  try {
    if (isGithub(r)) {
      const m = await mirrorFor(r, base, "trees");
      await buildTree(m.dir, base, diff, m.env);
    } else {
      await buildTree(repoPath(r.externalId), base, diff);
    }
    return { ok: true };
  } catch (e) {
    if (e instanceof AppError) return { ok: false, reason: e.code };
    return { ok: false, reason: e instanceof GitError ? `does_not_apply: ${e.stderr.split("\n")[0]}` : "does_not_apply" };
  }
}

/** Creates a new ruyashield/… branch holding the approved patch as one commit on its base. Never merges. */
export async function openChange(r: RepoRef, c: { base: string; diff: string; branch: string; message: string }): Promise<{ headSha: string; url: string }> {
  if (!c.branch.startsWith(BRANCH_PREFIX) || !/^[A-Za-z0-9._/-]+$/.test(c.branch) || c.branch.includes("..")) throw new AppError(422, "invalid_branch", "Invalid branch.");
  if (!SHA.test(c.base)) throw new AppError(422, "invalid_base_commit", "Invalid base commit.");
  assertSafeDiff(c.diff);
  if (isGithub(r)) return ghOpenChange(r, c);
  const dir = repoPath(r.externalId);
  const tree = await buildTree(dir, c.base, c.diff);
  const head = (await git(dir, ["commit-tree", tree, "-p", c.base, "-F", "-"], { input: c.message })).trim();
  // Create-only: fails if the branch already exists, so an existing ref is never moved.
  await git(dir, ["update-ref", `refs/heads/${c.branch}`, head, ZERO]);
  return { headSha: head, url: `local://${r.externalId}/${c.branch}` };
}

/** Where an opened change can be seen, for a branch adopted after a crash (local_git has no web page). */
export const changeUrl = (r: RepoRef, branch: string) =>
  isGithub(r) ? `https://github.com/${r.externalId}/tree/${branch}` : `local://${r.externalId}/${branch}`;

export type Observed = { state: "open" } | { state: "merged"; mergeSha: string } | { state: "closed" };

/** Reads the repository itself; a webhook is only ever a hint to look. */
export async function observeChange(r: RepoRef, c: { branch: string; headSha: string }): Promise<Observed> {
  if (isGithub(r)) return ghObserveChange(r, c);
  const dir = repoPath(r.externalId);
  const tip = (await git(dir, ["rev-parse", "--verify", "--quiet", `refs/heads/${r.defaultBranch}^{commit}`]).catch(() => "")).trim();
  if (tip && SHA.test(c.headSha)) {
    const merged = await git(dir, ["merge-base", "--is-ancestor", c.headSha, tip]).then(() => true, () => false);
    if (merged) return { state: "merged", mergeSha: tip };
  }
  const ref = await git(dir, ["rev-parse", "--verify", "--quiet", `refs/heads/${c.branch}`]).then(() => true, () => false);
  return ref ? { state: "open" } : { state: "closed" };
}

/** Removes a branch this service created (used when an approval was revoked mid-flight). */
export async function deleteBranch(r: RepoRef, branch: string, expectSha: string): Promise<void> {
  if (!branch.startsWith(BRANCH_PREFIX) || !SHA.test(expectSha)) throw new AppError(422, "invalid_branch", "Invalid branch.");
  if (isGithub(r)) return ghDeleteBranch(r, branch, expectSha);
  await git(repoPath(r.externalId), ["update-ref", "-d", `refs/heads/${branch}`, expectSha]);
}

/** A detached copy for the sandbox: patched source in a temp directory, the repository itself is not modified. */
export async function checkoutForSandbox(r: RepoRef, base: string, diff: string): Promise<{ dir: string; cleanup: () => Promise<void> } | { error: string }> {
  assertSafeDiff(diff);
  if (isGithub(r)) return ghCheckoutForSandbox(r, base, diff);
  const tmp = await mkdtemp(path.join(tmpdir(), "ruya-sbx-"));
  const work = path.join(tmp, "work");
  const cleanup = () => rm(tmp, { recursive: true, force: true });
  try {
    await git(tmp, ["clone", "--quiet", "--no-local", "--no-checkout", "--", repoPath(r.externalId), work]);
    await git(work, ["checkout", "--quiet", "--detach", base]);
  } catch (e) {
    await cleanup();
    return { error: e instanceof GitError ? `checkout_failed: ${e.stderr.split("\n")[0]}` : "checkout_failed" };
  }
  try {
    await git(work, ["apply", "--whitespace=nowarn", "-"], { input: diff });
  } catch (e) {
    await cleanup();
    return { error: e instanceof GitError ? `apply_failed: ${e.stderr.split("\n")[0]}` : "apply_failed" };
  }
  await rm(path.join(work, ".git"), { recursive: true, force: true }); // tests never see repository internals
  return { dir: work, cleanup };
}

// ---------- read-only snapshot for repository scanners ----------

/** Largest single file a repository scanner may read (lockfiles of big monorepos run to a few MB). */
export const MAX_SCAN_FILE_BYTES = 16 * 1024 * 1024;
const MAX_TREE_ENTRIES = 200_000;

/**
 * A read-only view of one commit. Plumbing only (ls-tree / cat-file): no checkout, no working tree,
 * no hooks, nothing executed from the repository. Symlinks and submodules are not listed.
 */
export interface RepoSnapshot {
  externalId: string;
  commit: string;
  /** Regular-file paths at this commit. */
  list(): Promise<string[]>;
  /** File contents; throws for files over MAX_SCAN_FILE_BYTES or paths not in the tree. */
  read(path: string): Promise<string>;
}

export async function snapshotRepo(r: RepoRef, ref = r.defaultBranch): Promise<RepoSnapshot> {
  const commit = await resolveCommit(r, ref);
  const m = isGithub(r) ? await mirrorFor(r, commit, "full") : { dir: repoPath(r.externalId), env: {} };
  const dir = m.dir;
  let files: Map<string, number> | null = null;
  const list = async () => {
    if (!files) {
      const out = await git(dir, ["ls-tree", "-r", "-z", "--long", "--full-tree", commit], { maxBuffer: 64 * 1024 * 1024, env: m.env });
      files = new Map();
      for (const rec of out.split("\0")) {
        // <mode> SP <type> SP <object> SP+ <size> TAB <path>
        const m = /^(100644|100755) blob [0-9a-f]{40}\s+(\d+)\t([^]+)$/.exec(rec);
        if (m) files.set(m[3], Number(m[2]));
        if (files.size > MAX_TREE_ENTRIES) throw new AppError(422, "repository_too_large", "The repository has too many files to scan.");
      }
    }
    return [...files.keys()];
  };
  return {
    externalId: r.externalId, commit, list,
    async read(p: string) {
      await list();
      const size = files!.get(p);
      if (size === undefined) throw new AppError(404, "not_found", `No file ${p} at ${commit.slice(0, 12)}.`);
      if (size > MAX_SCAN_FILE_BYTES) throw new AppError(422, "file_too_large", `${p} is larger than the scan limit.`);
      return git(dir, ["cat-file", "blob", `${commit}:${p}`], { maxBuffer: MAX_SCAN_FILE_BYTES + 1024, env: m.env });
    },
  };
}
