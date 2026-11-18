import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

// The GitHub adapter end to end against a stand-in: a local bare repository plays GitHub's git server, and a small
// fake answers the REST calls the way GitHub does (create-only refs, pulls, merges done by the "customer").

const root = mkdtempSync(path.join(tmpdir(), "ruya-gh-test-"));
const remote = path.join(root, "acme", "web.git");
const work = path.join(root, "seed");
const TOKEN = "github_pat_" + "A".repeat(40);
process.env.RUYA_GITHUB_GIT_URL = `file://${root}`;
process.env.RUYA_GITHUB_API_URL = "https://api.github.test";
process.env.RUYA_REPO_CACHE_DIR = path.join(root, "cache");

const g = (cwd: string, args: string[], input?: string) =>
  execFileSync("git", args, { cwd, input, encoding: "utf8", env: { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null", GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@t", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@t" } }).trim();

type Pull = { number: number; head: string; state: string; merged_at: string | null; merge_commit_sha: string | null; html_url: string };
const pulls: Pull[] = [];
const calls: string[] = [];
let authSeen = "";

async function fakeGithub(url: string, init: RequestInit): Promise<Response> {
  const method = init.method ?? "GET";
  authSeen = String((init.headers as Record<string, string>).authorization);
  const u = new URL(url);
  const p = decodeURIComponent(u.pathname.replace(/^\/repos\/acme\/web/, ""));
  calls.push(`${method} ${p}`);
  const body = init.body ? JSON.parse(String(init.body)) : null;
  const json = (status: number, data: unknown) => new Response(data === null ? null : JSON.stringify(data), { status });
  if (authSeen !== `Bearer ${TOKEN}`) return json(401, { message: "Bad credentials" });
  if (method === "GET" && p === "") return json(200, { default_branch: "main", private: true, permissions: { push: true, admin: false } });
  if (method === "GET" && p.startsWith("/commits/")) {
    try { return new Response(g(remote, ["rev-parse", "--verify", `${p.slice(9)}^{commit}`]), { status: 200 }); } catch { return json(422, { message: "No commit" }); }
  }
  if (method === "GET" && p.startsWith("/git/ref/heads/")) {
    try { return json(200, { object: { sha: g(remote, ["rev-parse", "--verify", `refs/heads/${p.slice(15)}`]) } }); } catch { return json(404, { message: "Not Found" }); }
  }
  if (method === "POST" && p === "/git/blobs") {
    const sha = execFileSync("git", ["hash-object", "-w", "--stdin"], { cwd: remote, input: Buffer.from(body.content, "base64") }).toString().trim();
    return json(201, { sha });
  }
  if (method === "POST" && p === "/git/trees") {
    const idx = path.join(root, `idx-${Date.now()}`);
    const env = { ...process.env, GIT_INDEX_FILE: idx };
    execFileSync("git", ["read-tree", body.base_tree], { cwd: remote, env });
    for (const e of body.tree) {
      if (e.sha === null) execFileSync("git", ["update-index", "--force-remove", e.path], { cwd: remote, env });
      else execFileSync("git", ["update-index", "--add", "--cacheinfo", `${e.mode},${e.sha},${e.path}`], { cwd: remote, env });
    }
    const sha = execFileSync("git", ["write-tree"], { cwd: remote, env }).toString().trim();
    rmSync(idx, { force: true });
    return json(201, { sha });
  }
  if (method === "POST" && p === "/git/commits") {
    return json(201, { sha: g(remote, ["commit-tree", body.tree, "-p", body.parents[0], "-m", body.message]) });
  }
  if (method === "POST" && p === "/git/refs") {
    try { g(remote, ["update-ref", body.ref, body.sha, "0".repeat(40)]); return json(201, { ref: body.ref }); } catch { return json(422, { message: "Reference already exists" }); }
  }
  if (method === "DELETE" && p.startsWith("/git/refs/heads/")) { g(remote, ["update-ref", "-d", `refs/heads/${p.slice(16)}`]); return json(204, null); }
  if (method === "GET" && p === "/pulls") {
    const head = u.searchParams.get("head")!.split(":")[1];
    return json(200, pulls.filter((x) => x.head === head).map((x) => ({ ...x })));
  }
  if (method === "POST" && p === "/pulls") {
    const pr: Pull = { number: pulls.length + 1, head: body.head, state: "open", merged_at: null, merge_commit_sha: null, html_url: `https://github.com/acme/web/pull/${pulls.length + 1}` };
    pulls.push(pr);
    return json(201, pr);
  }
  return json(404, { message: `unhandled ${method} ${p}` });
}

let gh: typeof import("@/server/remediation/github");
let repo: typeof import("@/server/remediation/repo");
const ref = () => ({ externalId: "acme/web", defaultBranch: "main", type: "github" as const, integrationId: "11111111-1111-4111-8111-111111111111", token: TOKEN });
let base = "";
const diff = [
  "diff --git a/server.js b/server.js",
  "--- a/server.js",
  "+++ b/server.js",
  "@@ -1,2 +1,3 @@",
  " const app = require('express')();",
  "+app.disable('x-powered-by');",
  " app.listen(3000);",
  "",
].join("\n");

beforeAll(async () => {
  g(root, ["init", "--quiet", "--bare", "--initial-branch=main", remote]);
  g(remote, ["config", "uploadpack.allowFilter", "true"]);
  g(remote, ["config", "uploadpack.allowAnySHA1InWant", "true"]);
  g(root, ["init", "--quiet", "--initial-branch=main", work]);
  execFileSync("sh", ["-c", "printf \"const app = require('express')();\\napp.listen(3000);\\n\" > server.js && printf 'ok\\n' > README.md"], { cwd: work });
  g(work, ["add", "."]);
  g(work, ["commit", "--quiet", "-m", "init"]);
  g(work, ["push", "--quiet", remote, "main"]);
  base = g(remote, ["rev-parse", "main"]);
  gh = await import("@/server/remediation/github");
  repo = await import("@/server/remediation/repo");
  gh.setGithubFetch(fakeGithub);
});
afterAll(() => { gh?.setGithubFetch(null); rmSync(root, { recursive: true, force: true }); });

describe("GitHub adapter", () => {
  it("accepts only fine-grained tokens and owner/name repositories", () => {
    expect(() => gh.assertTokenShape("ghp_" + "x".repeat(36))).toThrow(/fine-grained/);
    expect(() => gh.assertTokenShape(TOKEN)).not.toThrow();
    expect(() => gh.assertRepoName("acme")).toThrow();
    expect(() => gh.assertRepoName("acme/../x")).toThrow();
    expect(gh.assertRepoName("acme/web")).toEqual(["acme", "web"]);
  });

  it("checks the token can write, and reports the default branch", async () => {
    expect(await gh.inspectRepository(ref())).toMatchObject({ defaultBranch: "main", admin: false });
    await expect(gh.inspectRepository({ ...ref(), token: "github_pat_" + "B".repeat(40) })).rejects.toMatchObject({ code: "github_token_rejected" });
  });

  it("resolves commits and checks patches in a partial clone without file contents up front", async () => {
    expect(await repo.resolveCommit(ref(), "main")).toBe(base);
    expect(await repo.checkPatch(ref(), base, diff)).toEqual({ ok: true });
    const bad = diff.replace("app.listen(3000);", "app.listen(4000);");
    expect((await repo.checkPatch(ref(), base, bad)).ok).toBe(false);
  });

  it("opens a pull request on a new ruyashield/ branch, never touching main", async () => {
    const opened = await repo.openChange(ref(), { base, diff, branch: "ruyashield/plan-1-v1", message: "RuyaShield remediation: hide x-powered-by\n\nNot merged by RuyaShield." });
    expect(opened.url).toBe("https://github.com/acme/web/pull/1");
    expect(g(remote, ["rev-parse", "main"])).toBe(base);
    expect(g(remote, ["rev-parse", "ruyashield/plan-1-v1"])).toBe(opened.headSha);
    expect(g(remote, ["show", `${opened.headSha}:server.js`])).toContain("app.disable('x-powered-by');");
    expect(g(remote, ["rev-parse", `${opened.headSha}^`])).toBe(base);
    // A retry adopts the branch and the pull request instead of making new ones.
    const again = await repo.openChange(ref(), { base, diff, branch: "ruyashield/plan-1-v1", message: "RuyaShield remediation: hide x-powered-by" });
    expect(again).toEqual(opened);
    expect(pulls).toHaveLength(1);
    expect(await repo.observeChange(ref(), { branch: "ruyashield/plan-1-v1", headSha: opened.headSha })).toEqual({ state: "open" });
  });

  it("sees the customer's merge through the pull request", async () => {
    const head = g(remote, ["rev-parse", "ruyashield/plan-1-v1"]);
    g(remote, ["update-ref", "refs/heads/main", head]); // the customer merged it on GitHub
    Object.assign(pulls[0], { state: "closed", merged_at: new Date().toISOString(), merge_commit_sha: head });
    expect(await repo.observeChange(ref(), { branch: "ruyashield/plan-1-v1", headSha: head })).toEqual({ state: "merged", mergeSha: head });
  });

  it("deletes only its own branch, and only while it still points at its commit", async () => {
    const head = g(remote, ["rev-parse", "ruyashield/plan-1-v1"]);
    await repo.deleteBranch(ref(), "ruyashield/plan-1-v1", "0".repeat(39) + "1");
    expect(g(remote, ["rev-parse", "ruyashield/plan-1-v1"])).toBe(head);
    await repo.deleteBranch(ref(), "ruyashield/plan-1-v1", head);
    expect(() => g(remote, ["rev-parse", "--verify", "--quiet", "refs/heads/ruyashield/plan-1-v1"])).toThrow();
    await expect(repo.deleteBranch(ref(), "main", head)).rejects.toMatchObject({ code: "invalid_branch" });
  });

  it("gives the sandbox patched source without .git, and scanners a full snapshot", async () => {
    const co = await repo.checkoutForSandbox(ref(), base, diff);
    if ("error" in co) throw new Error(co.error);
    expect(readFileSync(path.join(co.dir, "server.js"), "utf8")).toContain("x-powered-by");
    expect(() => readFileSync(path.join(co.dir, ".git", "HEAD"))).toThrow();
    await co.cleanup();
    const snap = await repo.snapshotRepo(ref(), base);
    expect((await snap.list()).sort()).toEqual(["README.md", "server.js"]);
    expect(await snap.read("README.md")).toBe("ok\n");
  });

  it("never sends the token in git arguments or URLs, and never calls a merge endpoint", () => {
    expect(authSeen).toBe(`Bearer ${TOKEN}`);
    expect(calls.some((c) => /merge/i.test(c))).toBe(false);
    expect(calls.some((c) => c.startsWith("PATCH"))).toBe(false);
    const src = readFileSync(path.join(__dirname, "../../src/server/remediation/github.ts"), "utf8");
    expect(src).not.toMatch(/\/merges?\b|"PATCH"|"PUT"/);
    expect(src).not.toMatch(/x-access-token:\$\{[^}]+\}@/); // no token in a URL
  });
});
