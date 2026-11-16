import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { eq, sql } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { db, withOrg } from "@/server/db/client";
import { assets, findings, users } from "@/server/db/schema";
import { createOrg } from "@/server/orgs/orgs";
import { loadPrincipal, type LoadedPrincipal } from "@/server/principal";
import type { SessionInfo } from "@/server/auth/session";
import { addRepositoryAsset, startVerification } from "@/server/assets/assets";
import { launchAssessment, listCatalogue, runAssessment } from "@/server/assessments/assessments";
import { createOsvAdapter, type FetchLike } from "@/server/assessments/deps";
import { createSecretsAdapter } from "@/server/assessments/secrets";
import { createSastAdapter } from "@/server/assessments/sast";
import { transition } from "@/server/findings/findings";
import { createIntegration, disableIntegration } from "@/server/remediation/integrations";
import { requestVerification, runVerification } from "@/server/verification/verification";

// Repository assets end to end: connect a local git repo, scan its lockfile with deps.osv against a recorded OSV
// fixture, commit the upgrade, re-test, and see the finding become resolved_verified.
// Needs a migrated database (DATABASE_URL) and git. The background worker must be stopped while this runs.
const run = process.env.DATABASE_URL ? describe : describe.skip;

const FIX = path.join(__dirname, "../fixtures/osv");
const GHSA = "GHSA-p6mc-m468-83gw"; // lodash prototype pollution, fixed for lodash in 4.17.19

/** Recorded OSV: lodash 4.17.15 has GHSA-p6mc-m468-83gw, every other version is clean. Counts calls. */
function fakeOsv() {
  const calls: string[] = [];
  const fetch: FetchLike = async (url, init) => {
    calls.push(url);
    const json = (b: unknown) => ({ ok: true, status: 200, text: async () => JSON.stringify(b) });
    if (url === "https://api.osv.dev/v1/querybatch") {
      const { queries } = JSON.parse(init.body!) as { queries: { package: { name: string }; version: string }[] };
      return json({ results: queries.map((q) => (q.package.name === "lodash" && q.version === "4.17.15" ? { vulns: [{ id: GHSA }] } : {})) });
    }
    if (url === `https://api.osv.dev/v1/vulns/${GHSA}`) return json(JSON.parse(readFileSync(path.join(FIX, `${GHSA}.json`), "utf8")));
    return { ok: false, status: 404, text: async () => "" };
  };
  return { fetch, calls };
}

const lock = (lodash: string) => JSON.stringify({
  name: "vuln-demo", version: "1.0.0", lockfileVersion: 3, requires: true,
  packages: { "": { name: "vuln-demo", version: "1.0.0", dependencies: { lodash: `^${lodash}` } }, "node_modules/lodash": { version: lodash } },
}, null, 2);

let root: string;
const git = (repo: string, ...args: string[]) => execFileSync("git", ["-c", "user.name=t", "-c", "user.email=t@t.invalid", "-c", "commit.gpgsign=false", ...args], { cwd: repo, stdio: "pipe" });
function makeRepo(name: string, lodash: string) {
  const repo = path.join(root, name);
  execFileSync("git", ["init", "-q", "-b", "main", repo]);
  writeFileSync(path.join(repo, "package-lock.json"), lock(lodash));
  git(repo, "add", ".");
  git(repo, "commit", "-qm", "init");
  return repo;
}
function commitFile(repo: string, file: string, text: string, msg: string) {
  writeFileSync(path.join(repo, file), text);
  git(repo, "add", file);
  git(repo, "commit", "-qm", msg);
}
function bump(repo: string, lodash: string) {
  writeFileSync(path.join(repo, "package-lock.json"), lock(lodash));
  git(repo, "commit", "-qam", `bump lodash to ${lodash}`);
}

async function newUser(): Promise<SessionInfo> {
  const email = `t-${randomUUID()}@ruya-tests.invalid`;
  const [u] = await db.insert(users).values({ email, displayName: "Test", idpIssuer: "test", idpSubject: email }).returning();
  return { idHash: "x", userId: u.id, email, displayName: "Test", activeOrgId: null, mfa: true, amr: ["mfa"], authTime: new Date() };
}

async function fixture(lodash = "4.17.15") {
  const user = await newUser();
  const org = await createOrg(user, { name: `Repo ${randomUUID().slice(0, 8)}` });
  const ctx = (await loadPrincipal(user, org.id))!;
  const name = `demo-${randomUUID().slice(0, 8)}`;
  const repo = makeRepo(name, lodash);
  const integ = await createIntegration(ctx, { name: "Demo app", externalId: name, defaultBranch: "main", testCommands: [] });
  const { asset, created } = await addRepositoryAsset(ctx, integ.id);
  return { ctx, repo, integ, asset, created };
}

async function scan(ctx: LoadedPrincipal, assetId: string, osv = fakeOsv()) {
  const { assessment } = await launchAssessment(ctx, { assetId, idempotencyKey: `k-${randomUUID()}`, checkIds: ["deps.osv@1"] });
  const job = await withOrg(ctx.org.id, (tx) => tx.execute<{ payload: { assessmentId: string; token: string } }>(
    sql`SELECT payload FROM outbox WHERE business_key = ${`assessment:${assessment.id}:1`}`));
  await runAssessment(ctx.org.id, job.rows[0].payload, { adapters: new Map([["deps.osv@1", createOsvAdapter({ fetch: osv.fetch })]]), minIntervalMs: 0 });
  return assessment.id;
}
async function scanSast(ctx: LoadedPrincipal, assetId: string) {
  const { assessment } = await launchAssessment(ctx, { assetId, idempotencyKey: `k-${randomUUID()}`, checkIds: ["code.sast@1"] });
  const job = await withOrg(ctx.org.id, (tx) => tx.execute<{ payload: { assessmentId: string; token: string } }>(
    sql`SELECT payload FROM outbox WHERE business_key = ${`assessment:${assessment.id}:1`}`));
  await runAssessment(ctx.org.id, job.rows[0].payload, { adapters: sastDeps.adapters, minIntervalMs: 0 });
  return assessment.id;
}
const sastDeps = { adapters: new Map([["code.sast@1", createSastAdapter()]]), minIntervalMs: 0 };

async function scanSecrets(ctx: LoadedPrincipal, assetId: string) {
  const { assessment } = await launchAssessment(ctx, { assetId, idempotencyKey: `k-${randomUUID()}`, checkIds: ["code.secrets@1"] });
  const job = await withOrg(ctx.org.id, (tx) => tx.execute<{ payload: { assessmentId: string; token: string } }>(
    sql`SELECT payload FROM outbox WHERE business_key = ${`assessment:${assessment.id}:1`}`));
  await runAssessment(ctx.org.id, job.rows[0].payload, { adapters: new Map([["code.secrets@1", createSecretsAdapter()]]), minIntervalMs: 0 });
  return assessment.id;
}
const findingsOf = (orgId: string, assetId: string) => withOrg(orgId, (tx) => tx.select().from(findings).where(eq(findings.assetId, assetId)));
const assessmentRow = async (orgId: string, id: string) => withOrg(orgId, async (tx) => ({
  status: (await tx.execute<{ status: string }>(sql`SELECT status FROM assessments WHERE id = ${id}`)).rows[0].status,
  reasons: (await tx.execute<{ reason: string | null }>(sql`SELECT reason FROM check_runs WHERE assessment_id = ${id}`)).rows.map((r) => r.reason),
}));

run("repository assets and deps.osv (database)", () => {
  beforeAll(() => {
    root = mkdtempSync(path.join(tmpdir(), "ruya-repos-"));
    process.env.RUYA_LOCAL_REPO_ROOT = root;
  });
  afterAll(() => rmSync(root, { recursive: true, force: true }));

  it("adds a connected repository as an authorized asset without an ownership challenge", async () => {
    const { ctx, asset, created, integ } = await fixture();
    expect(created).toBe(true);
    expect(asset).toMatchObject({ kind: "repository", host: `repo:${integ.externalId}`, status: "verified", verifiedMethod: "repository_integration", repositoryIntegrationId: integ.id });
    // Adding it again is idempotent.
    expect((await addRepositoryAsset(ctx, integ.id)).created).toBe(false);
    await expect(startVerification(ctx, asset.id, "dns_txt")).rejects.toMatchObject({ code: "not_applicable" });
    // Only repository checks are offered for a repository, and host checks are not offered.
    const cat = await listCatalogue(ctx, "repository");
    expect(cat.map((d) => d.id)).toContain("deps.osv@1");
    expect(cat.map((d) => d.id)).not.toContain("http.security_headers@1");
    expect((await listCatalogue(ctx, "domain")).map((d) => d.id)).not.toContain("deps.osv@1");
  });

  it("raises a dependency finding, then resolves it as verified after the upgrade is committed", async () => {
    const { ctx, asset, repo } = await fixture();
    const osv = fakeOsv();
    const aid = await scan(ctx, asset.id, osv);
    expect((await assessmentRow(ctx.org.id, aid)).status).toBe("completed");
    // Only package names and versions went out, and only to api.osv.dev.
    expect(osv.calls.every((u) => u.startsWith("https://api.osv.dev/"))).toBe(true);

    const [f] = await findingsOf(ctx.org.id, asset.id);
    expect(f).toMatchObject({ checkKey: "deps.osv", status: "new", severity: expect.stringMatching(/critical|high/), location: "package-lock.json#lodash@4.17.15" });
    expect((f.evidence as { fixedVersion: string }).fixedVersion).toBe("4.17.19");

    // A second scan of the same commit does not duplicate the finding.
    await scan(ctx, asset.id);
    expect(await findingsOf(ctx.org.id, asset.id)).toHaveLength(1);

    bump(repo, "4.17.21");
    for (const k of ["triage", "confirm", "start_remediation", "mark_fix_applied"]) await transition(ctx, f.id, k);
    const { run: r } = await requestVerification(ctx, f.id, { idempotencyKey: `v-${randomUUID()}` });
    expect(await runVerification(ctx.org.id, { runId: r.id }, { adapters: new Map([["deps.osv@1", createOsvAdapter({ fetch: fakeOsv().fetch })]]), minIntervalMs: 0 })).toBe("completed:verified");
    expect((await findingsOf(ctx.org.id, asset.id))[0].status).toBe("resolved_verified");
  });

  it("does not resolve a finding when the re-test cannot reach OSV (fails closed)", async () => {
    const { ctx, asset, repo } = await fixture();
    await scan(ctx, asset.id);
    const [f] = await findingsOf(ctx.org.id, asset.id);
    bump(repo, "4.17.21");
    for (const k of ["triage", "confirm", "start_remediation", "mark_fix_applied"]) await transition(ctx, f.id, k);
    const { run: r } = await requestVerification(ctx, f.id, { idempotencyKey: `v-${randomUUID()}` });
    const down: FetchLike = async () => { throw new Error("ECONNREFUSED"); };
    const out = await runVerification(ctx.org.id, { runId: r.id }, { adapters: new Map([["deps.osv@1", createOsvAdapter({ fetch: down })]]), minIntervalMs: 0 });
    expect(out).not.toBe("completed:verified");
    expect((await findingsOf(ctx.org.id, asset.id))[0].status).toBe("fix_pending_verification");
  });

  it("errors instead of reporting clean when the repository cannot be read", async () => {
    const { ctx, asset, repo } = await fixture("4.17.21");
    rmSync(repo, { recursive: true, force: true });
    const aid = await scan(ctx, asset.id);
    const row = await assessmentRow(ctx.org.id, aid);
    expect(row.status).not.toBe("completed");
    expect(row.reasons).toContain("repository_unreadable");
  });

  it("lapses the repository asset when its connection is disabled, and refuses new scans", async () => {
    const { ctx, asset, integ } = await fixture();
    await disableIntegration(ctx, integ.id);
    const [a] = await withOrg(ctx.org.id, (tx) => tx.select().from(assets).where(eq(assets.id, asset.id)));
    expect(a.status).toBe("lapsed");
    await expect(launchAssessment(ctx, { assetId: asset.id, idempotencyKey: `k-${randomUUID()}`, checkIds: ["deps.osv@1"] })).rejects.toMatchObject({ status: expect.any(Number) });
  });

  it("finds a hard-coded key without storing it, and verifies its removal on re-test", async () => {
    const { ctx, asset, repo } = await fixture("4.17.21");
    const key = "AKIA" + "Q3EGRTZ7WJ5XN2LM"; // fake, assembled at runtime
    commitFile(repo, "config.js", `module.exports = { region: "eu-west-1", key: "${key}" };\n`, "add config");
    const aid = await scanSecrets(ctx, asset.id);
    expect((await assessmentRow(ctx.org.id, aid)).status).toBe("completed");
    const [f] = await findingsOf(ctx.org.id, asset.id);
    expect(f).toMatchObject({ checkKey: "code.secrets", status: "new", severity: "critical", location: "config.js" });
    expect(f.evidence).toMatchObject({ rule: "aws-access-key", line: 1, prefix: "AKIA", length: 20 });
    // The value itself is nowhere in what was stored for the finding or its occurrences.
    const stored = await withOrg(ctx.org.id, (tx) => tx.execute(sql`SELECT f.*, o.* FROM findings f LEFT JOIN finding_occurrences o ON o.finding_id = f.id WHERE f.id = ${f.id}`));
    expect(JSON.stringify(stored.rows)).not.toContain(key);
    const items = await withOrg(ctx.org.id, (tx) => tx.execute(sql`SELECT to_jsonb(e) AS e FROM evidence_items e`));
    expect(JSON.stringify(items.rows)).not.toContain(key);

    commitFile(repo, "config.js", `module.exports = { region: "eu-west-1", key: process.env.AWS_ACCESS_KEY_ID };\n`, "load key from env");
    for (const k of ["triage", "confirm", "start_remediation", "mark_fix_applied"]) await transition(ctx, f.id, k);
    const { run: r } = await requestVerification(ctx, f.id, { idempotencyKey: `v-${randomUUID()}` });
    expect(await runVerification(ctx.org.id, { runId: r.id }, { adapters: new Map([["code.secrets@1", createSecretsAdapter()]]), minIntervalMs: 0 })).toBe("completed:verified");
    expect((await findingsOf(ctx.org.id, asset.id))[0].status).toBe("resolved_verified");
  });

  it("flags a SQL injection pattern, keeps it open while unfixed, and verifies the fix on re-test", async () => {
    const { ctx, asset, repo } = await fixture("4.17.21");
    const vulnerable = "const db = require('./db');\nexports.get = (id) => db.query(`SELECT * FROM users WHERE id = ${id}`);\n";
    commitFile(repo, "users.js", vulnerable, "add users");
    const aid = await scanSast(ctx, asset.id);
    expect((await assessmentRow(ctx.org.id, aid)).status).toBe("completed");
    const [f] = await findingsOf(ctx.org.id, asset.id);
    expect(f).toMatchObject({ checkKey: "code.sast", status: "new", severity: "high", confidence: "suspected", location: "users.js" });
    expect(f.evidence).toMatchObject({ rule: "js-sql-template", cwe: "CWE-89", line: 2 });

    // Unrelated edits that move the line keep the same finding, so marking it fixed is rejected on re-test.
    commitFile(repo, "users.js", `// users\n${vulnerable}`, "add header");
    for (const k of ["triage", "confirm", "start_remediation", "mark_fix_applied"]) await transition(ctx, f.id, k);
    const { run: r } = await requestVerification(ctx, f.id, { idempotencyKey: `v-${randomUUID()}` });
    expect(await runVerification(ctx.org.id, { runId: r.id }, sastDeps)).toBe("completed:failed");
    expect((await findingsOf(ctx.org.id, asset.id))[0].status).toBe("reopened");

    commitFile(repo, "users.js", "const db = require('./db');\nexports.get = (id) => db.query('SELECT * FROM users WHERE id = $1', [id]);\n", "parameterize query");
    for (const k of ["start_remediation", "mark_fix_applied"]) await transition(ctx, f.id, k);
    const { run: r2 } = await requestVerification(ctx, f.id, { idempotencyKey: `v-${randomUUID()}` });
    expect(await runVerification(ctx.org.id, { runId: r2.id }, sastDeps)).toBe("completed:verified");
    expect((await findingsOf(ctx.org.id, asset.id))[0].status).toBe("resolved_verified");
  });
});
