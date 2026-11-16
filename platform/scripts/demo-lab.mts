// Dev-only demo lab: gives a user an org with two deliberately vulnerable, locally hosted assets and scans them.
//  - Domain asset "demo-shop.localhost" (served by scripts/demo-target.mts; needs EGRESS_ALLOW_PRIVATE=true and
//    EGRESS_DEV_PORT_MAP=443:8443,80:8080 in the worker's env). Inserted as verified directly: .localhost names
//    cannot pass real ownership verification, and this never runs in production.
//  - Repository asset "demo-vuln-shop" (a git repo under RUYA_LOCAL_REPO_ROOT) with an old lodash, a fake
//    GitHub-token-shaped canary string and two injection patterns.
// The running worker executes the queued assessments.
// Run: npx tsx --env-file=.env.local scripts/demo-lab.mts [email]
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { eq } from "drizzle-orm";

if (process.env.NODE_ENV === "production") throw new Error("demo-lab is dev only");
const { db, withOrg } = await import("../src/server/db/client");
const { assets, users } = await import("../src/server/db/schema");
const { createOrg, listUserOrgs } = await import("../src/server/orgs/orgs");
const { loadPrincipal } = await import("../src/server/principal");
const { launchAssessment } = await import("../src/server/assessments/assessments");
const { ADAPTERS } = await import("../src/server/assessments/checks");
const { addRepositoryAsset } = await import("../src/server/assets/assets");
const { createIntegration } = await import("../src/server/remediation/integrations");

const email = process.argv[2] ?? "hiteshgml@gmail.com";
const [user] = await db.select().from(users).where(eq(users.email, email));
if (!user) throw new Error(`no user ${email}: sign in once first`);
const session = { idHash: "x", userId: user.id, email, displayName: user.displayName ?? "Demo", activeOrgId: null, mfa: true, amr: ["mfa"], authTime: new Date() };

// Reuse the user's "Demo Lab" org if it already exists (user_orgs() is the RLS-safe lookup).
const existing = (await listUserOrgs(user.id)).find((o) => o.name === "Demo Lab");
const orgId = existing?.id ?? (await createOrg(session, { name: "Demo Lab" })).id;
const ctx = (await loadPrincipal(session, orgId))!;

// 1. Domain asset.
const HOST = "demo-shop.localhost";
let [site] = await withOrg(orgId, (tx) => tx.select().from(assets).where(eq(assets.host, HOST)));
site ??= (await withOrg(orgId, (tx) => tx.insert(assets).values({
  orgId, host: HOST, displayName: "Demo Shop (local)", environment: "production", createdBy: user.id, status: "verified",
}).returning()))[0];

// 2. Repository asset.
const root = process.env.RUYA_LOCAL_REPO_ROOT!;
const name = "demo-vuln-shop";
const repo = path.join(root, name);
if (!existsSync(repo)) {
  mkdirSync(path.join(repo, "src"), { recursive: true });
  writeFileSync(path.join(repo, "package.json"), JSON.stringify({ name, version: "1.0.0", dependencies: { lodash: "4.17.15" } }, null, 2));
  writeFileSync(path.join(repo, "package-lock.json"), JSON.stringify({
    name, version: "1.0.0", lockfileVersion: 3, requires: true,
    packages: { "": { name, version: "1.0.0", dependencies: { lodash: "4.17.15" } }, "node_modules/lodash": { version: "4.17.15", resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz" } },
  }, null, 2));
  // Fake canary token: GitHub-token shaped so the scanner fires, not a real credential.
  writeFileSync(path.join(repo, "src", "config.js"), `module.exports = {\n  githubToken: "ghp_${"D3m0CanaryNotARealToken".padEnd(36, "x")}",\n};\n`);
  writeFileSync(path.join(repo, "src", "orders.js"), [
    'const { exec } = require("node:child_process");',
    "async function findOrder(db, req) {",
    "  return db.query(`SELECT * FROM orders WHERE id = ${req.query.id}`);",
    "}",
    "function exportInvoice(req) {",
    "  exec(\"wkhtmltopdf \" + req.query.url + \" /tmp/invoice.pdf\");",
    "}",
    "module.exports = { findOrder, exportInvoice };",
    "",
  ].join("\n"));
  const git = (...a: string[]) => execFileSync("git", ["-c", "user.name=demo", "-c", "user.email=demo@demo.invalid", "-c", "commit.gpgsign=false", ...a], { cwd: repo, stdio: "pipe" });
  execFileSync("git", ["init", "-q", "-b", "main", repo]);
  git("add", ".");
  git("commit", "-qm", "demo shop with known issues");
}
let [repoAsset] = await withOrg(orgId, (tx) => tx.select().from(assets).where(eq(assets.host, `repo:${name}`)));
if (!repoAsset) {
  const integ = await createIntegration(ctx, { name: "Demo Vuln Shop", externalId: name, defaultBranch: "main", testCommands: [] });
  repoAsset = (await addRepositoryAsset(ctx, integ.id)).asset;
}

// 3. Launch: every enabled check that fits each asset (net.* ports need the A2 opt-in, so they are skipped).
const pick = (target: string) => [...ADAPTERS.values()].filter((a) => (a.target ?? "host") === target && !a.id.startsWith("net.") && !a.id.startsWith("x.")).map((a) => a.id);
for (const [a, ids] of [[site, pick("host")], [repoAsset, pick("repository")]] as const) {
  const { assessment } = await launchAssessment(ctx, { assetId: a.id, idempotencyKey: `demo-${randomUUID()}`, checkIds: ids });
  console.log(`queued ${assessment.id} for ${a.host}: ${ids.join(", ")}`);
}
console.log(`org ${orgId} ready; the worker will run the scans.`);
process.exit(0);
