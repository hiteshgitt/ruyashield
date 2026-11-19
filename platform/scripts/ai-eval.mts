// Runs the AI golden-case evaluation for each prompt and records the result. With --promote, a passing run releases
// that prompt version for that provider/model (the gateway refuses unreleased combinations).
//   npm run ai:eval -- --provider fixture [--promote]
// The provider defaults to RUYA_AI_PROVIDER. "openai" sends the golden cases (synthetic data only) to the
// configured endpoint and costs money; it is never chosen implicitly.
import { Client } from "pg";
import { GOLDEN, runEval } from "../src/server/ai/eval";
import { PROMPTS, templateSha256 } from "../src/server/ai/prompts";
import { getProvider } from "../src/server/ai/providers";
import type { AiUseCase } from "../src/server/db/schema";

const args = process.argv.slice(2);
const flag = (n: string) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : undefined; };
const providerName = flag("--provider") ?? process.env.RUYA_AI_PROVIDER ?? "disabled";
const promote = args.includes("--promote");
// --only explain|remediation|chat runs one prompt; --pause <ms> waits between cases (free tiers' per-minute limits).
const only = flag("--only");
const pauseMs = Number(flag("--pause") ?? 0) || 0;
const provider = getProvider({ ...process.env, RUYA_AI_PROVIDER: providerName });
if (!provider) { console.error(`No provider "${providerName}" is configured.`); process.exit(2); }

const url = process.env.DATABASE_OWNER_URL;
if (!url) throw new Error("DATABASE_OWNER_URL is required");
const client = new Client({ connectionString: url });
await client.connect();
let failed = false;
try {
  for (const useCase of Object.keys(PROMPTS) as AiUseCase[]) {
    if (only && useCase !== only) continue;
    const p = PROMPTS[useCase];
    const report = await runEval(provider, GOLDEN.filter((c) => c.useCase === useCase), { pauseMs });
    const sha = templateSha256(p);
    const run = await client.query<{ id: string }>(
      `INSERT INTO ai_eval_runs (prompt_id, prompt_version, template_sha256, provider, model, metrics, thresholds, passed)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
      [p.id, p.version, sha, provider.name, provider.model, JSON.stringify(report.metrics), JSON.stringify(report.thresholds), report.passed]);
    console.log(`${p.id}@${p.version} ${provider.name}/${provider.model}: ${report.passed ? "PASS" : "FAIL"} run=${run.rows[0].id}`);
    console.log("  " + JSON.stringify(report.metrics));
    for (const c of report.cases) if (c.error) console.log(`  case ${c.name}: ${c.error}`);
    if (!report.passed) { failed = true; console.log(`  failed thresholds: ${report.failures.join(", ")}`); continue; }
    if (promote) {
      await client.query(
        `INSERT INTO ai_prompt_releases (prompt_id, prompt_version, template_sha256, provider, model, eval_run_id) VALUES ($1,$2,$3,$4,$5,$6)
         ON CONFLICT (prompt_id, prompt_version, provider, model) DO UPDATE SET template_sha256 = EXCLUDED.template_sha256, eval_run_id = EXCLUDED.eval_run_id, released_at = now()`,
        [p.id, p.version, sha, provider.name, provider.model, run.rows[0].id]);
      console.log("  released");
    }
  }
} finally {
  await client.end();
}
process.exit(failed ? 1 : 0);
