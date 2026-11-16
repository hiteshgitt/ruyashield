import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: { alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) } },
  test: {
    include: ["tests/**/*.test.ts"],
    environment: "node",
    // DB suites share one Postgres; run files one at a time so audit-chain assertions stay deterministic.
    fileParallelism: false,
    // Suites exercise Pro features (reports, exports); tests/db/org-plans.test.ts covers Free explicitly.
    env: { RUYA_DEFAULT_ORG_PLAN: "pro" },
  },
});
