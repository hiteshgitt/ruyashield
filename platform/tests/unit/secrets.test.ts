import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { fingerprint, normalizeResult, type CheckContext } from "@/server/assessments/checks";
import { createSecretsAdapter, entropy, isScannable, scanText } from "@/server/assessments/secrets";
import type { RepoSnapshot } from "@/server/remediation/repo";

// Fake credentials are assembled at runtime so this file never contains a string that looks like a real key.
const AWS = "AKIA" + "Q3EGRTZ7WJ5XN2LM";
const STRIPE = "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc";
const GH = "ghp_" + "R8fK2mQ9vX4pL7nT1wZ6yB3cD5hJ0sA2eG8u";
const PEM = ["-----BEGIN RSA PRIVATE KEY-----", "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun", "-----END RSA PRIVATE KEY-----"].join("\n");
const GENERIC = "q8Zr3Lp0Xv7Tn2Wk5Yb9";
const sha = (v: string) => createHash("sha256").update(v).digest("hex");

function repo(files: Record<string, string>, opts: { failList?: boolean; failRead?: string; tooLarge?: string } = {}): RepoSnapshot {
  return {
    externalId: "demo", commit: "c".repeat(40),
    list: async () => { if (opts.failList) throw new Error("git failed"); return Object.keys(files); },
    read: async (p) => {
      if (p === opts.failRead) throw new Error("read failed");
      if (p === opts.tooLarge) throw Object.assign(new Error("too big"), { code: "file_too_large" });
      if (!(p in files)) throw new Error("not_found");
      return files[p];
    },
  };
}
const ctx = (r?: RepoSnapshot) => ({ host: "repo:demo", repo: r } as unknown as CheckContext);
const run = async (files: Record<string, string>, opts = {}) => normalizeResult(await createSecretsAdapter().run(ctx(repo(files, opts))));

describe("scanText", () => {
  it("finds specific credential formats with the right severity and line", () => {
    const hits = scanText(`const a = 1;\nconst key = "${AWS}";\nstripe = '${STRIPE}'\n${PEM}\ntoken: ${GH}\n`);
    expect(hits.map((h) => [h.rule.id, h.rule.severity, h.line])).toEqual([
      ["aws-access-key", "critical", 2], ["stripe-live-key", "critical", 3], ["private-key", "high", 4], ["github-token", "high", 7],
    ]);
  });

  it("never returns the secret value, only prefix, length and hash", () => {
    const [h] = scanText(`k = "${AWS}"`);
    expect(h).toMatchObject({ prefix: "AKIA", length: 20, sha256: sha(AWS) });
    expect(JSON.stringify({ ...h, rule: h.rule.id })).not.toContain(AWS);
  });

  it("reports generic high-entropy secrets, but not placeholders, env lookups or low-entropy words", () => {
    expect(scanText(`API_KEY = "${GENERIC}"`).map((h) => h.rule.id)).toEqual(["generic-secret"]);
    expect(scanText(`password = "your-password-here-please"`)).toEqual([]);
    expect(scanText(`api_key = "\${process.env.API_KEY_VALUE}"`)).toEqual([]);
    expect(scanText(`secret = "aaaaaaaaaaaaaaaaaaaa"`)).toEqual([]);
    expect(scanText(`token_name = "user_session_token_name"`)).toEqual([]);
  });

  it("does not double-report a specific key that also looks like a generic assignment", () => {
    expect(scanText(`aws_access_key = "${AWS}"`).map((h) => h.rule.id)).toEqual(["aws-access-key"]);
  });

  it("honours an explicit allow marker on the line", () => {
    expect(scanText(`key = "${AWS}" // ruya:allow-secret test fixture`)).toEqual([]);
  });

  it("computes entropy", () => {
    expect(entropy("aaaa")).toBe(0);
    expect(entropy(GENERIC)).toBeGreaterThan(3.5);
  });
});

describe("isScannable", () => {
  it("skips vendored, lockfiles, binaries and minified bundles", () => {
    for (const p of ["node_modules/x/index.js", "vendor/a.php", "package-lock.json", "img/logo.png", "app.min.js", "dist/main.js"]) expect(isScannable(p)).toBe(false);
    for (const p of ["src/config.ts", ".env", "deploy/key.pem", "settings.py"]) expect(isScannable(p)).toBe(true);
  });
});

describe("code.secrets adapter", () => {
  it("produces stable, line-independent fingerprints and evidence without the secret", async () => {
    const r = await run({ "src/config.ts": `export const k = "${AWS}";\n`, "node_modules/x/a.js": `"${AWS}"`, "README.md": "nothing here" });
    expect(r.status).toBe("ok");
    if (r.status !== "ok") return;
    expect(r.findings).toHaveLength(1);
    const f = r.findings[0];
    expect(f).toMatchObject({ issueKey: `aws-access-key.${sha(AWS).slice(0, 12)}`, severity: "critical", location: "src/config.ts", confidence: "likely" });
    expect(f.evidence).toMatchObject({ rule: "aws-access-key", file: "src/config.ts", line: 1, prefix: "AKIA", length: 20, sha256: sha(AWS) });
    expect(f.remediation).toMatch(/^Rotate first, then remove/);
    expect(JSON.stringify(r)).not.toContain(AWS);
    expect(r.evidence).toMatchObject({ commit: "c".repeat(40), filesScanned: 2, filesExcluded: 1 });

    // Moving the secret down a few lines keeps the same fingerprint.
    const moved = await run({ "src/config.ts": `// header\n\n\nexport const k = "${AWS}";\n` });
    if (moved.status !== "ok") throw new Error("expected ok");
    expect(fingerprint("code.secrets", moved.findings[0].location, moved.findings[0].issueKey)).toBe(fingerprint("code.secrets", f.location, f.issueKey));
    expect(moved.findings[0].evidence.line).toBe(4);
  });

  it("collapses repeats of one value in a file into one finding with all lines", async () => {
    const r = await run({ "a.env": `A=${GH}\nB=${GH}\n` });
    if (r.status !== "ok") throw new Error("expected ok");
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].evidence).toMatchObject({ occurrences: 2, lines: [1, 2] });
  });

  it("marks generic findings as suspected medium", async () => {
    const r = await run({ "settings.py": `SECRET_KEY = "${GENERIC}"\n` });
    if (r.status !== "ok") throw new Error("expected ok");
    expect(r.findings[0]).toMatchObject({ severity: "medium", confidence: "suspected" });
  });

  it("returns ok with no findings for a clean repository", async () => {
    expect(await run({ "src/a.ts": "export const x = 1;\n" })).toMatchObject({ status: "ok", findings: [] });
  });

  it("skips oversized and binary files but says so", async () => {
    const r = await run({ "big.sql": "x", "blob.dat": `\u0000\u0001${AWS}`, "ok.ts": "1" }, { tooLarge: "big.sql" });
    expect(r).toMatchObject({ status: "ok", findings: [], evidence: { largeSkipped: ["big.sql"], binarySkipped: 1 } });
  });

  it("fails closed when the repository or a file cannot be read", async () => {
    expect(normalizeResult(await createSecretsAdapter().run(ctx(undefined)))).toMatchObject({ status: "error", reason: "no_repository_snapshot" });
    expect(await run({ "a.ts": "" }, { failList: true })).toMatchObject({ status: "error", reason: "repository_unreadable" });
    expect(await run({ "a.ts": `"${AWS}"`, "b.ts": "" }, { failRead: "b.ts" })).toMatchObject({ status: "error", reason: "file_unreadable", evidence: { file: "b.ts" } });
  });

  it("errors rather than truncating when there are too many secrets", async () => {
    const files = Object.fromEntries(Array.from({ length: 51 }, (_, i) => [`k${i}.ts`, `"${"AKIA" + String(i).padStart(2, "0") + "Q3EGRTZ7WJ5XN2"}"`]));
    expect(await run(files)).toMatchObject({ status: "error", reason: "too_many_secrets", evidence: { secrets: 51 } });
  });
});
