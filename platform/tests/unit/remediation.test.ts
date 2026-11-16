import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { runTests, type CommandRunner } from "@/server/remediation/sandbox";
import { signWebhook } from "@/server/remediation/integrations";

const runner = (codes: (number | null | "timeout")[]): CommandRunner => {
  let i = 0;
  return async (_dir, argv) => {
    const c = codes[i++];
    return c === "timeout" ? { argv, exitCode: null, timedOut: true, output: "", truncated: false } : { argv, exitCode: c, timedOut: false, output: "", truncated: false };
  };
};

describe("sandbox test runner", () => {
  it("passes only when every command exits 0", async () => {
    expect((await runTests("/x", [["a"], ["b"]], runner([0, 0]))).result).toBe("test_passed");
    expect(await runTests("/x", [["a"], ["b"]], runner([0, 2]))).toMatchObject({ result: "test_failed", reason: "exit 2: b", exitCode: 2 });
  });
  it("never reports a timeout, a sandbox error or no tests as passed", async () => {
    expect((await runTests("/x", [["a"]], runner(["timeout"]))).result).toBe("timeout");
    expect((await runTests("/x", [["a"]], runner([null]))).result).toBe("error");
    expect(await runTests("/x", [], runner([]))).toMatchObject({ result: "error", reason: "no_test_commands" });
  });
  it("stops at the first failure", async () => {
    const out = await runTests("/x", [["a"], ["b"], ["c"]], runner([1, 0, 0]));
    expect(out.commands).toHaveLength(1);
  });
});

describe("repository webhook signature", () => {
  const A = "a".repeat(32), B = "b".repeat(32);
  it("refuses to sign without a strong secret", () => {
    expect(() => signWebhook("i1", "100", "{}", "short")).toThrow();
  });
  it("depends on the integration, timestamp, body and secret", () => {
    const s = signWebhook("i1", "100", "{}", A);
    expect(s).toMatch(/[0-9a-f]{64}/);
    expect(signWebhook("i1", "100", "{}", A)).toBe(s);
    expect(signWebhook("i2", "100", "{}", A)).not.toBe(s);
    expect(signWebhook("i1", "101", "{}", A)).not.toBe(s);
    expect(signWebhook("i1", "100", "{ }", A)).not.toBe(s);
    expect(signWebhook("i1", "100", "{}", B)).not.toBe(s);
  });
});

describe("RuyaShield never merges (static)", () => {
  // The repository adapter may open a branch; nothing may merge, push to the default branch or force-push.
  const files = (d: string): string[] => readdirSync(d).flatMap((n) => { const p = path.join(d, n); return statSync(p).isDirectory() ? files(p) : [p]; });
  const src = files(path.join(__dirname, "../../src")).filter((f) => /\.(ts|tsx|mts)$/.test(f));
  it("has no merge, rebase or force-push git calls", () => {
    for (const f of src) {
      const s = readFileSync(f, "utf8");
      expect(s, f).not.toMatch(/["'`](merge|rebase|cherry-pick)["'`]/);
      expect(s, f).not.toMatch(/--force\b|["'`]-f["'`]\s*[,\]]/);
    }
  });
});
