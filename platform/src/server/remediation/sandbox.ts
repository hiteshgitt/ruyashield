import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import type { SandboxResult } from "../db/schema";

// Patch test sandbox (RS-REM-002). Each test command runs with bubblewrap in fresh user/pid/net/ipc/uts namespaces,
// no network, a cleared environment, a read-only system and only the patched copy writable, under prlimit
// resource caps and a wall-clock timeout. This is process isolation on the worker host, not a microVM; the label
// recorded with each run says exactly that, and production should replace it with VM-level isolation.
// RLIMIT_NPROC is per host user (it counted the worker's own processes), so there is no process-count cap here;
// that needs cgroups, which this dev isolation does not use.

export const ISOLATION_LABEL = "bwrap-local (user/pid/net/ipc/uts namespaces, no network, read-only system; not a microVM)";
export const SANDBOX_LIMITS = { timeoutMs: 120_000, addressSpaceBytes: 8 * 1024 * 1024 * 1024, maxFileBytes: 64 * 1024 * 1024, maxLogBytes: 64 * 1024 };
export type SandboxLimits = typeof SANDBOX_LIMITS;

export interface CommandResult { argv: string[]; exitCode: number | null; timedOut: boolean; output: string; truncated: boolean }
export interface SandboxOutcome { result: SandboxResult; reason: string | null; exitCode: number | null; commands: CommandResult[] }

/** Runs one command inside the sandbox. Injectable so tests do not need bubblewrap. */
export type CommandRunner = (dir: string, argv: string[], limits: SandboxLimits) => Promise<CommandResult>;

const BWRAP = "/usr/bin/bwrap";
const PRLIMIT = "/usr/bin/prlimit";

export function sandboxAvailable(): boolean {
  return existsSync(BWRAP) && existsSync(PRLIMIT);
}

function bwrapArgs(dir: string, argv: string[]): string[] {
  const nodeDir = path.dirname(process.execPath); // test commands may need node; bound read-only
  const binds = ["--ro-bind", "/usr", "/usr"];
  for (const l of ["bin", "lib", "lib64", "sbin"]) binds.push("--symlink", `usr/${l}`, `/${l}`);
  if (existsSync("/etc/alternatives")) binds.push("--ro-bind", "/etc/alternatives", "/etc/alternatives");
  if (!nodeDir.startsWith("/usr/")) binds.push("--ro-bind", nodeDir, "/opt/node/bin");
  return [
    "--unshare-all", "--die-with-parent", "--new-session", "--clearenv",
    "--setenv", "PATH", "/opt/node/bin:/usr/bin:/bin", "--setenv", "HOME", "/tmp", "--setenv", "CI", "1",
    ...binds, "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
    "--bind", dir, "/work", "--chdir", "/work", "--", ...argv,
  ];
}

export const bwrapRunner: CommandRunner = (dir, argv, limits) => new Promise((resolve) => {
  const args = [
    `--as=${limits.addressSpaceBytes}`, `--fsize=${limits.maxFileBytes}`, "--core=0",
    BWRAP, ...bwrapArgs(dir, argv),
  ];
  const child = spawn(PRLIMIT, args, { stdio: ["ignore", "pipe", "pipe"], detached: true, env: {} as NodeJS.ProcessEnv });
  let output = "";
  let truncated = false;
  const take = (b: Buffer) => {
    if (output.length >= limits.maxLogBytes) { truncated = true; return; }
    output += b.toString("utf8");
    if (output.length > limits.maxLogBytes) { output = output.slice(0, limits.maxLogBytes); truncated = true; }
  };
  child.stdout.on("data", take);
  child.stderr.on("data", take);
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    try { process.kill(-child.pid!, "SIGKILL"); } catch { /* already gone */ }
  }, limits.timeoutMs);
  child.on("error", (e) => { clearTimeout(timer); resolve({ argv, exitCode: null, timedOut, output: `sandbox failed to start: ${e.message}`, truncated }); });
  child.on("close", (code) => { clearTimeout(timer); resolve({ argv, exitCode: code, timedOut, output, truncated }); });
});

/** Runs the snapshot of test commands in order and stops at the first failure. Only all-zero exits pass. */
export async function runTests(dir: string, commands: string[][], runner: CommandRunner = bwrapRunner, limits: SandboxLimits = SANDBOX_LIMITS): Promise<SandboxOutcome> {
  if (!commands.length) return { result: "error", reason: "no_test_commands", exitCode: null, commands: [] };
  const out: CommandResult[] = [];
  for (const argv of commands) {
    const r = await runner(dir, argv, limits);
    out.push(r);
    if (r.timedOut) return { result: "timeout", reason: `timeout: ${argv.join(" ")}`, exitCode: r.exitCode, commands: out };
    if (r.exitCode === null) return { result: "error", reason: "sandbox_error", exitCode: null, commands: out };
    if (r.exitCode !== 0) return { result: "test_failed", reason: `exit ${r.exitCode}: ${argv.join(" ")}`, exitCode: r.exitCode, commands: out };
  }
  return { result: "test_passed", reason: null, exitCode: 0, commands: out };
}
