import { createHash } from "node:crypto";
import type { Severity } from "../db/schema";
import type { CheckAdapter, CheckResult, FindingCandidate } from "./checks";

/**
 * code.secrets (scanner M2): hard-coded credentials in the repository's default branch.
 *  - Native, offline rules (gitleaks-style). Reads a read-only snapshot; nothing is executed and nothing leaves the box.
 *  - Never tests whether a found key works: that would be credential use (class X).
 *  - Never stores the secret. Evidence holds the rule, file, line, the first 4 characters, the length and the SHA-256.
 *  - Fingerprints do not depend on line numbers: location = file, issueKey = rule + a short hash of the value, so an
 *    unrelated edit above the secret neither duplicates nor "resolves" the finding.
 *  - Fails closed: an unreadable file or too many findings is an error, never "no findings".
 *  - Working tree only. Removing a secret does not remove it from git history, which is why remediation says rotate first.
 */

export interface SecretRule {
  id: string;
  label: string;
  severity: Severity;
  /** Global regex. Group 1 (if present) is the secret value; otherwise the whole match. */
  re: RegExp;
  /** Generic rules are heuristics: reported as suspected, and only above an entropy threshold. */
  generic?: boolean;
}

export const RULES: readonly SecretRule[] = [
  { id: "aws-access-key", label: "AWS access key ID", severity: "critical", re: /\b((?:AKIA|ASIA)[0-9A-Z]{16})\b/g },
  { id: "aws-secret-key", label: "AWS secret access key", severity: "critical", re: /aws_?secret_?(?:access_?)?key["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])/gi },
  { id: "stripe-live-key", label: "Stripe live secret key", severity: "critical", re: /\b((?:sk|rk)_live_[A-Za-z0-9]{24,})\b/g },
  { id: "private-key", label: "Private key", severity: "high", re: /(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----[^]*?-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----)/g },
  { id: "github-token", label: "GitHub token", severity: "high", re: /\b(gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{82})\b/g },
  { id: "gitlab-token", label: "GitLab personal access token", severity: "high", re: /\b(glpat-[A-Za-z0-9_-]{20})(?![A-Za-z0-9_-])/g },
  { id: "slack-token", label: "Slack token", severity: "high", re: /\b(xox[baprs]-[A-Za-z0-9-]{10,})\b/g },
  { id: "slack-webhook", label: "Slack incoming webhook", severity: "high", re: /(https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9_]+\/B[A-Za-z0-9_]+\/[A-Za-z0-9_]+)/g },
  { id: "google-api-key", label: "Google API key", severity: "high", re: /\b(AIza[0-9A-Za-z_-]{35})(?![0-9A-Za-z_-])/g },
  { id: "openai-api-key", label: "OpenAI API key", severity: "high", re: /\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,})(?![A-Za-z0-9_-])/g },
  { id: "anthropic-api-key", label: "Anthropic API key", severity: "high", re: /\b(sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,})(?![A-Za-z0-9_-])/g },
  { id: "sendgrid-api-key", label: "SendGrid API key", severity: "high", re: /\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})(?![A-Za-z0-9_-])/g },
  { id: "npm-token", label: "npm access token", severity: "high", re: /\b(npm_[A-Za-z0-9]{36})\b/g },
  {
    id: "generic-secret", label: "Possible hard-coded secret", severity: "medium", generic: true,
    re: /(?:secret|token|passw(?:or)?d|pwd|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?key)[A-Za-z0-9_-]*["']?\s*(?::|=|=>)\s*["'`]([^"'`\s]{16,200})["'`]/gi,
  },
];

const MAX_FILES = 20_000;
const MAX_FINDINGS = 50;
/** Files above this are not source code we can usefully scan (bundles, dumps); they are listed as skipped. */
const MAX_FILE_BYTES = 1024 * 1024;
const MIN_ENTROPY = 3.5;
const VENDORED = /(^|\/)(node_modules|vendor|\.git|bower_components|dist|build|\.next)\//;
const LOCKFILE = /(^|\/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|Pipfile\.lock|Cargo\.lock|composer\.lock|Gemfile\.lock|go\.sum)$/;
const BINARY_EXT = /\.(png|jpe?g|gif|webp|ico|bmp|tiff?|pdf|zip|gz|tgz|bz2|xz|7z|rar|jar|war|class|so|dylib|dll|exe|bin|o|a|woff2?|ttf|otf|eot|mp[34]|mov|avi|wasm|pyc|sqlite|db)$/i;
const MINIFIED = /\.min\.(js|css)$/i;
/** Values that are obviously not real secrets: placeholders, templates, references to env vars. */
const PLACEHOLDER = /(example|sample|dummy|placeholder|changeme|change_me|your[_-]|xxxx|\*\*\*\*|<[^>]*>|\$\{|\{\{|process\.env|os\.environ|getenv|redacted)/i;
/** An explicit, reviewable opt-out on the line (also honours gitleaks' marker). */
const ALLOW_MARKER = /(ruya:allow-secret|gitleaks:allow)/;

export const isScannable = (p: string) => !VENDORED.test(p) && !LOCKFILE.test(p) && !BINARY_EXT.test(p) && !MINIFIED.test(p);

/** Shannon entropy in bits per character. */
export function entropy(s: string): number {
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const c of counts.values()) { const p = c / s.length; h -= p * Math.log2(p); }
  return h;
}

export interface SecretHit { rule: SecretRule; line: number; sha256: string; prefix: string; length: number }

/** All secrets in one file's text. The returned hits never contain the value itself. */
export function scanText(text: string): SecretHit[] {
  const lineStarts = [0];
  for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) lineStarts.push(i + 1);
  const lineAt = (off: number) => { let lo = 0, hi = lineStarts.length - 1; while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (lineStarts[mid] <= off) lo = mid; else hi = mid - 1; } return lo; };
  const lineText = (i: number) => text.slice(lineStarts[i], i + 1 < lineStarts.length ? lineStarts[i + 1] : text.length);

  const out: SecretHit[] = [];
  const claimed: [number, number][] = [];
  for (const rule of RULES) {
    rule.re.lastIndex = 0;
    for (const m of text.matchAll(rule.re)) {
      const value = m[1] ?? m[0];
      const start = m.index! + m[0].indexOf(value);
      const end = start + value.length;
      // A specific rule already reported this span; the generic rule must not report it twice.
      if (claimed.some(([s, e]) => start < e && end > s)) continue;
      const li = lineAt(start);
      if (ALLOW_MARKER.test(lineText(li))) continue;
      if (rule.generic && (PLACEHOLDER.test(value) || entropy(value) < MIN_ENTROPY || /^[a-z_.]+$/i.test(value))) continue;
      claimed.push([start, end]);
      out.push({ rule, line: li + 1, sha256: createHash("sha256").update(value).digest("hex"), prefix: value.slice(0, 4), length: value.length });
    }
  }
  return out;
}

const clip = (s: string, n: number) => (s.length > n ? `…${s.slice(s.length - n + 1)}` : s);

function remediationFor(rule: SecretRule): string {
  if (rule.generic) {
    return "Check whether this is a real credential. If it is: rotate it first (issue a new one and revoke this one), then move it to a secret store or environment variable and remove it from the code. Deleting the line does not un-leak it: it stays in git history. If it is not a secret, add `ruya:allow-secret` to the line.";
  }
  return `Rotate first, then remove. Revoke this ${rule.label} with its provider and issue a new one, update every place that uses it, then load it from a secret store or environment variable instead of the code. Deleting the line does not un-leak the secret: it remains in git history and in any clone, so a re-test that no longer sees it confirms removal, not rotation.`;
}

export function createSecretsAdapter(): CheckAdapter {
  return {
    id: "code.secrets@1", checkKey: "code.secrets", target: "repository",
    async run(ctx): Promise<CheckResult> {
      const repo = ctx.repo;
      if (!repo) return { status: "error", reason: "no_repository_snapshot", evidence: {} };
      const base = { commit: repo.commit, rules: RULES.length };
      let all: string[];
      try { all = await repo.list(); } catch { return { status: "error", reason: "repository_unreadable", evidence: base }; }
      const paths = all.filter(isScannable).sort();
      if (paths.length > MAX_FILES) return { status: "error", reason: "too_many_files", evidence: { ...base, files: paths.length } };

      // One finding per (file, rule, value); repeated occurrences of the same value in a file count, not multiply.
      const byKey = new Map<string, { path: string; hit: SecretHit; lines: number[] }>();
      const skippedLarge: string[] = [];
      let binary = 0;
      for (const p of paths) {
        let text: string;
        try { text = await repo.read(p); } catch (e) {
          if ((e as { code?: string }).code === "file_too_large") { skippedLarge.push(p); continue; }
          return { status: "error", reason: "file_unreadable", evidence: { ...base, file: clip(p, 200) } };
        }
        if (Buffer.byteLength(text) > MAX_FILE_BYTES) { skippedLarge.push(p); continue; }
        if (text.slice(0, 8000).includes("\u0000")) { binary++; continue; }
        for (const hit of scanText(text)) {
          const key = `${p}|${hit.rule.id}|${hit.sha256}`;
          const cur = byKey.get(key);
          if (cur) cur.lines.push(hit.line); else byKey.set(key, { path: p, hit, lines: [hit.line] });
        }
      }
      const summary = { ...base, filesScanned: paths.length - skippedLarge.length - binary, filesExcluded: all.length - paths.length, binarySkipped: binary, largeSkipped: skippedLarge.slice(0, 20) };
      if (byKey.size > MAX_FINDINGS) return { status: "error", reason: "too_many_secrets", evidence: { ...summary, secrets: byKey.size } };

      const findings: FindingCandidate[] = [...byKey.values()].map(({ path, hit, lines }) => ({
        issueKey: `${hit.rule.id}.${hit.sha256.slice(0, 12)}`,
        title: clip(`${hit.rule.label} in ${path}`, 200),
        severity: hit.rule.severity,
        confidence: hit.rule.generic ? "suspected" : "likely",
        location: clip(path, 300),
        evidence: { rule: hit.rule.id, file: path, line: lines[0], lines: lines.slice(0, 20), occurrences: lines.length, prefix: hit.prefix, length: hit.length, sha256: hit.sha256, commit: repo.commit },
        remediation: remediationFor(hit.rule),
      }));
      return { status: "ok", findings, evidence: { ...summary, secrets: findings.length } };
    },
  };
}
