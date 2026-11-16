import { createHash } from "node:crypto";
import path from "node:path";
import type { Confidence, Severity } from "../db/schema";
import type { CheckAdapter, CheckResult, FindingCandidate } from "./checks";
import { isDockerfile } from "./container";
import { maskSnippet } from "./sast";

/**
 * code.iac (class P, repository): misconfigurations in infrastructure-as-code at the default branch.
 *  - Terraform (*.tf), Kubernetes manifests (YAML with apiVersion + kind), Docker Compose files, Dockerfiles and
 *    GitHub Actions workflows. Native line rules; nothing is executed, rendered or sent anywhere.
 *  - Test, example and vendored directories are skipped: they deliberately hold unsafe configs.
 *  - Opt out per line with a comment containing ruya:ignore, tfsec:ignore, checkov:skip or kics-scan ignore.
 *  - Fingerprints hash the rule and the normalized line, never the line number, so moving code keeps the finding.
 *  - Evidence snippets have string literals masked; secret-bearing rules store no snippet at all.
 *  - Fails closed: an unreadable repository or file, or more findings than can be reported, is an error.
 */

export type IacKind = "terraform" | "kubernetes" | "compose" | "dockerfile" | "workflow";

export interface IacRule {
  id: string; kinds: readonly IacKind[]; re: RegExp; severity: Severity; confidence: Confidence; title: string; fix: string;
  /** For secret-shaped rules: never keep a snippet. */
  noSnippet?: boolean;
  /** Extra condition on the surrounding lines (index i in lines). */
  context?: (lines: string[], i: number) => boolean;
}

const VENDORED = /(^|\/)(node_modules|vendor|\.git|bower_components|third_party|\.terraform)\//;
const TEST_PATH = /(^|\/)(tests?|__tests__|spec|specs|fixtures?|testdata|e2e|examples?|samples?)\//i;
const ALLOW = /(ruya:ignore|tfsec:ignore|checkov:skip|kics-scan ignore|nosemgrep)/i;
const MAX_FILES = 5_000;
const MAX_FILE_BYTES = 512 * 1024;
const MAX_FINDINGS = 300;
const MAX_LINE = 2000;

const SENSITIVE_PORTS = [22, 23, 3389, 3306, 5432, 1433, 1521, 27017, 6379, 9200, 5984, 11211, 2375, 2376, 5900, 9000];
const DB_PORTS = "3306|5432|6379|27017|9200|11211|1433|1521|5984|2375";

/** Is the 0.0.0.0/0 rule on this line part of an ingress rule that reaches a sensitive port? Looks at the enclosing block. */
function openSensitiveIngress(lines: string[], i: number): boolean {
  const from = Math.max(0, i - 12), to = Math.min(lines.length, i + 12);
  // Clip the window to the enclosing block: stop at a line that opens a new resource.
  let a = i, b = i;
  while (a > from && !/^\s*(resource|module|data)\s+"/.test(lines[a])) a--;
  while (b < to - 1 && !/^\s*(resource|module|data)\s+"/.test(lines[b + 1])) b++;
  const block = lines.slice(a, b + 1).join("\n");
  const near = lines.slice(Math.max(a, i - 8), Math.min(b + 1, i + 9)).join("\n");
  if (/\begress\b/.test(near) && !/\bingress\b/.test(near)) return false;
  if (/protocol\s*=\s*"(-1|all)"/i.test(near)) return true;
  const num = (k: string) => { const m = new RegExp(`\\b${k}\\s*=\\s*"?(\\d+)`).exec(near) ?? new RegExp(`\\b${k}\\s*=\\s*"?(\\d+)`).exec(block); return m ? Number(m[1]) : null; };
  const lo = num("from_port"), hi = num("to_port");
  if (lo !== null && hi !== null) return SENSITIVE_PORTS.some((p) => p >= lo && p <= hi);
  // Azure NSG style.
  const m = /destination_port_ranges?\s*=\s*\[?\s*"([^"]+)"/.exec(near);
  if (m) {
    if (m[1] === "*") return true;
    const [x, y] = m[1].split("-").map(Number);
    return SENSITIVE_PORTS.some((p) => p >= x && p <= (y || x));
  }
  return false;
}

export const IAC_RULES: readonly IacRule[] = [
  // ---- Terraform ----
  { id: "tf.open_ingress", kinds: ["terraform"], re: /(cidr_blocks|source_address_prefix(es)?|cidr_ipv4|cidr_ipv6|source_ranges)\s*=\s*\[?\s*"(0\.0\.0\.0\/0|::\/0|\*|Internet)"/, context: openSensitiveIngress,
    severity: "high", confidence: "likely", title: "Admin or database port open to the whole internet",
    fix: "Restrict the source to your office/VPN ranges or a bastion security group. SSH, RDP and database ports open to 0.0.0.0/0 are scanned and attacked within minutes." },
  { id: "tf.public_acl", kinds: ["terraform"], re: /\bacl\s*=\s*"(public-read|public-read-write|authenticated-read)"/, severity: "high", confidence: "confirmed",
    title: "Storage bucket ACL makes objects public", fix: "Use acl = \"private\" (or drop the ACL and use bucket ownership controls) and serve public files through a CDN with origin access control." },
  { id: "tf.public_access_block_off", kinds: ["terraform"], re: /\b(block_public_acls|block_public_policy|ignore_public_acls|restrict_public_buckets)\s*=\s*false/, severity: "medium", confidence: "confirmed",
    title: "S3 public access block is switched off", fix: "Set all four public-access-block settings to true unless the bucket is intentionally public." },
  { id: "tf.db_public", kinds: ["terraform"], re: /\bpublicly_accessible\s*=\s*true/, severity: "high", confidence: "confirmed",
    title: "Database instance is publicly accessible", fix: "Set publicly_accessible = false and reach the database from inside the VPC (application subnets, bastion or VPN)." },
  { id: "tf.encryption_off", kinds: ["terraform"], re: /\b(storage_encrypted|encrypted|encryption_enabled|enable_encryption|kms_encryption_enabled)\s*=\s*false/, severity: "medium", confidence: "confirmed",
    title: "Encryption at rest is disabled", fix: "Enable encryption at rest (it is free on most providers) so disks, snapshots and backups are unreadable if copied." },
  { id: "tf.iam_wildcard", kinds: ["terraform"], re: /("Action"\s*:\s*"\*"|\bactions\s*=\s*\[\s*"\*"\s*\])/, severity: "medium", confidence: "likely",
    title: "IAM policy grants every action (*)", fix: "List only the actions this role needs. A wildcard turns any leak of these credentials into full account control." },
  { id: "tf.hardcoded_password", kinds: ["terraform"], re: /\b(password|master_password|admin_password|secret_key|access_key|client_secret)\s*=\s*"(?!\$\{)[^"\s]{4,}"/i, severity: "high", confidence: "likely", noSnippet: true,
    title: "Credential written directly in Terraform", fix: "Move it to a secrets manager or a sensitive variable supplied at apply time, rotate the value (it is in git history), and keep state files encrypted." },
  { id: "tf.http_only", kinds: ["terraform"], re: /\b(protocol\s*=\s*"HTTP"\s*$|viewer_protocol_policy\s*=\s*"allow-all")/, severity: "low", confidence: "suspected",
    title: "Listener or CDN allows plain HTTP", fix: "Redirect HTTP to HTTPS (viewer_protocol_policy = \"redirect-to-https\", or an HTTP listener whose default action redirects)." },

  // ---- Kubernetes ----
  { id: "k8s.privileged", kinds: ["kubernetes"], re: /^\s*privileged:\s*true\b/, severity: "high", confidence: "confirmed",
    title: "Container runs privileged", fix: "Remove privileged: true. A privileged container has full access to the node and can escape to it." },
  { id: "k8s.host_namespace", kinds: ["kubernetes"], re: /^\s*host(Network|PID|IPC):\s*true\b/, severity: "high", confidence: "confirmed",
    title: "Pod shares the node's network/process namespace", fix: "Remove hostNetwork/hostPID/hostIPC unless this is a node agent that needs it." },
  { id: "k8s.docker_sock", kinds: ["kubernetes", "compose"], re: /\/var\/run\/docker\.sock|\/run\/containerd\/containerd\.sock/, severity: "high", confidence: "confirmed",
    title: "Container runtime socket is mounted into a container", fix: "Do not mount the Docker/containerd socket. Anything that can reach it controls the host as root." },
  { id: "k8s.host_path", kinds: ["kubernetes"], re: /^\s*hostPath:\s*$/, severity: "medium", confidence: "likely",
    title: "Pod mounts a path from the node (hostPath)", fix: "Use a PersistentVolume or emptyDir instead. hostPath lets the container read or change node files." },
  { id: "k8s.priv_escalation", kinds: ["kubernetes"], re: /^\s*allowPrivilegeEscalation:\s*true\b/, severity: "medium", confidence: "confirmed",
    title: "Privilege escalation is allowed", fix: "Set allowPrivilegeEscalation: false in the container securityContext." },
  { id: "k8s.run_as_root", kinds: ["kubernetes"], re: /^\s*(runAsUser:\s*0\b|runAsNonRoot:\s*false\b)/, severity: "medium", confidence: "confirmed",
    title: "Container is configured to run as root", fix: "Set runAsNonRoot: true and a non-zero runAsUser, and build the image with a non-root USER." },
  { id: "k8s.dangerous_caps", kinds: ["kubernetes"], re: /^\s*(-\s*|add:\s*\[.*)["']?(SYS_ADMIN|NET_ADMIN|SYS_PTRACE|ALL)["']?/, severity: "high", confidence: "likely",
    context: (l, i) => l.slice(Math.max(0, i - 4), i + 1).some((x) => /\badd:/.test(x)),
    title: "Container adds a dangerous Linux capability", fix: "Drop ALL capabilities and add back only narrow ones that are really needed (e.g. NET_BIND_SERVICE)." },

  // ---- Docker Compose ----
  { id: "compose.privileged", kinds: ["compose"], re: /^\s*privileged:\s*["']?true\b/, severity: "high", confidence: "confirmed",
    title: "Service runs privileged", fix: "Remove privileged: true. A privileged container can take over the host." },
  { id: "compose.host_namespace", kinds: ["compose"], re: /^\s*(network_mode|pid|ipc):\s*["']?host\b/, severity: "medium", confidence: "confirmed",
    title: "Service shares the host's network/process namespace", fix: "Use the default bridge network and published ports instead of host mode." },
  { id: "compose.db_port_public", kinds: ["compose"], re: new RegExp(`^\\s*-\\s*["']?(?:0\\.0\\.0\\.0:)?\\d+:(${DB_PORTS})(/tcp)?["']?\\s*$`), severity: "medium", confidence: "likely",
    title: "Database or admin port published on all interfaces", fix: "Bind it to localhost (\"127.0.0.1:5432:5432\") or remove the ports entry and reach it over the compose network. Docker port publishing bypasses ufw/iptables rules." },

  // ---- Dockerfile ----
  { id: "docker.curl_pipe_shell", kinds: ["dockerfile"], re: /\b(curl|wget)\b[^#|]*\|\s*(sudo\s+)?(ba|z|da)?sh\b/, severity: "medium", confidence: "likely",
    title: "Image build pipes a download straight into a shell", fix: "Download to a file, verify its checksum or signature, then run it. Otherwise a compromised server changes what gets built." },
  { id: "docker.add_url", kinds: ["dockerfile"], re: /^\s*ADD\s+(--\S+\s+)*https?:\/\//i, severity: "low", confidence: "confirmed",
    title: "ADD downloads from a URL without verification", fix: "Use ADD --checksum=sha256:… or RUN curl with a checksum check." },
  { id: "docker.user_root", kinds: ["dockerfile"], re: /^\s*USER\s+(root|0)(:\S*)?\s*$/i, severity: "medium", confidence: "likely",
    context: (l, i) => !l.slice(i + 1).some((x) => /^\s*USER\s+/i.test(x)),
    title: "Image switches to root as its final user", fix: "End the Dockerfile with USER <non-root user> so a compromised app does not run as root in the container." },
  { id: "docker.secret_in_env", kinds: ["dockerfile"], re: /^\s*(ENV|ARG)\s+\S*(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_KEY)\S*(\s*=\s*|\s+)\S+/i, severity: "medium", confidence: "likely", noSnippet: true,
    title: "Secret set with ENV/ARG in the image", fix: "ENV and ARG values are baked into image layers and history. Use build secrets (RUN --mount=type=secret) or inject at runtime, and rotate the value." },

  // ---- GitHub Actions ----
  { id: "ci.script_injection", kinds: ["workflow"], re: /\$\{\{\s*github\.(event\.(issue|pull_request|comment|review|review_comment|discussion|pages|commits|head_commit)[\w.\[\]*]*\.(title|body|name|message|ref|label|email|head_ref|default_branch)|head_ref)\s*\}\}/,
    severity: "high", confidence: "likely", title: "Workflow puts attacker-controlled text into a script",
    context: (l, i) => l.slice(Math.max(0, i - 6), i + 1).some((x) => /^\s*(-\s*)?(run|script):/.test(x)),
    fix: "Anyone opening an issue or PR controls this text, so they can run commands with the workflow's token. Pass it through an env: variable and use \"$VAR\" in the script instead of ${{ }}." },
  { id: "ci.pull_request_target", kinds: ["workflow"], re: /^\s*(-\s*)?pull_request_target\s*:?\s*$|^\s*on:\s*\[?.*\bpull_request_target\b/, severity: "medium", confidence: "suspected",
    title: "Workflow runs on pull_request_target", fix: "pull_request_target runs with secrets and a write token. Never check out or build the PR's code in it; use pull_request for builds." },
];

// ---------- file classification ----------

export function iacKind(p: string, head: string): IacKind | null {
  if (VENDORED.test(p) || TEST_PATH.test(p)) return null;
  const base = path.posix.basename(p).toLowerCase();
  if (isDockerfile(p)) return "dockerfile";
  if (base.endsWith(".tf")) return "terraform";
  if (!/\.ya?ml$/.test(base)) return null;
  if (/^\.github\/workflows\//.test(p)) return "workflow";
  if (/^(docker-)?compose([.-][\w.-]+)?\.ya?ml$/.test(base)) return "compose";
  if (/^\s*apiVersion:/m.test(head) && /^\s*kind:/m.test(head)) return "kubernetes";
  return null;
}
/** Paths that may be IaC (cheap filter before reading); YAML is confirmed after reading. */
const maybeIac = (p: string) => !VENDORED.test(p) && !TEST_PATH.test(p) && (isDockerfile(p) || /\.(tf|ya?ml)$/i.test(p));

// ---------- scanning ----------

const normalize = (line: string) => line.trim().replace(/\s+/g, " ");
const COMMENT: Record<IacKind, RegExp> = { terraform: /^\s*(#|\/\/|\/\*|\*)/, kubernetes: /^\s*#/, compose: /^\s*#/, dockerfile: /^\s*#/, workflow: /^\s*#/ };

export interface IacHit { rule: IacRule; line: number; key: string; snippet: string | null }

export function scanIac(kind: IacKind, text: string): IacHit[] {
  const rules = IAC_RULES.filter((r) => r.kinds.includes(kind));
  const lines = text.split("\n");
  const out: IacHit[] = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.length > MAX_LINE || COMMENT[kind].test(line) || ALLOW.test(line) || (i > 0 && ALLOW.test(lines[i - 1]) && COMMENT[kind].test(lines[i - 1]))) continue;
    const rule = rules.find((r) => r.re.test(line) && (!r.context || r.context(lines, i)));
    if (!rule) continue;
    const key = createHash("sha256").update(`${rule.id}\n${normalize(line)}`).digest("hex").slice(0, 12);
    out.push({ rule, line: i + 1, key, snippet: rule.noSnippet ? null : maskSnippet(line) });
  }
  // File-level: a Dockerfile whose final stage never sets USER runs as root.
  if (kind === "dockerfile") {
    const lastFrom = lines.map((l) => /^\s*FROM\s/i.test(l)).lastIndexOf(true);
    if (lastFrom >= 0 && !lines.slice(lastFrom).some((l) => /^\s*USER\s+/i.test(l)) && !ALLOW.test(lines[lastFrom]) && !/^\s*FROM\s+scratch\b/i.test(lines[lastFrom])) {
      const key = createHash("sha256").update("docker.no_user\nfile").digest("hex").slice(0, 12);
      out.push({ rule: NO_USER, line: lastFrom + 1, key, snippet: null });
    }
  }
  return out;
}

const NO_USER: IacRule = {
  id: "docker.no_user", kinds: ["dockerfile"], re: /$^/, severity: "low", confidence: "likely",
  title: "Image runs as root (no USER instruction)", fix: "Add a non-root user in the final stage (e.g. RUN adduser -D app && USER app). Distroless/nonroot base images may already do this; then mark this accepted.",
};

const clip = (s: string, n: number) => (s.length > n ? `…${s.slice(s.length - n + 1)}` : s);

export function createIacAdapter(): CheckAdapter {
  return {
    id: "code.iac@1", checkKey: "code.iac", target: "repository",
    async run(ctx): Promise<CheckResult> {
      const repo = ctx.repo;
      if (!repo) return { status: "error", reason: "no_repository_snapshot", evidence: {} };
      const base = { commit: repo.commit, rules: IAC_RULES.length + 1 };
      let all: string[];
      try { all = await repo.list(); } catch { return { status: "error", reason: "repository_unreadable", evidence: base }; }
      const candidates = all.filter(maybeIac).sort();
      if (candidates.length > MAX_FILES) return { status: "error", reason: "too_many_files", evidence: { ...base, files: candidates.length } };

      const byKey = new Map<string, { path: string; hit: IacHit; lines: number[] }>();
      const kinds: Record<string, number> = {};
      const skippedLarge: string[] = [];
      for (const p of candidates) {
        let text: string;
        try { text = await repo.read(p); } catch (e) {
          if ((e as { code?: string }).code === "file_too_large") { skippedLarge.push(p); continue; }
          return { status: "error", reason: "file_unreadable", evidence: { ...base, file: clip(p, 200) } };
        }
        if (Buffer.byteLength(text) > MAX_FILE_BYTES || text.slice(0, 8000).includes("\u0000")) { skippedLarge.push(p); continue; }
        const kind = iacKind(p, text.slice(0, 20_000));
        if (!kind) continue;
        kinds[kind] = (kinds[kind] ?? 0) + 1;
        for (const hit of scanIac(kind, text)) {
          const k = `${p}|${hit.key}`;
          const cur = byKey.get(k);
          if (cur) cur.lines.push(hit.line); else byKey.set(k, { path: p, hit, lines: [hit.line] });
        }
      }
      const filesScanned = Object.values(kinds).reduce((a, b) => a + b, 0);
      const summary = { ...base, filesScanned, kinds, largeSkipped: skippedLarge.slice(0, 20) };
      if (byKey.size > MAX_FINDINGS) return { status: "error", reason: "too_many_findings", evidence: { ...summary, findings: byKey.size } };

      const findings: FindingCandidate[] = [...byKey.values()].map(({ path: p, hit, lines }) => ({
        issueKey: `${hit.rule.id}.${hit.key}`,
        title: clip(`${hit.rule.title} in ${p}`, 200),
        severity: hit.rule.severity, confidence: hit.rule.confidence, location: clip(p, 300),
        evidence: { rule: hit.rule.id, file: p, line: lines[0], lines: lines.slice(0, 20), occurrences: lines.length, ...(hit.snippet ? { snippet: hit.snippet } : {}), commit: repo.commit },
        remediation: `${hit.rule.fix} If this is intended, mark the finding as accepted risk, or add a \`ruya:ignore\` comment on the line.`,
      }));
      return {
        status: "ok", findings,
        evidence: { ...summary, findings: findings.length, ...(filesScanned === 0 ? { note: "No Terraform, Kubernetes, Compose, Dockerfile or GitHub Actions files found at this commit." } : {}) },
      };
    },
  };
}
