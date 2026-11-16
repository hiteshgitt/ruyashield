import { describe, expect, it } from "vitest";
import { normalizeResult, type CheckContext } from "@/server/assessments/checks";
import { createIacAdapter, iacKind, scanIac } from "@/server/assessments/iac";
import { createBlocklistAdapter, type BlocklistKeys } from "@/server/assessments/blocklist";
import type { FetchLike } from "@/server/assessments/deps";
import type { RepoSnapshot } from "@/server/remediation/repo";

const keys = (r: { status: string } & Record<string, unknown>) => r.status === "ok" ? (r.findings as { issueKey: string; severity: string }[]).map((f) => `${f.issueKey}:${f.severity}`) : [`error:${r.reason}`];
const ids = (r: { status: string } & Record<string, unknown>) => keys(r).map((k) => k.replace(/\.[0-9a-f]{12}(?=:)/, ""));

function repo(files: Record<string, string>, commit = "c".repeat(40)): RepoSnapshot {
  return { externalId: "demo", commit, list: async () => Object.keys(files), read: async (p) => { if (!(p in files)) throw new Error("not_found"); return files[p]; } };
}
const rctx = (r: RepoSnapshot | undefined) => ({ repo: r, timeoutMs: 600_000 }) as unknown as CheckContext;
const runIac = (files: Record<string, string>) => createIacAdapter().run(rctx(repo(files))).then(normalizeResult);

const TF = `resource "aws_security_group" "db" {
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_security_group" "web" {
  ingress {
    from_port   = 443
    to_port     = 443
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_s3_bucket_acl" "b" { acl = "public-read" }
resource "aws_db_instance" "d" {
  publicly_accessible = true
  storage_encrypted   = false
  password            = "SuperSecret123"
}
`;

describe("code.iac", () => {
  it("terraform: open DB port, public bucket/db, encryption off, hard-coded password; port 443 is fine", async () => {
    const r = await runIac({ "infra/main.tf": TF });
    expect(ids(r).sort()).toEqual(["tf.db_public:high", "tf.encryption_off:medium", "tf.hardcoded_password:high", "tf.open_ingress:high", "tf.public_acl:high"]);
    expect(JSON.stringify(r)).not.toContain("SuperSecret123");
  });

  it("kubernetes manifests (only YAML with apiVersion+kind) and compose files", async () => {
    const k8s = `apiVersion: v1\nkind: Pod\nspec:\n  hostNetwork: true\n  containers:\n    - name: a\n      securityContext:\n        privileged: true\n        capabilities:\n          add:\n            - SYS_ADMIN\n`;
    const compose = `services:\n  db:\n    image: postgres\n    ports:\n      - "5432:5432"\n  agent:\n    privileged: true\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n`;
    const r = await runIac({ "k8s/pod.yaml": k8s, "docker-compose.yml": compose, "config/app.yaml": "privileged: true\n" });
    expect(ids(r).sort()).toEqual(["compose.db_port_public:medium", "compose.privileged:high", "k8s.dangerous_caps:high", "k8s.docker_sock:high", "k8s.host_namespace:high", "k8s.privileged:high"]);
  });

  it("dockerfile: curl|sh, secret in ENV (no snippet), no USER; workflows: script injection", async () => {
    const df = `FROM node:22\nRUN curl -fsSL https://x.example/install.sh | sh\nENV API_KEY=abcd1234efgh\nCMD ["node","a.js"]\n`;
    const wf = `on:\n  issues:\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          echo "\${{ github.event.issue.title }}"\n`;
    const r = await runIac({ Dockerfile: df, ".github/workflows/ci.yml": wf });
    expect(ids(r).sort()).toEqual(["ci.script_injection:high", "docker.curl_pipe_shell:medium", "docker.no_user:low", "docker.secret_in_env:medium"]);
    expect(JSON.stringify(r)).not.toContain("abcd1234efgh");
    expect(keys(await runIac({ Dockerfile: "FROM node:22\nUSER node\n" }))).toEqual([]);
    expect(keys(await runIac({ Dockerfile: "FROM golang AS b\nFROM scratch\n" }))).toEqual([]);
  });

  it("ignore markers, comments, test and vendored paths are skipped", async () => {
    const r = await runIac({
      "a.tf": `acl = "public-read" # ruya:ignore\n# acl = "public-read"\n`,
      "b.tf": `# tfsec:ignore:aws-s3\nacl = "public-read"\n`,
      "examples/x.tf": `acl = "public-read"\n`, "tests/fixtures/y.tf": `acl = "public-read"\n`, ".terraform/modules/z.tf": `acl = "public-read"\n`,
    });
    expect(keys(r)).toEqual([]);
  });

  it("fingerprints stay the same when the line moves", () => {
    const a = scanIac("terraform", `acl = "public-read"\n`)[0].key;
    const b = scanIac("terraform", `\n\n# moved\n  acl  =  "public-read"\n`)[0].key;
    expect(a).toBe(b);
  });

  it("kind detection", () => {
    expect(iacKind("main.tf", "")).toBe("terraform");
    expect(iacKind("Dockerfile.prod", "FROM x")).toBe("dockerfile");
    expect(iacKind("compose.yaml", "services:")).toBe("compose");
    expect(iacKind("deploy.yaml", "apiVersion: apps/v1\nkind: Deployment")).toBe("kubernetes");
    expect(iacKind("values.yaml", "replicas: 2")).toBeNull();
  });

  it("clean repo is ok with a note; missing or unreadable repo is an error", async () => {
    const r = await runIac({ "src/a.ts": "x" });
    expect(r).toMatchObject({ status: "ok", findings: [] });
    expect(keys(await createIacAdapter().run(rctx(undefined)).then(normalizeResult))).toEqual(["error:no_repository_snapshot"]);
    const broken: RepoSnapshot = { externalId: "d", commit: "c", list: async () => { throw new Error("x"); }, read: async () => "" };
    expect(keys(await createIacAdapter().run(rctx(broken)).then(normalizeResult))).toEqual(["error:repository_unreadable"]);
  });
});

describe("web.blocklist", () => {
  const ctx = { host: "Shop.Example.com", timeoutMs: 30000 } as unknown as CheckContext;
  const KEY = "AIzaSECRETKEY123";
  type Reply = { status?: number; body?: string } | Error;
  const run = (k: BlocklistKeys, sb: Reply = { body: "{}" }, uh: Reply = { body: `{"query_status":"no_results"}` }, calls: string[] = []) => {
    const fetch: FetchLike = async (url, init) => {
      calls.push(`${init.method} ${new URL(url).host} ${init.body ?? ""}`);
      const r = url.includes("safebrowsing") ? sb : uh;
      if (r instanceof Error) throw r;
      return { ok: (r.status ?? 200) < 400, status: r.status ?? 200, text: async () => r.body ?? "" };
    };
    return createBlocklistAdapter({ fetch, keys: () => k }).run(ctx).then(normalizeResult);
  };

  it("no keys configured: error, never clean", async () => {
    expect(keys(await run({}))).toEqual(["error:blocklist_not_configured"]);
  });

  it("clean answers from both sources: ok with no findings; only the host is sent", async () => {
    const calls: string[] = [];
    const r = await run({ safeBrowsing: KEY, urlhaus: "uh" }, undefined, undefined, calls);
    expect(r.status).toBe("ok");
    expect(keys(r)).toEqual([]);
    expect(calls.length).toBe(2);
    expect(calls.join(" ")).toContain("shop.example.com");
  });

  it("Safe Browsing matches are critical (malware/phishing) or high", async () => {
    const body = JSON.stringify({ matches: [{ threatType: "SOCIAL_ENGINEERING" }, { threatType: "UNWANTED_SOFTWARE" }, { threatType: "SOCIAL_ENGINEERING" }] });
    expect(keys(await run({ safeBrowsing: KEY }, { body })).sort()).toEqual(["safe_browsing.social_engineering:critical", "safe_browsing.unwanted_software:high"]);
  });

  it("URLhaus: live URLs critical, historic medium", async () => {
    const hit = (status: string) => ({ body: JSON.stringify({ query_status: "ok", url_count: "2", urlhaus_reference: "https://urlhaus.abuse.ch/host/x/", urls: [{ url_status: status, threat: "malware_download", date_added: "2026-01-02 10:00:00 UTC" }, { url_status: "offline", threat: "malware_download", date_added: "2025-12-01 10:00:00 UTC" }] }) });
    expect(keys(await run({ urlhaus: "uh" }, undefined, hit("online")))).toEqual(["urlhaus.active:critical"]);
    expect(keys(await run({ urlhaus: "uh" }, undefined, hit("offline")))).toEqual(["urlhaus.historic:medium"]);
  });

  it("fails closed on HTTP errors, malformed answers and network errors, without leaking the key", async () => {
    const results = [
      await run({ safeBrowsing: KEY }, { status: 403, body: `{"error":"key ${KEY} invalid"}` }),
      await run({ safeBrowsing: KEY }, { body: "not json" }),
      await run({ safeBrowsing: KEY }, { body: `{"matches":"x"}` }),
      await run({ safeBrowsing: KEY }, new TypeError(`fetch failed ${KEY}`)),
      await run({ urlhaus: "uh" }, undefined, { body: `{"query_status":"unknown_auth_key"}` }),
      await run({ safeBrowsing: KEY, urlhaus: "uh" }, undefined, new Error("down")),
    ];
    expect(results.map((r) => keys(r)[0])).toEqual([
      "error:safe_browsing_http_403", "error:safe_browsing_malformed_response", "error:safe_browsing_malformed_response",
      "error:safe_browsing_unreachable", "error:urlhaus_unknown_auth_key", "error:urlhaus_unreachable",
    ]);
    expect(JSON.stringify(results)).not.toContain(KEY);
  });
});
