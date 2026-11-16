import { describe, expect, it } from "vitest";
import { normalizeResult, type CheckContext } from "@/server/assessments/checks";
import { createSastAdapter, isSastTarget, maskSnippet, SAST_RULES, scanSource } from "@/server/assessments/sast";
import type { RepoSnapshot } from "@/server/remediation/repo";

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
const run = async (files: Record<string, string>, opts = {}) => normalizeResult(await createSastAdapter().run(ctx(repo(files, opts))));
const ids = (path: string, text: string) => scanSource(path, text).map((h) => h.rule.id);

describe("SAST rules", () => {
  it("have unique ids, a CWE and remediation text", () => {
    expect(new Set(SAST_RULES.map((r) => r.id)).size).toBe(SAST_RULES.length);
    for (const r of SAST_RULES) { expect(r.cwe).toMatch(/^CWE-\d+$/); expect(r.fix.length).toBeGreaterThan(20); }
  });

  it.each([
    ["app/db.php", `$r = mysqli_query($c, "SELECT * FROM u WHERE id=" . $_GET['id']);`, "php-sql-superglobal"],
    ["app/run.php", `system("ping " . $_POST["host"]);`, "php-command-superglobal"],
    ["index.php", `include $_GET['page'] . ".php";`, "php-include-superglobal"],
    ["view.php", `echo "Hello " . $_GET['name'];`, "php-echo-superglobal"],
    ["lib.php", `$o = unserialize($data);`, "php-unserialize"],
    ["api.php", `curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);`, "php-tls-verify-disabled"],
    ["src/users.ts", "await db.query(`SELECT * FROM users WHERE id = ${id}`);", "js-sql-template"],
    ["src/sh.js", "const cp = require('child_process');\ncp.exec(`ls ${dir}`);", "js-command-injection"],
    ["src/x.js", "const v = eval(input);", "js-eval"],
    ["src/ui.ts", "el.innerHTML = comment.body;", "js-inner-html"],
    ["src/C.tsx", "<div dangerouslySetInnerHTML={{ __html: post.html }} />", "react-dangerously-set-html"],
    ["src/http.ts", "const agent = new https.Agent({ rejectUnauthorized: false });", "js-tls-verify-disabled"],
    ["src/auth.ts", "jwt.verify(t, key, { algorithms: ['HS256', 'none'] });", "jwt-none-algorithm"],
    ["app/views.py", `cursor.execute(f"SELECT * FROM t WHERE id = {uid}")`, "py-sql-format"],
    ["app/tasks.py", "subprocess.run(cmd, shell=True)", "py-subprocess-shell"],
    ["app/load.py", "data = pickle.loads(blob)", "py-pickle-load"],
    ["app/cfg.py", "cfg = yaml.load(f)", "py-yaml-load"],
    ["app/client.py", "requests.get(url, verify=False)", "py-tls-verify-disabled"],
    ["app/main.py", "app.run(host='0.0.0.0', debug=True)", "py-flask-debug"],
    ["app/settings.py", "INSTALLED_APPS = []\nDEBUG = True", "py-django-debug"],
    ["src/Dao.java", `stmt.executeQuery("SELECT * FROM u WHERE name='" + name + "'");`, "java-sql-concat"],
    ["src/Run.java", "Runtime.getRuntime().exec(cmd);", "java-runtime-exec"],
    ["src/Enc.java", `Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");`, "weak-cipher"],
    ["main.go", `rows, _ := db.Query(fmt.Sprintf("SELECT * FROM u WHERE id = %s", id))`, "go-sql-format"],
    ["main.go", "cfg := &tls.Config{InsecureSkipVerify: true}", "go-tls-verify-disabled"],
    ["app/models/u.rb", `User.where("name = '#{params[:name]}'")`, "rb-sql-interpolation"],
    ["app/hash.py", "h = hashlib.md5(password.encode())", "weak-hash"],
  ])("%s → %s", (path, text, rule) => {
    expect(ids(path, text)).toContain(rule);
  });

  it("does not flag safe equivalents", () => {
    expect(ids("a.php", `echo htmlspecialchars($_GET['q'], ENT_QUOTES);`)).toEqual([]);
    expect(ids("a.php", `$o = unserialize($d, ['allowed_classes' => false]);`)).toEqual([]);
    expect(ids("a.ts", "await db.query('SELECT * FROM users WHERE id = $1', [id]);")).toEqual([]);
    expect(ids("a.ts", "el.innerHTML = '';")).toEqual([]);
    expect(ids("a.ts", "if (el.innerHTML === x) {}")).toEqual([]);
    expect(ids("a.ts", "<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(h) }} />")).toEqual([]);
    expect(ids("a.js", "exec(cmd)")).toEqual([]); // no child_process in the file
    expect(ids("a.py", "cfg = yaml.load(f, Loader=yaml.SafeLoader)")).toEqual([]);
    expect(ids("a.py", `cursor.execute("SELECT * FROM t WHERE id = %s", (uid,))`)).toEqual([]);
    expect(ids("a.py", "subprocess.run(['ls', d])")).toEqual([]);
    expect(ids("settings.py", "DEBUG = True")).toEqual([]); // not a Django settings file
    expect(ids("a.py", "hashlib.md5(b, usedforsecurity=False)")).toEqual([]);
    expect(ids("README.md", "eval(x)")).toEqual([]); // not source
  });

  it("skips comments and lines marked ruya:ignore / nosemgrep", () => {
    expect(ids("a.js", "// eval(input)\n# x")).toEqual([]);
    expect(ids("a.js", "eval(input); // ruya:ignore")).toEqual([]);
    expect(ids("a.py", "# nosemgrep\neval(expr)")).toEqual([]);
    expect(ids("a.py", "eval(expr)  # nosemgrep")).toEqual([]);
  });

  it("excludes tests, fixtures, vendored and minified files", () => {
    for (const p of ["tests/a.ts", "src/__tests__/a.ts", "a.test.ts", "a.spec.js", "test_views.py", "x_test.go", "fixtures/a.php", "node_modules/x/a.js", "dist/a.min.js"]) expect(isSastTarget(p)).toBe(false);
    for (const p of ["src/a.ts", "app/views.py", "index.php", "cmd/main.go", "src/Main.java", "app/models/u.rb"]) expect(isSastTarget(p)).toBe(true);
  });

  it("keys findings by rule and normalized line, not line number", () => {
    const [a] = scanSource("a.js", "eval(input);");
    const [b] = scanSource("a.js", "\n\n// moved\n   eval(input);   ");
    expect(b.line).toBe(4);
    expect(b.key).toBe(a.key);
    expect(scanSource("a.js", "eval(other);")[0].key).not.toBe(a.key);
  });

  it("masks long string literals and drops snippets that look like secrets", () => {
    expect(maskSnippet(`  db.query("SELECT secret_column FROM t WHERE x = " + v)`)).toBe(`db.query("…" + v)`);
    expect(maskSnippet(`run('ls')`)).toBe(`run('ls')`);
    const aws = "AKIA" + "Q3EGRTZ7WJ5XN2LM";
    expect(maskSnippet(`requests.get(u, auth=("${aws}", k), verify=False)`)).toBeNull();
  });
});

describe("code.sast adapter", () => {
  it("reports findings with file location, rule key, confidence and line evidence", async () => {
    const r = await run({
      "src/app.ts": "import x from 'y';\nconst v = eval(input);\n",
      "app/client.py": "requests.get(u, verify=False)\nrequests.post(u, verify=False)\n",
      "tests/bad.ts": "eval(input)",
      "README.md": "eval(input)",
    });
    expect(r.status).toBe("ok");
    if (r.status !== "ok") return;
    expect(r.findings.map((f) => [f.issueKey.split(".")[0], f.location, f.severity, f.confidence])).toEqual([
      ["py-tls-verify-disabled", "app/client.py", "high", "likely"],
      ["py-tls-verify-disabled", "app/client.py", "high", "likely"],
      ["js-eval", "src/app.ts", "high", "suspected"],
    ]);
    expect(r.findings[2].evidence).toMatchObject({ rule: "js-eval", cwe: "CWE-95", file: "src/app.ts", line: 2, occurrences: 1, snippet: "const v = eval(input);", commit: "c".repeat(40) });
    expect(r.findings[2].remediation).toMatch(/ruya:ignore/);
    expect(r.evidence).toMatchObject({ filesScanned: 2, filesExcluded: 2, findings: 3, languages: { js: 1, py: 1 } });
  });

  it("merges identical lines in one file into one finding", async () => {
    const r = await run({ "a.js": "eval(input);\nfoo();\neval(input);\n" });
    if (r.status !== "ok") throw new Error(r.status);
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].evidence).toMatchObject({ lines: [1, 3], occurrences: 2 });
  });

  it("returns ok with no findings for clean code, skipping oversized files", async () => {
    expect(await run({ "a.ts": "export const x = 1;\n", "big.ts": "" }, { tooLarge: "big.ts" })).toMatchObject({ status: "ok", findings: [], evidence: { largeSkipped: ["big.ts"] } });
  });

  it("fails closed when the repository or a file cannot be read, or there are too many findings", async () => {
    expect(await createSastAdapter().run(ctx())).toMatchObject({ status: "error", reason: "no_repository_snapshot" });
    expect(await run({ "a.ts": "" }, { failList: true })).toMatchObject({ status: "error", reason: "repository_unreadable" });
    expect(await run({ "a.ts": "eval(x)" }, { failRead: "a.ts" })).toMatchObject({ status: "error", reason: "file_unreadable" });
    const many = Array.from({ length: 301 }, (_, i) => `eval(v${i});`).join("\n");
    expect(await run({ "a.js": many })).toMatchObject({ status: "error", reason: "too_many_findings" });
  });
});
