import { describe, expect, it } from "vitest";
import type { FetchResult } from "@/server/net/egress";
import { createSurfaceAdapter } from "@/server/assessments/surface";
import type { CheckContext } from "@/server/assessments/checks";

const res = (status: number, body = "", extra: Partial<FetchResult> = {}): FetchResult =>
  ({ status, body, finalUrl: "", contentType: "text/html", redirects: 0, pinnedAddress: "1.1.1.1", headers: {}, truncated: false, ...extra });
const ctx = { host: "example.com", timeoutMs: 5000 } as unknown as CheckContext;
const run = (pages: Record<string, FetchResult>) =>
  createSurfaceAdapter(async (url) => pages[url] ?? res(404, "not found"), () => "/random").run(ctx);

describe("pt.surface", () => {
  it("finds exposed files and WordPress weaknesses, and ignores ordinary 404s", async () => {
    const r = await run({
      "https://example.com/": res(200, '<link href="/wp-content/themes/x/style.css">'),
      "https://example.com/phpinfo.php": res(200, "<title>PHP 8.2.1 - phpinfo()</title>"),
      "https://example.com/wp-config.php.bak": res(200, "<?php define('DB_PASSWORD', 'x');", { contentType: "text/plain" }),
      "https://example.com/wp-content/debug.log": res(200, "[01-Nov] PHP Warning: x in /var/www", { contentType: "text/plain" }),
      "https://example.com/wp-json/wp/v2/users": res(200, '[{"id":1,"slug":"admin"}]', { contentType: "application/json" }),
      "https://example.com/?author=1": res(301, "", { headers: { location: "https://example.com/author/admin/" } }),
      "https://example.com/xmlrpc.php": res(405, "XML-RPC server accepts POST requests only."),
      "http://example.com/wp-login.php": res(200, '<input type="password" name="pwd" id="user_pass">'),
    });
    expect(r.status).toBe("ok");
    if (r.status !== "ok") return;
    expect(r.findings.map((f) => f.issueKey).sort()).toEqual(["config_backup_exposed", "debug_log_exposed", "login_over_http", "phpinfo_exposed", "wp_user_enum_author", "wp_user_enum_rest", "wp_xmlrpc_enabled"]);
    expect(JSON.stringify(r.findings)).not.toContain("DB_PASSWORD"); // evidence never holds file contents
  });
  it("does not report a catch-all page, and skips WordPress checks on other sites", async () => {
    const catchAll = res(200, "<html>Welcome</html>");
    const r = await createSurfaceAdapter(async (url) => (url.endsWith("/") ? res(200, "<html>shop</html>") : catchAll), () => "/random").run(ctx);
    expect(r.status === "ok" && r.findings).toEqual([]);
  });
  it("fails closed on server errors", async () => {
    const r = await createSurfaceAdapter(async () => res(503), () => "/random").run(ctx);
    expect(r.status).toBe("error");
  });
});
