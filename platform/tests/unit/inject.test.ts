import { describe, expect, it } from "vitest";
import type { FetchResult } from "@/server/net/egress";
import { createInjectAdapter } from "@/server/assessments/inject";
import type { CheckContext } from "@/server/assessments/checks";

const res = (status: number, body = "", extra: Partial<FetchResult> = {}): FetchResult =>
  ({ status, body, finalUrl: "", contentType: "text/html", redirects: 0, pinnedAddress: "1.1.1.1", headers: {}, truncated: false, ...extra });
const ctx = { host: "example.com", timeoutMs: 5000, sleep: async () => {} } as unknown as CheckContext;
const home = `<a href="/item?id=7">i</a><a href="/news?slug=hello">n</a><a href="/show?file=a.txt">f</a>`;

describe("pt.inject", () => {
  it("detects error-based and boolean SQL injection and path traversal", async () => {
    const r = await createInjectAdapter(async (raw) => {
      const u = new URL(raw);
      if (u.pathname === "/" && !u.search) return res(200, home);
      if (u.pathname === "/news") return res(200, u.searchParams.get("slug")!.includes("'") ? "You have an error in your SQL syntax near ''" : "<h1>Hello</h1>");
      if (u.pathname === "/item") { const v = u.searchParams.get("id")!; return res(200, v.endsWith("1=2") ? "<p>No item</p>" : "<h1>Item 7</h1>" + "x".repeat(400)); }
      if (u.pathname === "/show") return res(200, u.searchParams.get("file")!.includes("passwd") ? "root:x:0:0:root:/root:/bin/bash" : "file a");
      return res(404, "nf");
    }).run(ctx);
    expect(r.status).toBe("ok");
    if (r.status !== "ok") return;
    expect(r.findings.map((f) => `${f.issueKey}:${(f.evidence as { parameter: string }).parameter}`).sort()).toEqual(["path_traversal:file", "sql_injection:id", "sql_injection:slug"]);
    expect(JSON.stringify(r.findings)).not.toContain("/bin/bash");
  });
  it("reports nothing on a safe site, including one that always shows the same error", async () => {
    const r = await createInjectAdapter(async (raw) => {
      const u = new URL(raw);
      if (u.pathname === "/" && !u.search) return res(200, home);
      return res(200, "SQLSTATE[HY000] maintenance notice, page " + (u.searchParams.get("id") ? "item" : "other"));
    }).run(ctx);
    expect(r.status === "ok" && r.findings).toEqual([]);
  });
  it("ignores unstable pages for the boolean test", async () => {
    let n = 0;
    const r = await createInjectAdapter(async (raw) => {
      const u = new URL(raw);
      if (u.pathname === "/" && !u.search) return res(200, `<a href="/item?id=7">i</a>`);
      n++; return res(200, n % 2 ? "short" : "a much longer and different page body ".repeat(5));
    }).run(ctx);
    expect(r.status === "ok" && r.findings).toEqual([]);
  });
});
