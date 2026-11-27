import { describe, expect, it } from "vitest";
import type { FetchResult } from "@/server/net/egress";
import { createReflectAdapter, linksIn, redirectsToProbe, REDIRECT_PROBE_HOST, reflectsUnescaped } from "@/server/assessments/reflect";
import type { CheckContext } from "@/server/assessments/checks";

const res = (status: number, body = "", extra: Partial<FetchResult> = {}): FetchResult =>
  ({ status, body, finalUrl: "", contentType: "text/html; charset=utf-8", redirects: 0, pinnedAddress: "1.1.1.1", headers: {}, truncated: false, ...extra });
const ctx = { host: "example.com", timeoutMs: 5000, sleep: async () => {} } as unknown as CheckContext;

describe("pt.reflect helpers", () => {
  it("collects same-host links and GET forms, never state-changing ones", () => {
    const html = `<a href="/search?q=a">s</a><a href="https://other.com/?x=1">o</a><a href="/cart?add-to-cart=5">c</a>
      <a href="/wp-login.php?redirect_to=/">l</a><a href="/go?url=/home&amp;_wpnonce=abc">g</a>
      <form action="/find" method="get"><input name="term"><input type="hidden" name="token" value="x"></form>
      <form action="/contact" method="post"><input name="msg"></form>`;
    const { candidates } = linksIn(html, new URL("https://example.com/"));
    expect(candidates.map((c) => `${c.url.pathname}|${c.param}`).sort()).toEqual(["/find|term", "/go|url", "/search|q"]);
  });
  it("needs the marker back as markup, and a redirect to the probe host", () => {
    expect(reflectsUnescaped(res(200, "you searched ruyaab<ruyaab>"), "ruyaab")).toBe(true);
    expect(reflectsUnescaped(res(200, "you searched ruyaab&lt;ruyaab&gt;"), "ruyaab")).toBe(false);
    expect(reflectsUnescaped(res(200, "ruyaab<ruyaab>", { contentType: "application/json" }), "ruyaab")).toBe(false);
    expect(redirectsToProbe(res(302, "", { headers: { location: `https://${REDIRECT_PROBE_HOST}/` } }))).toBe(true);
    expect(redirectsToProbe(res(302, "", { headers: { location: `//${REDIRECT_PROBE_HOST}/` } }))).toBe(true);
    expect(redirectsToProbe(res(302, "", { headers: { location: "https://example.com/home" } }))).toBe(false);
  });
});

describe("pt.reflect run", () => {
  it("finds reflected XSS and an open redirect from crawled parameters", async () => {
    const fetch = async (raw: string) => {
      const u = new URL(raw);
      if (u.pathname === "/" && !u.search) return res(200, `<a href="/search?q=x">s</a><a href="/go?next=/a">g</a>`);
      if (u.pathname === "/search") return res(200, `Results for ${u.searchParams.get("q")}`);
      if (u.pathname === "/go") return res(302, "", { headers: { location: u.searchParams.get("next") ?? "/" } });
      return res(404, "nf");
    };
    const r = await createReflectAdapter(fetch, () => "ruyatest").run(ctx);
    expect(r.status).toBe("ok");
    if (r.status !== "ok") return;
    expect(r.findings.map((f) => f.issueKey).sort()).toEqual(["open_redirect", "reflected_xss"]);
  });
  it("reports nothing when output is escaped, and fails closed when the site errors", async () => {
    const escaped = async (raw: string) => {
      const u = new URL(raw);
      if (u.pathname === "/" && !u.search) return res(200, `<a href="/search?q=x">s</a>`);
      return res(200, `Results for ${String(u.searchParams.get("q")).replace(/</g, "&lt;").replace(/>/g, "&gt;")}`);
    };
    const ok = await createReflectAdapter(escaped, () => "ruyatest").run(ctx);
    expect(ok.status === "ok" && ok.findings).toEqual([]);
    const down = await createReflectAdapter(async () => res(503), () => "ruyatest").run(ctx);
    expect(down.status).toBe("error");
  });
});
