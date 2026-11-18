import { describe, expect, it } from "vitest";
import { createTechnologyAdapter, detectTechnologies, technologyFindings } from "@/server/assessments/technology";

const WP_HTML = `<html><head><meta name="generator" content="WordPress 6.4.2" />
<script src="https://shop.example.com/wp-includes/js/jquery/jquery.min.js?ver=3.4.1"></script>
<script async src="https://www.googletagmanager.com/gtag/js?id=G-1"></script></head></html>`;

describe("detectTechnologies", () => {
  it("reads WordPress, PHP, server, CDN and jQuery from one response", () => {
    const t = detectTechnologies({ server: "nginx/1.24.0", "x-powered-by": "PHP/7.4.33", "cf-ray": "abc" }, WP_HTML);
    const by = Object.fromEntries(t.map((x) => [x.name, x.version]));
    expect(by).toMatchObject({ WordPress: "6.4.2", PHP: "7.4.33", nginx: "1.24.0", Cloudflare: null, jQuery: "3.4.1", "Google Analytics": null });
  });
  it("recognises Next.js and Laravel", () => {
    expect(detectTechnologies({ "x-vercel-id": "x" }, `<script id="__NEXT_DATA__">{}</script>`).map((t) => t.name)).toEqual(["Next.js", "Vercel"]);
    expect(detectTechnologies({ "set-cookie": ["laravel_session=abc; path=/"] }, "").map((t) => t.name)).toEqual(["Laravel", "PHP"]);
  });
  it("finds nothing in an empty response", () => {
    expect(detectTechnologies({}, "")).toEqual([]);
  });
});

describe("technologyFindings", () => {
  const tech = detectTechnologies({ "x-powered-by": "PHP/7.4.33" }, WP_HTML);
  it("flags outdated WordPress, end-of-life PHP and old jQuery", () => {
    const f = technologyFindings("https://shop.example.com/", tech, "6.8.1");
    expect(f.map((x) => [x.issueKey, x.severity])).toEqual([["wordpress_outdated", "high"], ["php_end_of_life", "medium"], ["jquery_outdated", "medium"]]);
  });
  it("does not judge WordPress without the current release, or current versions", () => {
    expect(technologyFindings("u", tech, null).map((x) => x.issueKey)).not.toContain("wordpress_outdated");
    const ok = detectTechnologies({ "x-powered-by": "PHP/8.3.1" }, `<meta name="generator" content="WordPress 6.8.1"><script src="/jquery-3.7.1.min.js"></script>`);
    expect(technologyFindings("u", ok, "6.8.1")).toEqual([]);
  });
});

describe("web.technology adapter", () => {
  const ctx = { host: "shop.example.com", timeoutMs: 1000 } as never;
  it("stores the stack in the evidence and asks for the WordPress release only when needed", async () => {
    let asked = 0;
    const a = createTechnologyAdapter({
      fetch: async () => ({ status: 200, finalUrl: "https://shop.example.com/", contentType: "text/html", body: WP_HTML, redirects: 0, pinnedAddress: "1.2.3.4", headers: { server: "Apache" }, truncated: false }),
      latestWordPress: async () => { asked++; return "6.4.2"; },
    });
    const r = await a.run(ctx);
    expect(r.status).toBe("ok");
    if (r.status !== "ok") return;
    expect(asked).toBe(1);
    expect((r.evidence.technologies as { name: string }[]).map((t) => t.name)).toContain("Apache");
    expect(r.findings.map((f) => f.issueKey)).toEqual(["jquery_outdated"]);
  });
  it("reports an error on a 5xx instead of an empty stack", async () => {
    const a = createTechnologyAdapter({ fetch: async () => ({ status: 503, finalUrl: "u", contentType: null, body: "", redirects: 0, pinnedAddress: "", headers: {}, truncated: false }), latestWordPress: async () => null });
    expect((await a.run(ctx)).status).toBe("error");
  });
});
