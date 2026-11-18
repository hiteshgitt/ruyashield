import { describe, expect, it } from "vitest";
import { resolveOptions, severitiesFrom } from "@/server/reports/content";
import { richPdf, textWidth, wrap } from "@/server/richpdf";

describe("report options", () => {
  it("presets fill in sections, severity and fixes; the summary is always in", () => {
    expect(resolveOptions({ preset: "executive" })).toMatchObject({ sections: ["summary", "verification"], minSeverity: "high", includeFixes: false });
    expect(resolveOptions({ preset: "technical" }).sections).toHaveLength(7);
    const custom = resolveOptions({ preset: "custom", sections: ["findings"], minSeverity: "medium", includeFixes: false, title: "  Acme  " });
    expect(custom).toMatchObject({ sections: ["summary", "findings"], minSeverity: "medium", includeFixes: false, title: "Acme" });
    expect(resolveOptions(undefined).preset).toBe("client");
    expect(() => resolveOptions({ preset: "custom", sections: ["nope"] })).toThrow();
  });
  it("severity floors", () => {
    expect(severitiesFrom("high")).toEqual(["critical", "high"]);
    expect(severitiesFrom("info")).toHaveLength(5);
  });
});

describe("formatted PDF", () => {
  it("measures and wraps with Helvetica widths", () => {
    expect(textWidth("W", 10)).toBeGreaterThan(textWidth("i", 10));
    const lines = wrap("Content-Security-Policy header missing on every page of the site", 10, 120);
    expect(lines.length).toBeGreaterThan(1);
    expect(lines.every((l) => textWidth(l, 10) <= 120)).toBe(true);
  });
  it("builds a valid multi-page PDF with a footer on every page", () => {
    const pdf = richPdf([
      { t: "cover", title: "Security report - Acme", subtitle: "Acme", meta: ["Scope: all assets"] },
      { t: "h1", text: "Open findings" },
      ...Array.from({ length: 80 }, (_, i) => ({ t: "finding" as const, severity: ["critical", "high", "medium", "low"][i % 4], title: `Finding ${i} — “quoted” (paren)`, meta: "shop.example.com - new", body: "Fix: add the header." })),
      { t: "table", head: ["Asset", "Status"], widths: [3, 1], rows: [["a.example.com", "verified"]] },
    ], "Footer");
    const text = pdf.toString("latin1");
    expect(text.startsWith("%PDF-1.4")).toBe(true);
    expect(text.trimEnd().endsWith("%%EOF")).toBe(true);
    const pages = Number(text.match(/\/Count (\d+)/)![1]);
    expect(pages).toBeGreaterThan(2);
    expect(text.match(/Page \d+ of \d+/g)).toHaveLength(pages);
    expect(text).toContain("\\(paren\\)");
  });
});
