// Formatted PDF reports without a PDF dependency: a cover band, headings, key-figure tiles, tables and
// finding cards, wrapped with real Helvetica glyph widths, broken across A4 pages, with a footer on each page.
// Text is WinAnsi (non-Latin characters become "?"), the same limit as the plain textPdf writer.

export type Rgb = [number, number, number];
export type Block =
  | { t: "cover"; title: string; subtitle?: string; meta: string[] }
  | { t: "h1"; text: string }
  | { t: "h2"; text: string }
  | { t: "p"; text: string; muted?: boolean; size?: number }
  | { t: "bullets"; items: string[]; muted?: boolean }
  | { t: "stats"; items: { label: string; value: string; tone?: Rgb }[] }
  | { t: "table"; head: string[]; rows: string[][]; widths: number[] }
  | { t: "finding"; severity: string; title: string; meta: string; body?: string }
  | { t: "note"; text: string }
  | { t: "space"; h?: number };

// Helvetica and Helvetica-Bold advance widths (1/1000 em) for ASCII 32..126, from the standard AFM files.
const W_REG = [278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556, 1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556, 333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556, 556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584];
const W_BOLD = [278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 333, 333, 584, 584, 584, 611, 975, 722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 333, 278, 333, 584, 556, 333, 556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556, 278, 889, 611, 611, 611, 611, 389, 556, 333, 611, 556, 778, 556, 556, 500, 389, 280, 389, 584];

const ascii = (s: string) => s.replace(/[‘’]/g, "'").replace(/[“”]/g, '"').replace(/[–—]/g, "-").replace(/…/g, "...").replace(/·/g, "-").replace(/[^\x20-\x7e]/g, "?");
export function textWidth(s: string, size: number, bold = false): number {
  const w = bold ? W_BOLD : W_REG;
  let sum = 0;
  for (const ch of ascii(s)) sum += w[ch.charCodeAt(0) - 32] ?? 556;
  return (sum * size) / 1000;
}

/** Greedy word wrap to a width in points; very long words are split. */
export function wrap(text: string, size: number, width: number, bold = false): string[] {
  const out: string[] = [];
  for (const para of ascii(text).split("\n")) {
    let line = "";
    for (const word of para.split(/\s+/).filter(Boolean)) {
      let w = word;
      while (textWidth(w, size, bold) > width) {
        let cut = w.length - 1;
        while (cut > 1 && textWidth(w.slice(0, cut), size, bold) > width) cut--;
        if (line) { out.push(line); line = ""; }
        out.push(w.slice(0, cut));
        w = w.slice(cut);
      }
      const next = line ? `${line} ${w}` : w;
      if (textWidth(next, size, bold) > width && line) { out.push(line); line = w; } else line = next;
    }
    out.push(line);
  }
  return out;
}

const PAGE_W = 595, PAGE_H = 842, MARGIN = 48, CONTENT_W = PAGE_W - MARGIN * 2, BOTTOM = 60;
const INK: Rgb = [0.11, 0.1, 0.16], MUTED: Rgb = [0.42, 0.41, 0.5], LINE: Rgb = [0.86, 0.85, 0.9];
const ORANGE: Rgb = [1, 0.35, 0.12], VIOLET: Rgb = [0.55, 0.36, 0.96], DARK: Rgb = [0.09, 0.08, 0.14];
export const SEVERITY_COLOR: Record<string, Rgb> = {
  critical: [0.82, 0.13, 0.2], high: [0.92, 0.42, 0.1], medium: [0.86, 0.62, 0.05], low: [0.2, 0.5, 0.85], info: [0.5, 0.5, 0.58],
};

const esc = (s: string) => ascii(s).replace(/[\\()]/g, (m) => `\\${m}`);
const rgb = (c: Rgb, stroke = false) => `${c.map((v) => v.toFixed(3)).join(" ")} ${stroke ? "RG" : "rg"}`;

export function richPdf(blocks: Block[], footer: string): Buffer {
  const pages: string[][] = [[]];
  let y = PAGE_H - MARGIN;
  const ops = () => pages[pages.length - 1];
  const newPage = () => { pages.push([]); y = PAGE_H - MARGIN; };
  const ensure = (h: number) => { if (y - h < BOTTOM) newPage(); };
  const text = (x: number, yy: number, s: string, size: number, bold = false, color: Rgb = INK) =>
    ops().push(`BT ${rgb(color)} /${bold ? "F2" : "F1"} ${size} Tf ${x.toFixed(1)} ${yy.toFixed(1)} Td (${esc(s)}) Tj ET`);
  const rect = (x: number, yy: number, w: number, h: number, color: Rgb) => ops().push(`${rgb(color)} ${x.toFixed(1)} ${yy.toFixed(1)} ${w.toFixed(1)} ${h.toFixed(1)} re f`);
  const hline = (yy: number, color: Rgb = LINE, x = MARGIN, w = CONTENT_W, width = 0.6) =>
    ops().push(`${rgb(color, true)} ${width} w ${x} ${yy.toFixed(1)} m ${x + w} ${yy.toFixed(1)} l S`);
  const para = (s: string, size: number, color: Rgb, x = MARGIN, width = CONTENT_W, bold = false) => {
    for (const line of wrap(s, size, width, bold)) {
      ensure(size + 4);
      text(x, y - size, line, size, bold, color);
      y -= size * 1.42;
    }
  };

  for (const b of blocks) {
    switch (b.t) {
      case "cover": {
        const h = 150 + b.meta.length * 13;
        rect(0, PAGE_H - h, PAGE_W, h, DARK);
        rect(0, PAGE_H - h, PAGE_W, 4, ORANGE);
        rect(PAGE_W * 0.55, PAGE_H - h, PAGE_W * 0.45, 4, VIOLET);
        text(MARGIN, PAGE_H - 62, "RUYASHIELD", 9, true, ORANGE);
        let yy = PAGE_H - 92;
        for (const line of wrap(b.title, 24, CONTENT_W, true)) { text(MARGIN, yy, line, 24, true, [1, 1, 1]); yy -= 28; }
        if (b.subtitle) { text(MARGIN, yy - 2, b.subtitle, 11, false, [0.8, 0.78, 0.9]); yy -= 18; }
        for (const m of b.meta) { text(MARGIN, yy - 6, m, 9, false, [0.7, 0.68, 0.8]); yy -= 13; }
        y = PAGE_H - h - 26;
        break;
      }
      case "h1":
        ensure(48);
        y -= 10;
        text(MARGIN, y - 15, b.text, 15, true, INK);
        y -= 22;
        hline(y, ORANGE, MARGIN, 36, 2);
        y -= 12;
        break;
      case "h2":
        ensure(30);
        text(MARGIN, y - 11, b.text, 11, true, INK);
        y -= 18;
        break;
      case "p":
        para(b.text, b.size ?? 10, b.muted ? MUTED : INK);
        y -= 4;
        break;
      case "bullets":
        for (const item of b.items) {
          const lines = wrap(item, 9.5, CONTENT_W - 14);
          ensure(lines.length * 13 + 2);
          rect(MARGIN + 2, y - 8, 3, 3, b.muted ? MUTED : VIOLET);
          for (const line of lines) { text(MARGIN + 14, y - 9.5, line, 9.5, false, b.muted ? MUTED : INK); y -= 13.4; }
        }
        y -= 4;
        break;
      case "stats": {
        const per = 4, gap = 8, w = (CONTENT_W - gap * (per - 1)) / per, h = 50;
        for (let i = 0; i < b.items.length; i += per) {
          ensure(h + gap);
          b.items.slice(i, i + per).forEach((s, j) => {
            const x = MARGIN + j * (w + gap);
            rect(x, y - h, w, h, [0.965, 0.96, 0.985]);
            rect(x, y - h, 3, h, s.tone ?? VIOLET);
            text(x + 10, y - 16, s.label.toUpperCase(), 7, true, MUTED);
            text(x + 10, y - 38, s.value, 17, true, s.tone ?? INK);
          });
          y -= h + gap;
        }
        y -= 4;
        break;
      }
      case "table": {
        const total = b.widths.reduce((a, c) => a + c, 0);
        const cols = b.widths.map((w) => (w / total) * CONTENT_W);
        const head = () => {
          ensure(22);
          rect(MARGIN, y - 17, CONTENT_W, 17, [0.94, 0.93, 0.97]);
          let x = MARGIN;
          b.head.forEach((h, i) => { text(x + 5, y - 12, h.toUpperCase(), 7.5, true, MUTED); x += cols[i]; });
          y -= 19;
        };
        head();
        for (const row of b.rows) {
          const cells = row.map((cell, i) => wrap(cell ?? "", 8.5, cols[i] - 10));
          const h = Math.max(...cells.map((c) => c.length)) * 11.5 + 6;
          if (y - h < BOTTOM) { newPage(); head(); }
          let x = MARGIN;
          cells.forEach((lines, i) => {
            lines.forEach((line, k) => text(x + 5, y - 10 - k * 11.5, line, 8.5, i === 0, INK));
            x += cols[i];
          });
          y -= h;
          hline(y + 1);
        }
        if (!b.rows.length) { text(MARGIN + 5, y - 11, "None.", 8.5, false, MUTED); y -= 16; }
        y -= 8;
        break;
      }
      case "finding": {
        const titleLines = wrap(b.title, 10, CONTENT_W - 78, true);
        const metaLines = wrap(b.meta, 8, CONTENT_W - 78);
        const bodyLines = b.body ? wrap(b.body, 8.5, CONTENT_W - 78) : [];
        const h = titleLines.length * 13 + metaLines.length * 10.5 + (bodyLines.length ? bodyLines.length * 11.5 + 6 : 0) + 12;
        ensure(h + 6);
        const color = SEVERITY_COLOR[b.severity] ?? MUTED;
        rect(MARGIN, y - 14, 62, 14, color);
        const label = b.severity.toUpperCase();
        text(MARGIN + (62 - textWidth(label, 7, true)) / 2, y - 10, label, 7, true, [1, 1, 1]);
        let yy = y - 10;
        for (const l of titleLines) { text(MARGIN + 74, yy, l, 10, true, INK); yy -= 13; }
        for (const l of metaLines) { text(MARGIN + 74, yy + 1, l, 8, false, MUTED); yy -= 10.5; }
        if (bodyLines.length) {
          yy -= 3;
          for (const l of bodyLines) { text(MARGIN + 74, yy, l, 8.5, false, INK); yy -= 11.5; }
        }
        y = yy - 4;
        hline(y + 2);
        y -= 6;
        break;
      }
      case "note": {
        const lines = wrap(b.text, 8.5, CONTENT_W - 24);
        const h = lines.length * 11.5 + 14;
        ensure(h + 6);
        rect(MARGIN, y - h, CONTENT_W, h, [1, 0.96, 0.92]);
        rect(MARGIN, y - h, 3, h, ORANGE);
        lines.forEach((l, k) => text(MARGIN + 13, y - 14 - k * 11.5, l, 8.5, false, INK));
        y -= h + 10;
        break;
      }
      case "space":
        y -= b.h ?? 10;
        break;
    }
  }

  // Footer on every page.
  pages.forEach((p, i) => {
    p.push(`${rgb(LINE, true)} 0.6 w ${MARGIN} 40 m ${PAGE_W - MARGIN} 40 l S`);
    p.push(`BT ${rgb(MUTED)} /F1 7.5 Tf ${MARGIN} 28 Td (${esc(footer)}) Tj ET`);
    const n = `Page ${i + 1} of ${pages.length}`;
    p.push(`BT ${rgb(MUTED)} /F1 7.5 Tf ${(PAGE_W - MARGIN - textWidth(n, 7.5)).toFixed(1)} 28 Td (${esc(n)}) Tj ET`);
  });

  const objs: string[] = [];
  const pageIds = pages.map((_, i) => 5 + i * 2);
  objs[1] = "<< /Type /Catalog /Pages 2 0 R >>";
  objs[2] = `<< /Type /Pages /Kids [${pageIds.map((id) => `${id} 0 R`).join(" ")}] /Count ${pages.length} >>`;
  objs[3] = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>";
  objs[4] = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>";
  pages.forEach((p, i) => {
    const stream = p.join("\n");
    objs[pageIds[i]] = `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${PAGE_W} ${PAGE_H}] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents ${pageIds[i] + 1} 0 R >>`;
    objs[pageIds[i] + 1] = `<< /Length ${Buffer.byteLength(stream, "latin1")} >>\nstream\n${stream}\nendstream`;
  });
  let out = "%PDF-1.4\n";
  const offsets: number[] = [];
  for (let i = 1; i < objs.length; i++) {
    offsets[i] = Buffer.byteLength(out, "latin1");
    out += `${i} 0 obj\n${objs[i]}\nendobj\n`;
  }
  const xref = Buffer.byteLength(out, "latin1");
  out += `xref\n0 ${objs.length}\n0000000000 65535 f \n${offsets.slice(1).map((o) => `${String(o).padStart(10, "0")} 00000 n \n`).join("")}`;
  out += `trailer\n<< /Size ${objs.length} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return Buffer.from(out, "latin1");
}
