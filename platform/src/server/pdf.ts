// Minimal PDF writer: Helvetica, A4, plain text lines (non-ASCII becomes "?"). No external PDF dependency.

export function textPdf(lines: string[]): Buffer {
  const wrapped = lines.flatMap((l) => {
    const s = l.replace(/[^\x20-\x7e]/g, "?");
    const out: string[] = [];
    for (let i = 0; i < s.length || i === 0; i += 95) out.push(s.slice(i, i + 95));
    return out;
  });
  const esc = (s: string) => s.replace(/[\\()]/g, (m) => `\\${m}`);
  const perPage = 60;
  const pages: string[][] = [];
  for (let i = 0; i < wrapped.length; i += perPage) pages.push(wrapped.slice(i, i + perPage));

  const objs: string[] = [];
  const pageIds = pages.map((_, i) => 4 + i * 2);
  objs[1] = "<< /Type /Catalog /Pages 2 0 R >>";
  objs[2] = `<< /Type /Pages /Kids [${pageIds.map((p) => `${p} 0 R`).join(" ")}] /Count ${pages.length} >>`;
  objs[3] = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>";
  pages.forEach((p, i) => {
    const stream = `BT /F1 10 Tf 13 TL 50 800 Td ${p.map((l, j) => `${j ? "T* " : ""}(${esc(l)}) Tj`).join(" ")} ET`;
    objs[pageIds[i]] = `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R >> >> /Contents ${pageIds[i] + 1} 0 R >>`;
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
