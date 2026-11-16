import { createHash } from "node:crypto";
import { isIP } from "node:net";
import { classify, splitPath, type AttackType } from "./classify";

/**
 * Parses access-log lines in the Apache/nginx "combined" (or "common") format:
 *   1.2.3.4 - - [10/Nov/2026:13:55:36 +0000] "GET /path?q HTTP/1.1" 404 512 "referer" "user-agent"
 * Lines that do not parse, or that look benign, are dropped and never stored. The raw line is never kept.
 */
export interface ParsedEvent {
  occurredAt: Date; ip: string; method: string | null; path: string; status: number | null;
  userAgent: string | null; attackType: AttackType; dedupeKey: string;
}

const LINE = /^(\S+) \S+ \S+ \[([^\]]+)\] "([^"]*)" (\d{3}|-) (\S+)(?: "([^"]*)" "([^"]*)")?/;
const MONTHS: Record<string, number> = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };

export function parseClfDate(s: string): Date | null {
  const m = /^(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})$/.exec(s);
  if (!m || MONTHS[m[2]] === undefined) return null;
  const off = (Number(m[8]) * 60 + Number(m[9])) * (m[7] === "+" ? 1 : -1);
  const t = Date.UTC(Number(m[3]), MONTHS[m[2]], Number(m[1]), Number(m[4]), Number(m[5]), Number(m[6])) - off * 60_000;
  return Number.isFinite(t) ? new Date(t) : null;
}

export function parseLine(line: string, now = new Date()): ParsedEvent | null {
  if (line.length > 8192) return null;
  const m = LINE.exec(line);
  if (!m) return null;
  const ip = m[1].replace(/^::ffff:/, "");
  if (!isIP(ip)) return null;
  const at = parseClfDate(m[2]);
  // Reject timestamps from the future (clock skew > 1h) or older than the retention window.
  if (!at || at.getTime() > now.getTime() + 3_600_000 || at.getTime() < now.getTime() - 90 * 86_400_000) return null;
  const req = m[3].split(" ");
  const method = req.length >= 2 && /^[A-Z]{3,10}$/.test(req[0]) ? req[0] : null;
  const target = method ? req[1] ?? "/" : m[3];
  const status = m[4] === "-" ? null : Number(m[4]);
  const userAgent = m[7] && m[7] !== "-" ? m[7].slice(0, 200) : null;
  const type = classify({ method, target, status, userAgent });
  if (!type) return null;
  const dedupeKey = createHash("sha256").update(line).digest("hex").slice(0, 40);
  return { occurredAt: at, ip, method, path: splitPath(target), status, userAgent, attackType: type, dedupeKey };
}

export const MAX_LINES_PER_BATCH = 5000;

export function parseBatch(lines: string[], now = new Date()): { events: ParsedEvent[]; received: number; unparsed: number } {
  const events: ParsedEvent[] = [];
  let unparsed = 0;
  const seen = new Set<string>();
  for (const l of lines.slice(0, MAX_LINES_PER_BATCH)) {
    if (!LINE.test(l)) { if (l.trim()) unparsed++; continue; }
    const e = parseLine(l, now);
    if (e && !seen.has(e.dedupeKey)) { seen.add(e.dedupeKey); events.push(e); }
  }
  return { events, received: Math.min(lines.length, MAX_LINES_PER_BATCH), unparsed };
}
