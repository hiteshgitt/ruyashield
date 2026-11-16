import { createHmac, timingSafeEqual } from "node:crypto";

// Provisional WebMonitor adapter (DEP-WM-01 / D-14). No WebMonitor contract is agreed, so this module defines
// RuyaShield's own side only: how an inbound handoff is authenticated, and where a minimal result summary would be
// sent. Nothing here describes a real WebMonitor API. Until a contract exists the outbound side records
// "no_contract" instead of sending anything.

export const HANDOFF_TOLERANCE_MS = 5 * 60_000;
export const MIN_SECRET_LENGTH = 32;

export type HandoffAuth = { ok: true } | { ok: false; status: 401 | 503; code: "bad_signature" | "stale_timestamp" | "handoffs_disabled" };

/** The only fields that ever leave RuyaShield about a referral (FR-042): status and a link, never evidence. */
export type ResultSummary = {
  externalRef: string;
  assessmentStatus: string | null;
  severityCounts: Record<"critical" | "high" | "medium" | "low" | "info", number> | null;
  fixproofStatus: string | null;
  link: string;
};

export type PublishResult = { sent: true } | { sent: false; reason: string };

export interface WebMonitorAdapter {
  verifyHandoff(h: { timestamp?: string | null; signature?: string | null }, body: string, now?: number): HandoffAuth;
  publishResult(summary: ResultSummary): Promise<PublishResult>;
}

function secret(): string | null {
  const s = process.env.WEBMONITOR_HANDOFF_SECRET ?? "";
  return s.length >= MIN_SECRET_LENGTH ? s : null;
}

/** `sha256=<hex>` of HMAC-SHA256 over `${timestamp}.${body}`; the same shape as the repository webhook. */
export function signHandoff(timestamp: string, body: string, key: string): string {
  return `sha256=${createHmac("sha256", key).update(`${timestamp}.${body}`).digest("hex")}`;
}

export function verifyHandoffSignature(h: { timestamp?: string | null; signature?: string | null }, body: string, key: string | null, now = Date.now()): HandoffAuth {
  if (!key) return { ok: false, status: 503, code: "handoffs_disabled" };
  if (!h.timestamp || !h.signature || !/^\d{1,13}$/.test(h.timestamp)) return { ok: false, status: 401, code: "bad_signature" };
  if (Math.abs(now - Number(h.timestamp) * 1000) > HANDOFF_TOLERANCE_MS) return { ok: false, status: 401, code: "stale_timestamp" };
  const expected = Buffer.from(signHandoff(h.timestamp, body, key));
  const given = Buffer.from(h.signature);
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) return { ok: false, status: 401, code: "bad_signature" };
  return { ok: true };
}

/** Default: inbound handoffs are verified with the shared secret; outbound publishing is off (no contract). */
export const provisionalAdapter: WebMonitorAdapter = {
  verifyHandoff: (h, body, now) => verifyHandoffSignature(h, body, secret(), now),
  publishResult: async () => ({ sent: false, reason: "no_contract" }),
};

let current: WebMonitorAdapter = provisionalAdapter;
export const webmonitorAdapter = () => current;
/** Tests only. */
export function setWebMonitorAdapter(a: WebMonitorAdapter | null) { current = a ?? provisionalAdapter; }
