import { createHash } from "node:crypto";
import { eq } from "drizzle-orm";
import type { Tx } from "../db/client";
import { evidenceItems } from "../db/schema";
import { redactString } from "../log";

// Evidence (RS-FIND-002). Stored in Postgres behind this module; object storage with SSE-KMS is not implemented.
//
// Two redaction layers:
// - at capture, credentials (cookies, authorization, tokens, keys) are removed before anything is stored, so
//   no tier of evidence ever holds a credential;
// - at display, personal data (emails, phone numbers) is masked as well. The stored body ("raw") is only
//   served to roles with evidence.download_raw, and every download is audited.

export const MAX_EVIDENCE_BYTES = 5 * 1024 * 1024;
export const REDACTED = "[REDACTED]";
const SECRET_KEY = /(cookie|authorization|token|secret|passw|api[_-]?key|session|private[_-]?key|credential)/i;
const SECRET_HEADER_LINE = /^(\s*)(set-cookie|cookie|authorization|proxy-authorization|x-api-key)(\s*:).*$/gim;
const EMAIL = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
// Separators required and dots excluded, so IP addresses, versions and ISO dates are left alone.
const PHONE = /(?<![\w.])\+?\d{1,3}[\s-]\(?\d{2,4}\)?[\s-]\d{3,4}(?:[\s-]\d{3,4})?(?![\w.])/g;
// Keys whose values change between runs without the issue changing (used for the stable evidence class).
const VOLATILE_KEYS = new Set(["daysRemaining", "address", "addresses", "date", "age", "capturedAt", "checkedAt", "expires", "requestId", "durationMs"]);

/** JSON with object keys sorted, so equal content always hashes equally. */
export function canonicalJson(v: unknown): string {
  return JSON.stringify(sortKeys(v));
}
function sortKeys(v: unknown, skip?: ReadonlySet<string>): unknown {
  if (Array.isArray(v)) return v.map((x) => sortKeys(x, skip));
  if (v && typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(v).sort()) if (!skip?.has(k)) out[k] = sortKeys((v as Record<string, unknown>)[k], skip);
    return out;
  }
  return v;
}

export const sha256 = (s: string) => createHash("sha256").update(s, "utf8").digest("hex");

function mapStrings(v: unknown, f: (s: string) => string, depth = 0): unknown {
  if (depth > 20) return "[TRUNCATED]";
  if (typeof v === "string") return f(v);
  if (Array.isArray(v)) return v.map((x) => mapStrings(x, f, depth + 1));
  if (v && typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(v)) out[k] = SECRET_KEY.test(k) ? REDACTED : mapStrings(x, f, depth + 1);
    return out;
  }
  return v;
}

const secretText = (s: string) => redactString(s.replace(SECRET_HEADER_LINE, `$1$2$3 ${REDACTED}`));
const personalText = (s: string) => s.replace(EMAIL, "[REDACTED_EMAIL]").replace(PHONE, (m) => (m.replace(/\D/g, "").length >= 9 ? "[REDACTED_PHONE]" : m));

/** Removes credentials. Applied before evidence is stored. */
export function redactSecrets(body: string, contentType: string): string {
  if (contentType.startsWith("application/json")) {
    try { return JSON.stringify(mapStrings(JSON.parse(body), secretText)); } catch { /* not JSON: treat as text */ }
  }
  return secretText(body);
}

/** Full display redaction: credentials and personal data. Untrusted content stays data; it is never interpreted. */
export function redactEvidence(body: string, contentType: string): string {
  if (contentType.startsWith("application/json")) {
    try { return JSON.stringify(mapStrings(JSON.parse(body), (s) => personalText(secretText(s))), null, 2); } catch { /* fall through */ }
  }
  return personalText(secretText(body));
}

/** Stable class of an observation: same issue, same evidence modulo volatile values (timestamps, counters, IPs). */
export function evidenceClass(evidence: unknown): string {
  return sha256(JSON.stringify(sortKeys(evidence, VOLATILE_KEYS)));
}

export interface StoredEvidence { id: string; sha256: string }

/** Stores redacted, size-capped evidence. sha256 covers the stored body; size_bytes is the original size. */
export async function storeEvidence(tx: Tx, e: { orgId: string; assessmentId?: string | null; checkRunId?: string | null; contentType?: string; body: unknown }): Promise<StoredEvidence> {
  const contentType = e.contentType ?? "application/json";
  const text = typeof e.body === "string" ? e.body : canonicalJson(e.body);
  const original = Buffer.byteLength(text, "utf8");
  let body = redactSecrets(text, contentType);
  const truncated = Buffer.byteLength(body, "utf8") > MAX_EVIDENCE_BYTES;
  if (truncated) body = Buffer.from(body, "utf8").subarray(0, MAX_EVIDENCE_BYTES).toString("utf8").replace(/�$/, "");
  const hash = sha256(body);
  const row = (await tx.insert(evidenceItems).values({
    orgId: e.orgId, sha256: hash, contentType, sizeBytes: original, truncated, body,
    assessmentId: e.assessmentId ?? null, checkRunId: e.checkRunId ?? null,
  }).returning({ id: evidenceItems.id }))[0];
  return { id: row.id, sha256: hash };
}

export const verifyIntegrity = (e: { body: string; sha256: string }) => sha256(e.body) === e.sha256;

export async function loadEvidence(tx: Tx, id: string) {
  return (await tx.select().from(evidenceItems).where(eq(evidenceItems.id, id)))[0];
}
