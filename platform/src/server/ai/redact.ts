import { redactEvidence } from "../findings/evidence";

// Redaction for anything sent to an AI provider (blueprint §7, "redaction is versioned"). Runs on top of the
// display redaction (credentials + personal data), adding value patterns that may appear in page bodies or
// headers without a tell-tale key. Bump the version whenever a pattern changes; it is stored on every analysis.
export const AI_REDACTION_VERSION = "ai-redact/1";
export const AI_REDACTED = "[REDACTED:secret]";

const PATTERNS: RegExp[] = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)/g,
  /\b(sk|rk|pk)_(live|test)_[A-Za-z0-9]{10,}\b/g,                 // payment-provider style keys
  /\bsk-[A-Za-z0-9_-]{16,}\b/g,                                    // API keys of the sk-… form
  /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g,                               // GitHub tokens
  /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g,                             // Slack tokens
  /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g,                                  // AWS access key ids
  /\bAIza[0-9A-Za-z_-]{35}\b/g,                                    // Google API keys
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, // JWTs
  /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/gi,
  /\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@]+:[^\s@/]+@/gi,                 // credentials in URLs
];
// key=value / key: value where the key names a secret; the key is kept so the model knows something was there.
const ASSIGNMENT = /\b((?:[A-Za-z0-9_-]*?)(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|session(?:id)?|auth))(["']?\s*[:=]\s*["']?)([^\s"'&;,<>]{4,})/gi;

/** Redacts one string for a provider request. Idempotent. */
export function redactForAi(s: string, contentType = "text/plain"): string {
  let out = redactEvidence(s, contentType);
  for (const re of PATTERNS) out = out.replace(re, AI_REDACTED);
  return out.replace(ASSIGNMENT, (m, k: string, sep: string, v: string) => (v.startsWith("[REDACTED") ? m : `${k}${sep}${AI_REDACTED}`));
}

/** True when text still looks like it holds a credential. Used as a last check before anything leaves the service. */
export function containsSecret(s: string): boolean {
  return PATTERNS.some((re) => { re.lastIndex = 0; const hit = re.test(s); re.lastIndex = 0; return hit; });
}
