// Structured JSON logger with secret redaction (RS-PLAT-003).
const SECRET_KEY = /(pass(word)?|secret|token|authorization|cookie|api[_-]?key|code_verifier|session|private[_-]?key)/i;
const SECRET_VALUE = [
  /\bBearer\s+[A-Za-z0-9._~+/=-]+/g,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, // JWT
  /\b(gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})\b/g,
  /(postgres(ql)?:\/\/[^:\s]+:)[^@\s]+@/g,
];

export function redactString(s: string): string {
  let out = s;
  for (const re of SECRET_VALUE) {
    out = out.replace(re, (m, p1) => (typeof p1 === "string" && m.startsWith(p1) && p1.includes("://") ? `${p1}[REDACTED]@` : "[REDACTED]"));
  }
  return out;
}

export function redact(value: unknown, depth = 0): unknown {
  if (depth > 6) return "[TRUNCATED]";
  if (typeof value === "string") return redactString(value);
  if (Array.isArray(value)) return value.map((v) => redact(v, depth + 1));
  if (value instanceof Error) return { name: value.name, message: redactString(value.message) };
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) out[k] = SECRET_KEY.test(k) ? "[REDACTED]" : redact(v, depth + 1);
    return out;
  }
  return value;
}

type Level = "debug" | "info" | "warn" | "error";
function emit(level: Level, msg: string, fields?: Record<string, unknown>) {
  if (level === "debug" && process.env.NODE_ENV === "production") return;
  const line = JSON.stringify({ ts: new Date().toISOString(), level, msg: redactString(msg), ...(redact(fields ?? {}) as object) });
  (level === "error" || level === "warn" ? console.error : console.log)(line);
}

export const log = {
  debug: (msg: string, f?: Record<string, unknown>) => emit("debug", msg, f),
  info: (msg: string, f?: Record<string, unknown>) => emit("info", msg, f),
  warn: (msg: string, f?: Record<string, unknown>) => emit("warn", msg, f),
  error: (msg: string, f?: Record<string, unknown>) => emit("error", msg, f),
};
