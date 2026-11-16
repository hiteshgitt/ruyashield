import { createHmac, timingSafeEqual } from "node:crypto";

/** What a worker is allowed to run: one assessment of one org, bound to one scope hash, until exp. */
export interface JobClaims { org: string; assessment: string; sha: string; exp: number }

function secret(): Buffer {
  const s = process.env.JOB_TOKEN_SECRET;
  // Fail closed: without a real secret no job token can be issued or accepted.
  if (!s || s.length < 32) throw new Error("JOB_TOKEN_SECRET is missing or shorter than 32 characters");
  return Buffer.from(s);
}

const mac = (body: string) => createHmac("sha256", secret()).update(body).digest("base64url");

export function signJobToken(c: JobClaims): string {
  const body = Buffer.from(JSON.stringify([c.org, c.assessment, c.sha, c.exp])).toString("base64url");
  return `${body}.${mac(body)}`;
}

export type TokenCheck = { ok: true } | { ok: false; reason: "malformed" | "bad_signature" | "mismatch" | "expired" };

export function verifyJobToken(token: unknown, expect: Omit<JobClaims, "exp">, now = Date.now()): TokenCheck {
  if (typeof token !== "string") return { ok: false, reason: "malformed" };
  const [body, sig, extra] = token.split(".");
  if (!body || !sig || extra !== undefined) return { ok: false, reason: "malformed" };
  const want = Buffer.from(mac(body));
  const got = Buffer.from(sig);
  if (want.length !== got.length || !timingSafeEqual(want, got)) return { ok: false, reason: "bad_signature" };
  let c: unknown;
  try { c = JSON.parse(Buffer.from(body, "base64url").toString()); } catch { return { ok: false, reason: "malformed" }; }
  if (!Array.isArray(c) || c.length !== 4) return { ok: false, reason: "malformed" };
  const [org, assessment, sha, exp] = c;
  if (org !== expect.org || assessment !== expect.assessment || sha !== expect.sha) return { ok: false, reason: "mismatch" };
  if (typeof exp !== "number" || exp < now) return { ok: false, reason: "expired" };
  return { ok: true };
}
