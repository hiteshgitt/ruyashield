import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

// RFC 6238 authenticator codes (HMAC-SHA1, 30 s steps, 6 digits): what Google Authenticator, Microsoft
// Authenticator, 1Password, Authy and others expect from an otpauth:// QR code.

export const TOTP_STEP_S = 30;
export const TOTP_DIGITS = 6;
/** Accept the previous and next step too, for clock drift between phone and server. */
export const TOTP_WINDOW = 1;

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Encode(buf: Buffer): string {
  let bits = 0, value = 0, out = "";
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(s: string): Buffer {
  const clean = s.replace(/[\s=-]/g, "").toUpperCase();
  let bits = 0, value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const i = ALPHABET.indexOf(ch);
    if (i < 0) throw new Error("invalid_base32");
    value = (value << 5) | i;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/** A new 160-bit secret, base32 (the form authenticator apps take). */
export const newTotpSecret = () => base32Encode(randomBytes(20));

export const stepAt = (now: number) => Math.floor(now / 1000 / TOTP_STEP_S);

export function codeAt(secret: string, step: number): string {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const h = createHmac("sha1", base32Decode(secret)).update(counter).digest();
  const offset = h[h.length - 1] & 15;
  const bin = ((h[offset] & 127) << 24) | (h[offset + 1] << 16) | (h[offset + 2] << 8) | h[offset + 3];
  return String(bin % 10 ** TOTP_DIGITS).padStart(TOTP_DIGITS, "0");
}

/**
 * Returns the matching step, or null. Steps at or before `lastStep` are refused, so a code that was
 * already used (or an older one) cannot be replayed within its window.
 */
export function verifyTotp(secret: string, code: string, lastStep: number, now = Date.now()): number | null {
  const c = code.replace(/\s/g, "");
  if (!/^\d{6}$/.test(c)) return null;
  const current = stepAt(now);
  for (let d = -TOTP_WINDOW; d <= TOTP_WINDOW; d++) {
    const step = current + d;
    if (step <= lastStep) continue;
    const expected = Buffer.from(codeAt(secret, step));
    if (timingSafeEqual(expected, Buffer.from(c))) return step;
  }
  return null;
}

export function otpauthUri(secret: string, account: string, issuer = "RuyaShield"): string {
  const label = encodeURIComponent(`${issuer}:${account}`);
  const q = new URLSearchParams({ secret, issuer, algorithm: "SHA1", digits: String(TOTP_DIGITS), period: String(TOTP_STEP_S) });
  return `otpauth://totp/${label}?${q}`;
}
