import { describe, expect, it } from "vitest";
import { base32Decode, base32Encode, codeAt, newTotpSecret, otpauthUri, stepAt, verifyTotp } from "@/server/auth/totp";

// RFC 6238 appendix B (SHA-1 seed "12345678901234567890"), last 6 of the 8-digit values.
const SEED = base32Encode(Buffer.from("12345678901234567890"));

describe("TOTP (RFC 6238)", () => {
  it("matches the RFC test vectors", () => {
    expect(SEED).toBe("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    expect(codeAt(SEED, stepAt(59_000))).toBe("287082");
    expect(codeAt(SEED, stepAt(1_111_111_109_000))).toBe("081804");
    expect(codeAt(SEED, stepAt(1_234_567_890_000))).toBe("005924");
    expect(codeAt(SEED, stepAt(2_000_000_000_000))).toBe("279037");
  });

  it("round-trips base32 and makes 160-bit secrets", () => {
    const s = newTotpSecret();
    expect(s).toMatch(/^[A-Z2-7]{32}$/);
    expect(base32Encode(base32Decode(s))).toBe(s);
  });

  it("accepts one step of drift, refuses replays and junk", () => {
    const now = 1_700_000_000_000;
    const step = stepAt(now);
    expect(verifyTotp(SEED, codeAt(SEED, step), 0, now)).toBe(step);
    expect(verifyTotp(SEED, codeAt(SEED, step - 1), 0, now)).toBe(step - 1);
    expect(verifyTotp(SEED, codeAt(SEED, step + 1), 0, now)).toBe(step + 1);
    expect(verifyTotp(SEED, codeAt(SEED, step - 2), 0, now)).toBeNull();
    // Already used this step (or later): refused.
    expect(verifyTotp(SEED, codeAt(SEED, step), step, now)).toBeNull();
    expect(verifyTotp(SEED, "12345", 0, now)).toBeNull();
    expect(verifyTotp(SEED, "abcdef", 0, now)).toBeNull();
  });

  it("builds an otpauth URI authenticator apps accept", () => {
    const u = new URL(otpauthUri(SEED, "a@b.com"));
    expect(u.protocol).toBe("otpauth:");
    expect(u.host).toBe("totp");
    expect(decodeURIComponent(u.pathname)).toBe("/RuyaShield:a@b.com");
    expect(u.searchParams.get("secret")).toBe(SEED);
    expect(u.searchParams.get("issuer")).toBe("RuyaShield");
  });
});
