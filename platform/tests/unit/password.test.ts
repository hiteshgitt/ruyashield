import { describe, expect, it } from "vitest";
import { hashPassword, passwordProblem, verifyPassword } from "@/server/auth/password";

describe("password hashing", () => {
  it("verifies the right password and rejects others", async () => {
    const h = await hashPassword("correct horse battery");
    expect(h.startsWith("scrypt$")).toBe(true);
    expect(await verifyPassword("correct horse battery", h)).toBe(true);
    expect(await verifyPassword("correct horse batterY", h)).toBe(false);
    expect(await verifyPassword("x", "not-a-hash")).toBe(false);
  });
  it("salts every hash", async () => {
    expect(await hashPassword("same password here")).not.toBe(await hashPassword("same password here"));
  });
  it("refuses short, common and email-based passwords", () => {
    expect(passwordProblem("short")).toMatch(/at least/);
    expect(passwordProblem("password123")).toMatch(/common/);
    expect(passwordProblem("aaaaaaaaaaaa")).toMatch(/common/);
    expect(passwordProblem("hitesh-2026-secure", "hitesh@example.com")).toMatch(/email/);
    expect(passwordProblem("a long and unusual phrase")).toBeNull();
  });
});
