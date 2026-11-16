import { afterEach, describe, expect, it, vi } from "vitest";
import { amrHasMfa, providerKind, safeReturnTo } from "@/server/auth/login";

describe("safeReturnTo", () => {
  it.each(["/assets", "/invite/abc?x=1"])("keeps %s", (v) => expect(safeReturnTo(v)).toBe(v));
  it.each(["https://evil.com", "//evil.com", "/\\evil.com", "assets", "", undefined, 42, "/" + "a".repeat(600)])(
    "replaces %j with /", (v) => expect(safeReturnTo(v)).toBe("/"));
});

describe("amrHasMfa", () => {
  it("fails closed", () => {
    expect(amrHasMfa(undefined)).toBe(false);
    expect(amrHasMfa([])).toBe(false);
    expect(amrHasMfa(["pwd"])).toBe(false);
    expect(amrHasMfa(["pwd", "otp"])).toBe(true);
    expect(amrHasMfa(["hwk"])).toBe(true);
  });
});

describe("providerKind", () => {
  afterEach(() => vi.unstubAllEnvs());
  it("refuses the dev provider in production", () => {
    vi.stubEnv("AUTH_PROVIDER", "dev");
    vi.stubEnv("NODE_ENV", "production");
    expect(() => providerKind()).toThrow(/refused in production/);
  });
  it("defaults to oidc", () => {
    vi.stubEnv("AUTH_PROVIDER", "");
    expect(providerKind()).toBe("oidc");
  });
});
