import { describe, expect, it } from "vitest";
import { assertNotPrivate, parseHost } from "@/server/assets/host";
import { isBlockedIp, isIpLiteral } from "@/server/net/ip";

describe("parseHost", () => {
  it("canonicalises URLs and case", () => {
    expect(parseHost("https://Shop.Acme.com/path?q=1")).toBe("shop.acme.com");
    expect(parseHost("  acme.co.uk. ")).toBe("acme.co.uk");
    expect(parseHost("bücher.de")).toBe("xn--bcher-kva.de");
  });

  it.each([
    "", "localhost", "intranet", "10.0.0.1", "http://127.0.0.1/", "[::1]", "0x7f000001", "2130706433.com.1",
    "acme.com:8080", "user:pw@acme.com", "printer.local", "app.internal", "shop.test", "www.example",
    "-bad.com", "a..b.com", "x".repeat(64) + ".com",
  ])("rejects %j", (input) => {
    expect(() => parseHost(input)).toThrow(expect.objectContaining({ code: "invalid_target" }));
  });
});

describe("isBlockedIp", () => {
  it.each(["127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fc00::1", "fe80::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1"])(
    "blocks %s", (ip) => expect(isBlockedIp(ip)).toBe(true));
  it.each(["93.184.216.34", "1.1.1.1", "2606:4700:4700::1111"])("allows %s", (ip) => expect(isBlockedIp(ip)).toBe(false));
  it("treats unparseable input as blocked", () => expect(isBlockedIp("not-an-ip")).toBe(true));
  it("detects literals", () => {
    expect(isIpLiteral("[::1]")).toBe(true);
    expect(isIpLiteral("acme.com")).toBe(false);
  });
});

describe("assertNotPrivate", () => {
  it("rejects names that resolve to private addresses (including mixed answers)", async () => {
    const resolve = async () => [{ address: "93.184.216.34", family: 4 as const }, { address: "10.0.0.5", family: 4 as const }];
    await expect(assertNotPrivate("acme.com", { resolve })).rejects.toMatchObject({ code: "invalid_target" });
  });
  it("allows unresolvable names (pre-launch)", async () => {
    await expect(assertNotPrivate("acme.com", { resolve: async () => { throw new Error("ENOTFOUND"); } })).resolves.toBeUndefined();
  });
});
