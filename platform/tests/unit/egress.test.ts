import http from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { devPort, guardedGet, lookupTxtEverywhere } from "@/server/net/egress";

// A local server stands in for a customer site. allowPrivate (dev/test only) lets us reach 127.0.0.1 on a high port;
// a fake resolver maps every name to it, so the host-name rules still apply.
let server: http.Server;
let port = 0;
const local = { allowPrivate: true, resolve: async () => [{ address: "127.0.0.1", family: 4 as const }], timeoutMs: 1500 };

beforeAll(async () => {
  server = http.createServer((req, res) => {
    switch (req.url) {
      case "/ok": res.end("hello"); break;
      case "/big": res.end("x".repeat(70 * 1024)); break;
      case "/hop": res.writeHead(302, { location: "/ok" }).end(); break;
      case "/offsite": res.writeHead(302, { location: `http://elsewhere.test:${port}/ok` }).end(); break;
      case "/loop": res.writeHead(302, { location: "/loop" }).end(); break;
      case "/slow": setTimeout(() => res.end("late"), 3000); break;
      default: res.writeHead(404).end();
    }
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  port = (server.address() as AddressInfo).port;
});
afterAll(() => { server.closeAllConnections(); server.close(); });

const u = (path: string) => `http://site.test:${port}${path}`;

describe("guardedGet refusals (production defaults)", () => {
  it.each([
    ["ftp://acme.com/x", "bad_url"],
    ["not a url", "bad_url"],
    ["https://user:pw@acme.com/", "bad_url"],
    ["https://acme.com:8443/", "bad_url"],
    ["http://127.0.0.1/", "egress_blocked"],
    ["http://[::1]/", "egress_blocked"],
  ])("%s -> %s", async (url, code) => {
    await expect(guardedGet(url)).rejects.toMatchObject({ code });
  });
  it("blocks names resolving to metadata/private ranges", async () => {
    const resolve = async () => [{ address: "169.254.169.254", family: 4 as const }];
    await expect(guardedGet("https://acme.com/", { resolve })).rejects.toMatchObject({ code: "egress_blocked" });
  });
});

describe("guardedGet against a local server", () => {
  it("fetches and pins the validated address", async () => {
    const r = await guardedGet(u("/ok"), local);
    expect(r).toMatchObject({ status: 200, body: "hello", redirects: 0, pinnedAddress: "127.0.0.1" });
  });
  it("follows same-host redirects", async () => {
    expect(await guardedGet(u("/hop"), local)).toMatchObject({ status: 200, redirects: 1 });
  });
  it("refuses cross-host redirects and redirect loops", async () => {
    await expect(guardedGet(u("/offsite"), local)).rejects.toMatchObject({ code: "redirect_refused" });
    await expect(guardedGet(u("/loop"), local)).rejects.toMatchObject({ code: "redirect_refused" });
  });
  it("reads only a prefix when truncateAt is set", async () => {
    const r = await guardedGet(u("/big"), { ...local, truncateAt: 512 });
    expect(r).toMatchObject({ status: 200, truncated: true });
    expect(r.body).toHaveLength(512);
    expect(await guardedGet(u("/ok"), { ...local, truncateAt: 512 })).toMatchObject({ body: "hello", truncated: false });
  });

  it("returns a 3xx as-is when followRedirects is false", async () => {
    expect(await guardedGet(u("/offsite"), { ...local, followRedirects: false })).toMatchObject({ status: 302, redirects: 0 });
  });

  it("caps the body at 64 KB", async () => {
    await expect(guardedGet(u("/big"), local)).rejects.toMatchObject({ code: "too_large" });
  });
  it("times out", async () => {
    await expect(guardedGet(u("/slow"), { ...local, timeoutMs: 300 })).rejects.toMatchObject({ code: "timeout" });
  });
});

describe("lookupTxtEverywhere", () => {
  it("joins chunked TXT records and separates no-data from failures", async () => {
    const r = await lookupTxtEverywhere("n", {
      resolvers: [["a"], ["b"], ["c"]],
      resolveTxt: async (_n, [s]) => {
        if (s === "a") return [["ruyashield-verify=", "abc"]];
        throw Object.assign(new Error(), { code: s === "b" ? "ENODATA" : "ESERVFAIL" });
      },
    });
    expect(r).toEqual([
      { resolver: "a", records: ["ruyashield-verify=abc"], error: null },
      { resolver: "b", records: [], error: null },
      { resolver: "c", records: null, error: "ESERVFAIL" },
    ]);
  });
});

describe("devPort (EGRESS_DEV_PORT_MAP)", () => {
  const saved = { map: process.env.EGRESS_DEV_PORT_MAP, env: process.env.NODE_ENV };
  afterEach(() => { process.env.EGRESS_DEV_PORT_MAP = saved.map; (process.env as Record<string, string | undefined>).NODE_ENV = saved.env; });

  it("remaps only loopback addresses, only with private egress allowed, never in production", () => {
    process.env.EGRESS_DEV_PORT_MAP = "443:8443, 80:8080";
    expect(devPort(443, "127.0.0.1", true)).toBe(8443);
    expect(devPort(80, "::1", true)).toBe(8080);
    expect(devPort(22, "::1", true)).toBe(22);
    expect(devPort(443, "10.0.0.5", true)).toBe(443);
    expect(devPort(443, "93.184.216.34", true)).toBe(443);
    expect(devPort(443, "127.0.0.1", false)).toBe(443);
    (process.env as Record<string, string | undefined>).NODE_ENV = "production";
    expect(devPort(443, "127.0.0.1", true)).toBe(443);
  });

  it("ignores a missing or malformed map", () => {
    delete process.env.EGRESS_DEV_PORT_MAP;
    expect(devPort(443, "127.0.0.1", true)).toBe(443);
    process.env.EGRESS_DEV_PORT_MAP = "443:abc,443:70000";
    expect(devPort(443, "127.0.0.1", true)).toBe(443);
  });
});
