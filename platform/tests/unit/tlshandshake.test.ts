import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import https from "node:https";
import tls from "node:tls";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { guardedGet, tlsHandshake } from "@/server/net/egress";

// Real handshakes against a local TLS server with a throwaway self-signed 1024-bit RSA certificate that accepts
// TLS 1.0 – 1.2 only, so pinned-version probes, key size and "refused" all go through OpenSSL for real.
let server: tls.Server;
let port = 0;
let web: https.Server;
let webPort = 0;
let dir = "";
const haveOpenssl = (() => { try { execFileSync("openssl", ["version"]); return true; } catch { return false; } })();
const run = haveOpenssl ? describe : describe.skip;
const deps = () => ({ allowPrivate: true, port, resolve: async () => [{ address: "127.0.0.1", family: 4 as const }], timeoutMs: 3000 });

beforeAll(async () => {
  if (!haveOpenssl) return;
  dir = mkdtempSync(join(tmpdir(), "ruya-tls-"));
  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:1024", "-nodes", "-keyout", join(dir, "k.pem"), "-out", join(dir, "c.pem"), "-days", "1", "-subj", "/CN=site.test"], { stdio: "ignore" });
  server = tls.createServer({ key: readFileSync(join(dir, "k.pem")), cert: readFileSync(join(dir, "c.pem")), minVersion: "TLSv1", maxVersion: "TLSv1.2", ciphers: "ALL:@SECLEVEL=0" }, (s) => s.end());
  server.on("tlsClientError", () => {});
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  port = (server.address() as AddressInfo).port;
  web = https.createServer({ key: readFileSync(join(dir, "k.pem")), cert: readFileSync(join(dir, "c.pem")), ciphers: "ALL:@SECLEVEL=0" }, (_q, res) => { res.writeHead(200, { "x-frame-options": "DENY" }); res.end("ok"); });
  web.on("tlsClientError", () => {});
  await new Promise<void>((r) => web.listen(0, "127.0.0.1", r));
  webPort = (web.address() as AddressInfo).port;
});
afterAll(() => { server?.close(); web?.close(); if (dir) rmSync(dir, { recursive: true, force: true }); });

run("tlsHandshake (local server)", () => {
  it("records protocol, key size and the untrusted certificate", async () => {
    const r = await tlsHandshake("site.test", { ciphers: "DEFAULT:@SECLEVEL=0" }, deps());
    expect(r).toMatchObject({ outcome: "accepted", protocol: "TLSv1.2", keyType: "RSA", keyBits: 1024, pinnedAddress: "127.0.0.1" });
    if (r.outcome === "accepted") expect(r.authorizationError).toBeTruthy();
  });

  it("negotiates a pinned legacy version the server still allows", async () => {
    expect(await tlsHandshake("site.test", { minVersion: "TLSv1", maxVersion: "TLSv1", ciphers: "DEFAULT:@SECLEVEL=0" }, deps())).toMatchObject({ outcome: "accepted", protocol: "TLSv1" });
  });

  it("reports a version the server does not speak as refused", async () => {
    expect(await tlsHandshake("site.test", { minVersion: "TLSv1.3", maxVersion: "TLSv1.3" }, deps())).toMatchObject({ outcome: "refused" });
  });

  it("calls onHop and refuses IP literals in production mode", async () => {
    const hops: string[] = [];
    await tlsHandshake("site.test", { ciphers: "DEFAULT:@SECLEVEL=0" }, { ...deps(), onHop: (u) => { hops.push(u.hostname); } });
    expect(hops).toEqual(["site.test"]);
    await expect(tlsHandshake("127.0.0.1", {}, {})).rejects.toMatchObject({ code: "egress_blocked" });
  });

  it("guardedGet refuses a weak, untrusted certificate by default and reads it only with tlsLenient", async () => {
    const url = `https://site.test:${webPort}/`;
    const d = { allowPrivate: true, resolve: async () => [{ address: "127.0.0.1", family: 4 as const }], timeoutMs: 3000 };
    await expect(guardedGet(url, d)).rejects.toMatchObject({ code: "network" });
    const r = await guardedGet(url, { ...d, tlsLenient: true });
    expect(r).toMatchObject({ status: 200, body: "ok" });
    expect(r.headers["x-frame-options"]).toBe("DENY");
  });
});
