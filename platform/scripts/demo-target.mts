// Local demo target for end-to-end scans (dev only). Stands in for "demo-shop.localhost" on loopback:
//   https -> :8443, http -> :8080 (the worker reaches them through EGRESS_DEV_PORT_MAP="443:8443,80:8080").
// Default mode is deliberately misconfigured: 1024-bit RSA key, TLS 1.0-1.2 only, anonymous ciphers allowed,
// /.git/HEAD and /.env exposed (fake canary values only), an open directory listing, no security headers,
// version banners, and plain HTTP served without a redirect.
// --fixed serves a corrected setup (2048-bit key, TLS 1.2-1.3, nothing exposed, security headers, HTTP -> HTTPS redirect)
// to show re-tests.
// Run: npx tsx scripts/demo-target.mts [--fixed]
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync } from "node:fs";
import http from "node:http";
import https from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";

const fixed = process.argv.includes("--fixed");
const HOST = "demo-shop.localhost";
const dir = join(tmpdir(), "ruya-demo-target");
mkdirSync(dir, { recursive: true });
const bits = fixed ? 2048 : 1024;
const key = join(dir, `k${bits}.pem`), cert = join(dir, `c${bits}.pem`);
execFileSync("openssl", ["req", "-x509", "-newkey", `rsa:${bits}`, "-nodes", "-keyout", key, "-out", cert, "-days", "30", "-subj", `/CN=${HOST}`, "-addext", `subjectAltName=DNS:${HOST}`], { stdio: "ignore" });

const SECURE_HEADERS = {
  "strict-transport-security": "max-age=31536000; includeSubDomains",
  "content-security-policy": "default-src 'self'",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "strict-origin-when-cross-origin",
};

function handler(req: http.IncomingMessage & { socket: { encrypted?: boolean } }, res: http.ServerResponse) {
  const path = (req.url ?? "/").split("?")[0];
  const base = { "content-type": "text/html; charset=utf-8", ...(fixed ? SECURE_HEADERS : { server: "Apache/2.4.29 (Ubuntu)", "x-powered-by": "PHP/7.2.24" }) };
  const send = (status: number, body: string, type?: string) => { res.writeHead(status, { ...base, ...(type ? { "content-type": type } : {}) }); res.end(body); };
  if (!fixed) {
    if (path === "/.git/HEAD") return send(200, "ref: refs/heads/main\n", "text/plain");
    if (path === "/.env") return send(200, "APP_ENV=production\nAPP_KEY=zq7-demo-canary-not-a-real-key\nDB_PASSWORD=demo-canary-not-real\n", "text/plain");
    if (path === "/uploads/") return send(200, `<html><head><title>Index of /uploads</title></head><body><h1>Index of /uploads</h1><pre><a href="../">Parent Directory</a>\n<a href="invoice-1001.pdf">invoice-1001.pdf</a>\n<a href="backup.zip">backup.zip</a></pre></body></html>`);
  }
  // Fixed mode: plain HTTP only redirects to HTTPS.
  if (fixed && !req.socket.encrypted) { res.writeHead(301, { location: `https://${HOST}${req.url ?? "/"}` }); return res.end(); }
  if (path === "/") return send(200, `<!doctype html><html><head><title>Demo Shop</title></head><body><h1>Demo Shop</h1><p>Local demo target for RuyaShield.</p></body></html>`);
  return send(404, "<h1>Not found</h1>");
}

const tlsOpts: https.ServerOptions = fixed
  ? { key: readFileSync(key), cert: readFileSync(cert), minVersion: "TLSv1.2", maxVersion: "TLSv1.3" }
  : { key: readFileSync(key), cert: readFileSync(cert), minVersion: "TLSv1", maxVersion: "TLSv1.2", ciphers: "ALL:@SECLEVEL=0" };

for (const addr of ["127.0.0.1", "::1"]) {
  const s = https.createServer(tlsOpts, handler);
  s.on("tlsClientError", () => {});
  s.listen(8443, addr);
  http.createServer(handler).listen(8080, addr);
}
console.log(`demo target (${fixed ? "FIXED" : "misconfigured"}) for ${HOST}: https :8443, http :8080 on loopback`);
