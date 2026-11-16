import net from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { normalizeResult, type CheckContext } from "@/server/assessments/checks";
import { createExposedServicesAdapter, PORTS, type Probe } from "@/server/assessments/ports";
import { cleanBanner, EgressError, tcpProbe, type TcpProbeResult } from "@/server/net/egress";

const local = { allowPrivate: true, resolve: async () => [{ address: "127.0.0.1", family: 4 as const }], timeoutMs: 1500, spacingMs: 0, bannerWaitMs: 300 };

let banner: net.Server, silent: net.Server, closedPort: number;
const portOf = (s: net.Server) => (s.address() as net.AddressInfo).port;
const listen = (s: net.Server) => new Promise<void>((r) => s.listen(0, "127.0.0.1", () => r()));

beforeAll(async () => {
  banner = net.createServer((sock) => { sock.write("SSH-2.0-OpenSSH_9.6\r\n\u0000\u0007"); });
  silent = net.createServer(() => {});
  await Promise.all([listen(banner), listen(silent)]);
  const tmp = net.createServer();
  await listen(tmp);
  closedPort = portOf(tmp);
  await new Promise<void>((r) => tmp.close(() => r()));
});
afterAll(() => { banner.close(); silent.close(); });

describe("tcpProbe", () => {
  it("reports open (with a cleaned banner), open without banner, and closed", async () => {
    const hops: string[] = [];
    const r = await tcpProbe("svc.example", [portOf(banner), portOf(silent), closedPort], { ...local, onHop: (u) => { hops.push(u.port); } });
    expect(r.pinnedAddress).toBe("127.0.0.1");
    expect(r.results).toEqual([
      { port: portOf(banner), state: "open", banner: "SSH-2.0-OpenSSH_9.6" },
      { port: portOf(silent), state: "open" },
      { port: closedPort, state: "closed" },
    ]);
    // Every connection attempt passes through the guard first.
    expect(hops).toEqual([portOf(banner), portOf(silent), closedPort].map(String));
  });

  it("refuses private addresses and IP literals without allowPrivate", async () => {
    await expect(tcpProbe("svc.example", [22], { resolve: async () => [{ address: "10.0.0.5", family: 4 }] })).rejects.toMatchObject({ code: "egress_blocked" });
    await expect(tcpProbe("127.0.0.1", [22], {})).rejects.toMatchObject({ code: "egress_blocked" });
  });

  it("stops when the guard refuses a hop", async () => {
    let n = 0;
    const onHop = () => { if (++n > 1) throw new Error("budget exhausted"); };
    await expect(tcpProbe("svc.example", [portOf(silent), closedPort], { ...local, onHop })).rejects.toThrow("budget exhausted");
  });

  it("cleans banners to printable text", () => {
    expect(cleanBanner(Buffer.from("220 mail\r\n\u0000ready"))).toBe("220 mail ready");
  });
});

const ctx = { host: "svc.example", onHop: () => {}, egress: {}, timeoutMs: 60000 } as unknown as CheckContext;
const fake = (r: TcpProbeResult | Error): Probe => async () => { if (r instanceof Error) throw r; return r; };

describe("net.exposed_services adapter", () => {
  it("checks exactly 26 distinct ports", () => {
    expect(PORTS).toHaveLength(26);
    expect(new Set(PORTS.map((p) => p.port)).size).toBe(26);
  });

  it("reports open ports only, with stable keys and no request content", async () => {
    const r = normalizeResult(await createExposedServicesAdapter(fake({ pinnedAddress: "203.0.113.7", results: [
      { port: 6379, state: "open" }, { port: 22, state: "open", banner: "SSH-2.0-OpenSSH_9.6" },
      { port: 3389, state: "filtered" }, { port: 5432, state: "closed" },
    ] })).run(ctx));
    expect(r.status).toBe("ok");
    if (r.status !== "ok") return;
    expect(r.findings.map((f) => [f.issueKey, f.severity, f.location])).toEqual([
      ["port-6379", "critical", "svc.example:6379"], ["port-22", "info", "svc.example:22"],
    ]);
    expect(r.findings[1].evidence).toEqual({ port: 22, service: "SSH", pinnedAddress: "203.0.113.7", banner: "SSH-2.0-OpenSSH_9.6" });
    expect(r.findings[0].remediation).toMatch(/Do not expose databases/);
    expect(r.evidence).toMatchObject({ open: 2, closed: 1, filtered: 1, openPorts: [6379, 22] });
  });

  it("returns ok with no findings when everything is closed", async () => {
    const r = await createExposedServicesAdapter(fake({ pinnedAddress: "203.0.113.7", results: PORTS.map((p) => ({ port: p.port, state: "closed" as const })) })).run(ctx);
    expect(r).toMatchObject({ status: "ok", findings: [] });
  });

  it("fails closed when the host cannot be reached or is refused", async () => {
    expect(await createExposedServicesAdapter(fake(new EgressError("network", "EHOSTUNREACH on port 22"))).run(ctx)).toMatchObject({ status: "error", reason: "host_unreachable" });
    expect(await createExposedServicesAdapter(fake(new EgressError("egress_blocked", "private"))).run(ctx)).toMatchObject({ status: "error", reason: "egress_blocked" });
  });
});
