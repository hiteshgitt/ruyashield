import type { Severity } from "../db/schema";
import { EgressError, tcpProbe, type TcpProbeResult } from "../net/egress";
import type { CheckAdapter, CheckContext, CheckResult, FindingCandidate } from "./checks";

/**
 * net.exposed_services (scanner M3, class A2: off unless two admins opt the organization in).
 *  - TCP connect to a fixed list of 26 well-known service ports on the asset's own host. Nothing is sent: no login
 *    attempts, no protocol probes, no version exploits. A server-first banner is read if offered, then the socket closes.
 *  - Only "open" produces a finding. Filtered and closed ports are recorded in the run evidence.
 *  - Fails closed: an unreachable host or a DNS/egress refusal is an error, never "nothing exposed".
 *  - Fingerprint = host:port + port-<n>, so closing the port and re-testing resolves exactly that finding.
 */

type Group = "database" | "container" | "remote" | "mail" | "file" | "web" | "ssh";
export interface ServiceDef { port: number; service: string; severity: Severity; group: Group }

export const PORTS: readonly ServiceDef[] = [
  // Databases and caches: should never face the internet.
  { port: 1433, service: "Microsoft SQL Server", severity: "critical", group: "database" },
  { port: 1521, service: "Oracle Database", severity: "critical", group: "database" },
  { port: 3306, service: "MySQL / MariaDB", severity: "critical", group: "database" },
  { port: 5432, service: "PostgreSQL", severity: "critical", group: "database" },
  { port: 6379, service: "Redis", severity: "critical", group: "database" },
  { port: 9200, service: "Elasticsearch", severity: "critical", group: "database" },
  { port: 11211, service: "Memcached", severity: "critical", group: "database" },
  { port: 27017, service: "MongoDB", severity: "critical", group: "database" },
  // Container and orchestration control planes: open = remote code execution for whoever finds it.
  { port: 2375, service: "Docker API (unencrypted)", severity: "critical", group: "container" },
  { port: 2376, service: "Docker API (TLS)", severity: "critical", group: "container" },
  { port: 10250, service: "Kubernetes kubelet", severity: "critical", group: "container" },
  // Remote desktop and legacy remote shells.
  { port: 23, service: "Telnet", severity: "high", group: "remote" },
  { port: 3389, service: "Remote Desktop (RDP)", severity: "high", group: "remote" },
  { port: 5900, service: "VNC", severity: "high", group: "remote" },
  { port: 445, service: "SMB / Windows file sharing", severity: "high", group: "file" },
  // Plain-text file transfer and mail access.
  { port: 21, service: "FTP", severity: "medium", group: "file" },
  { port: 110, service: "POP3 (plain text)", severity: "medium", group: "mail" },
  { port: 143, service: "IMAP (plain text)", severity: "medium", group: "mail" },
  { port: 25, service: "SMTP", severity: "low", group: "mail" },
  // Admin consoles and dev servers that usually belong behind a VPN.
  { port: 5000, service: "Development web server", severity: "medium", group: "web" },
  { port: 8080, service: "Alternate HTTP / admin console", severity: "medium", group: "web" },
  { port: 8443, service: "Alternate HTTPS / admin console", severity: "low", group: "web" },
  { port: 9090, service: "Admin console (Prometheus, Cockpit…)", severity: "medium", group: "web" },
  { port: 8888, service: "Notebook / dev server", severity: "medium", group: "web" },
  { port: 15672, service: "RabbitMQ management", severity: "medium", group: "web" },
  // SSH is normal for servers; reported for inventory, not as a problem.
  { port: 22, service: "SSH", severity: "info", group: "ssh" },
];

/** Per-port connect timeout. 26 ports × (timeout + spacing) stays well inside the 60 s check timeout. */
const PORT_TIMEOUT_MS = 1200;
const BANNER_WAIT_MS = 1000;

const REMEDIATION: Record<Group, string> = {
  database: "Do not expose databases or caches to the internet. Bind the service to a private interface or localhost, block the port in your firewall / cloud security group, and reach it through a VPN, bastion or private network. Require authentication and TLS even internally.",
  container: "Close this port to the internet immediately: anyone who can reach this control API can run code on the host. Block it in the firewall / security group, bind it to localhost or a private network, and require mutual TLS client certificates if remote access is needed.",
  remote: "Do not expose remote desktop or remote shell services directly. Put them behind a VPN or zero-trust access gateway, block the port in the firewall, require MFA, and disable Telnet in favour of SSH.",
  file: "Do not expose file-sharing or plain-text file-transfer services to the internet. Block the port, use SFTP or HTTPS-based transfer, and keep SMB on private networks only.",
  mail: "If this host is not a mail server, close the port. If it is, disable plain-text protocols in favour of their TLS versions (IMAPS 993, POP3S 995, submission 587 with STARTTLS) and keep the server patched.",
  web: "Check whether this service is meant to be public. Admin consoles, dev servers and management UIs belong behind a VPN or an authenticated reverse proxy; block the port in the firewall if it is not needed.",
  ssh: "SSH is commonly exposed on purpose. Make sure password login is disabled (keys only), root login is off, and consider restricting the source IPs or putting it behind a VPN.",
};

export type Probe = (host: string, ports: readonly number[], ctx: CheckContext) => Promise<TcpProbeResult>;

const defaultProbe: Probe = (host, ports, ctx) =>
  tcpProbe(host, ports, { ...ctx.egress, onHop: ctx.onHop, timeoutMs: PORT_TIMEOUT_MS, bannerWaitMs: BANNER_WAIT_MS, sleep: ctx.sleep });

export function createExposedServicesAdapter(probe: Probe = defaultProbe): CheckAdapter {
  return {
    id: "net.exposed_services@1", checkKey: "net.exposed_services", target: "host",
    async run(ctx): Promise<CheckResult> {
      let r: TcpProbeResult;
      try {
        r = await probe(ctx.host, PORTS.map((p) => p.port), ctx);
      } catch (e) {
        if (e instanceof EgressError) return { status: "error", reason: e.code === "network" ? "host_unreachable" : e.code, evidence: { error: e.message.slice(0, 200) } };
        throw e;
      }
      const byPort = new Map(PORTS.map((p) => [p.port, p]));
      const findings: FindingCandidate[] = [];
      for (const res of r.results) {
        if (res.state !== "open") continue;
        const def = byPort.get(res.port);
        if (!def) continue;
        findings.push({
          issueKey: `port-${def.port}`,
          title: `${def.service} is reachable from the internet (port ${def.port})`,
          severity: def.severity,
          confidence: "confirmed",
          location: `${ctx.host}:${def.port}`,
          evidence: { port: def.port, service: def.service, pinnedAddress: r.pinnedAddress, ...(res.banner ? { banner: res.banner } : {}) },
          remediation: REMEDIATION[def.group],
        });
      }
      const count = (s: string) => r.results.filter((x) => x.state === s).length;
      return {
        status: "ok", findings,
        evidence: { pinnedAddress: r.pinnedAddress, portsChecked: r.results.length, open: count("open"), closed: count("closed"), filtered: count("filtered"), openPorts: r.results.filter((x) => x.state === "open").map((x) => x.port) },
      };
    },
  };
}
