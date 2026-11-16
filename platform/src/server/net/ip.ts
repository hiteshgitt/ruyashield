import { BlockList, isIP } from "node:net";

// Destinations the platform must never reach on behalf of a tenant (SSRF guard, TC-SEC-001).
const v4 = new BlockList();
for (const [net, bits] of [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16],
  ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.88.99.0", 24], ["192.168.0.0", 16],
  ["198.18.0.0", 15], ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
] as const) v4.addSubnet(net, bits, "ipv4");

const v6 = new BlockList();
for (const [net, bits] of [
  ["::", 128], ["::1", 128], ["100::", 64], ["2001::", 32], ["2001:db8::", 32], ["2002::", 16],
  ["fc00::", 7], ["fe80::", 10], ["fec0::", 10], ["ff00::", 8],
] as const) v6.addSubnet(net, bits, "ipv6");

/** Extracts an embedded IPv4 address from IPv4-mapped (::ffff:a.b.c.d / ::ffff:xxxx:xxxx) or NAT64 (64:ff9b::/96) forms. */
function embeddedV4(ip: string): string | null {
  const lower = ip.toLowerCase();
  const m = /^(?:::ffff:|64:ff9b::)(?:(\d+\.\d+\.\d+\.\d+)|([0-9a-f]{1,4}):([0-9a-f]{1,4}))$/.exec(lower);
  if (!m) return null;
  if (m[1]) return m[1];
  const hi = parseInt(m[2], 16), lo = parseInt(m[3], 16);
  return `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
}

/** True for any address that is not publicly routable unicast. Unparseable input is treated as blocked. */
export function isBlockedIp(ip: string): boolean {
  const fam = isIP(ip);
  if (fam === 4) return v4.check(ip, "ipv4");
  if (fam === 6) {
    const inner = embeddedV4(ip);
    if (inner) return isBlockedIp(inner);
    return v6.check(ip, "ipv6");
  }
  return true;
}

export const isIpLiteral = (host: string) => isIP(host.replace(/^\[|\]$/g, "")) !== 0;
