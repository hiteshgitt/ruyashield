import { EgressError, guardedGet, lookupRecords, type DnsAnswer, type DnsDeps, type DnsRecordType, type FetchResult } from "../net/egress";
import type { CheckAdapter, CheckContext, CheckResult, FindingCandidate } from "./checks";

/**
 * dns.takeover (class P + one A1 GET): can someone else claim this host name?
 *  - Reads the verified host's own CNAME chain (at most 5 links). No other names are queried or guessed.
 *  - Dangling: the chain ends in a name that does not exist (NXDOMAIN). Whoever registers that name, or claims it on
 *    the hosting service, serves content on this host: high, likely.
 *  - Unclaimed service: the chain points at a hosting service where unclaimed names can be taken (GitHub Pages,
 *    Heroku, S3, …) and the host answers with that service's "nothing here" page. One GET, 512 bytes: high, likely.
 *  - No CNAME: nothing to take over through DNS; ok with no findings.
 *  - Fails closed: a DNS error (other than "no such name"/"no record"), or a failed GET on a takeover-prone service
 *    with no fingerprint match, is an error.
 */

export const MAX_CHAIN = 5;

/** Services where an unclaimed name can be claimed by anyone, with the body text they serve for an unclaimed name. */
export const PRONE: ReadonlyArray<{ service: string; suffix: RegExp; fingerprint: RegExp }> = [
  { service: "GitHub Pages", suffix: /\.github\.io$/, fingerprint: /There isn't a GitHub Pages site here/i },
  { service: "Heroku", suffix: /\.(herokuapp\.com|herokudns\.com)$/, fingerprint: /no-such-app|No such app|herokucdn\.com\/error-pages\/no-such-app/i },
  { service: "Amazon S3", suffix: /\.s3[.-]([a-z0-9-]+\.)?amazonaws\.com$|^s3[.-]/, fingerprint: /NoSuchBucket|The specified bucket does not exist/i },
  { service: "Azure", suffix: /\.(azurewebsites\.net|cloudapp\.net|cloudapp\.azure\.com|trafficmanager\.net|blob\.core\.windows\.net|azureedge\.net)$/, fingerprint: /404 Web Site not found|The resource you are looking for has been removed/i },
  { service: "Surge", suffix: /\.surge\.sh$/, fingerprint: /project not found/i },
  { service: "Shopify", suffix: /\.myshopify\.com$/, fingerprint: /Sorry, this shop is currently unavailable|Only one step left/i },
  { service: "Pantheon", suffix: /\.pantheonsite\.io$/, fingerprint: /The gods are wise, but do not know of the site which you seek/i },
  { service: "Fastly", suffix: /\.fastly\.net$/, fingerprint: /Fastly error: unknown domain/i },
  { service: "Bitbucket", suffix: /\.bitbucket\.io$/, fingerprint: /Repository not found/i },
  { service: "Read the Docs", suffix: /\.readthedocs\.io$/, fingerprint: /unknown to Read the Docs/i },
  { service: "Zendesk", suffix: /\.zendesk\.com$/, fingerprint: /Help Center Closed/i },
  { service: "Ghost", suffix: /\.ghost\.io$/, fingerprint: /Domain error|Failed to resolve DNS path for this host/i },
];

export type Lookup = (name: string, type: DnsRecordType, deps: DnsDeps) => Promise<DnsAnswer>;
export type Fetch = (url: string, ctx: CheckContext) => Promise<FetchResult>;
const defaultFetch: Fetch = (url, ctx) => guardedGet(url, {
  ...ctx.egress, onHop: ctx.onHop, timeoutMs: Math.min(ctx.timeoutMs, 8000), truncateAt: 512, accept: "text/html, */*;q=0.5", tlsLenient: true, followRedirects: false,
});

export function createTakeoverAdapter(lookup: Lookup = lookupRecords, fetch: Fetch = defaultFetch): CheckAdapter {
  return {
    id: "dns.takeover@1", checkKey: "dns.takeover", target: "host",
    async run(ctx): Promise<CheckResult> {
      const host = ctx.host.toLowerCase();
      const chain: string[] = [];
      let name = host;
      for (let i = 0; i < MAX_CHAIN; i++) {
        const r = await lookup(name, "CNAME", ctx.dns);
        if ("error" in r) return { status: "error", reason: `dns_${r.error}`, evidence: { chain, name } };
        if (r.nxdomain && name !== host) {
          return dangling(host, chain, name);
        }
        if (!r.records.length) break;
        name = r.records[0];
        if (chain.includes(name)) return { status: "error", reason: "dns_cname_loop", evidence: { chain } };
        chain.push(name);
      }
      if (!chain.length) return { status: "ok", findings: [], evidence: { cname: null, note: "No CNAME on this host, so it cannot be taken over through a dangling DNS alias." } };

      const target = chain[chain.length - 1];
      // The end of the chain must resolve to an address; NXDOMAIN there is dangling.
      const a = await lookup(target, "A", ctx.dns);
      if ("error" in a) return { status: "error", reason: `dns_${a.error}`, evidence: { chain } };
      if (a.nxdomain) return dangling(host, chain, target);
      if (!a.records.length) {
        const aaaa = await lookup(target, "AAAA", ctx.dns);
        if ("error" in aaaa) return { status: "error", reason: `dns_${aaaa.error}`, evidence: { chain } };
        if (aaaa.nxdomain) return dangling(host, chain, target);
      }

      const prone = PRONE.find((p) => chain.some((c) => p.suffix.test(c)));
      if (!prone) return { status: "ok", findings: [], evidence: { chain, note: "The alias resolves and does not point at a service known to allow takeover." } };

      let r: FetchResult;
      try { r = await fetch(`https://${host}/`, ctx); } catch (e) {
        if (e instanceof EgressError) return { status: "error", reason: `egress:${e.code}`, evidence: { chain, service: prone.service } };
        throw e;
      }
      const probe = { status: r.status, bytes: Buffer.byteLength(r.body, "utf8"), truncated: r.truncated };
      if (prone.fingerprint.test(r.body)) {
        return { status: "ok", evidence: { chain, service: prone.service, probe }, findings: [{
          issueKey: "unclaimed_service", title: `Host points at an unclaimed ${prone.service} site that anyone could claim`.slice(0, 200),
          severity: "high", confidence: "likely", location: host, evidence: { chain, service: prone.service, fingerprint: prone.fingerprint.source.slice(0, 120), status: r.status },
          remediation: `Either claim the name on ${prone.service} again (recreate the site/app/bucket under your account) or delete the CNAME record for ${host}. Until then an attacker can create it and serve content, steal cookies scoped to your domain, or phish under your name.`,
        }] };
      }
      if (r.status === 429 || r.status >= 500) return { status: "error", reason: `http_${r.status}`, evidence: { chain, service: prone.service, probe } };
      return { status: "ok", findings: [], evidence: { chain, service: prone.service, probe, note: `Points at ${prone.service}, and the site there is claimed.` } };
    },
  };
}

function dangling(host: string, chain: string[], missing: string): CheckResult {
  const f: FindingCandidate = {
    issueKey: "dangling_cname", title: "Host is an alias (CNAME) for a name that does not exist", severity: "high", confidence: "likely", location: host,
    evidence: { chain, missing },
    remediation: `Delete the CNAME record for ${host} if the service it pointed to is gone, or recreate ${missing} under your control. Whoever registers or claims that name can serve content on ${host}.`,
  };
  return { status: "ok", findings: [f], evidence: { chain, missing } };
}
