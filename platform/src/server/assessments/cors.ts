import { randomBytes } from "node:crypto";
import type { IncomingHttpHeaders } from "node:http";
import { EgressError, guardedGet, type FetchResult } from "../net/egress";
import type { CheckAdapter, CheckContext, CheckResult, FindingCandidate } from "./checks";

/**
 * http.cors (class A1): two ordinary GETs of https://host/ carrying an Origin header, read for the CORS answer.
 *  - Origin 1 is a random, unregistrable https://ruya-<hex>.invalid; Origin 2 is "null" (sandboxed iframes, file://).
 *  - Reflecting an arbitrary Origin, or allowing "null", together with Access-Control-Allow-Credentials: true lets
 *    any website read signed-in users' responses: high. Without credentials it is low (only public data is exposed).
 *  - Only the home page is tested; APIs on other paths may differ, which evidence says.
 *  - At most 512 bytes of body are read. Fails closed on 429, 5xx or a network error.
 */

export type Fetch = (url: string, ctx: CheckContext, origin: string) => Promise<FetchResult>;
const defaultFetch: Fetch = (url, ctx, origin) => guardedGet(url, {
  ...ctx.egress, onHop: ctx.onHop, timeoutMs: Math.min(ctx.timeoutMs, 8000), truncateAt: 512, accept: "*/*", tlsLenient: true, origin,
});

const one = (h: IncomingHttpHeaders, k: string) => { const v = h[k]; return Array.isArray(v) ? v.join(", ") : v; };

const FIX = "Allow only an explicit list of trusted origins (compare the Origin header against it exactly; never echo it back unchecked), never allow the \"null\" origin, and send Access-Control-Allow-Credentials: true only for origins on that list.";

export function corsFindings(host: string, probe: string, a: { acao?: string; acac?: string }, n: { acao?: string; acac?: string }): FindingCandidate[] {
  const loc = `https://${host}/`;
  const out: FindingCandidate[] = [];
  const cred = (x: { acac?: string }) => (x.acac ?? "").trim().toLowerCase() === "true";
  const ev = (x: { acao?: string; acac?: string }, origin: string) => ({ originSent: origin, allowOrigin: x.acao ?? null, allowCredentials: x.acac ?? null });
  if (a.acao === probe) {
    out.push(cred(a)
      ? { issueKey: "cors_reflects_origin_credentials", title: "CORS trusts any website, with credentials", severity: "high", confidence: "confirmed", location: loc, evidence: ev(a, probe), remediation: `Any website a signed-in user visits can read responses from this site as that user. ${FIX}` }
      : { issueKey: "cors_reflects_origin", title: "CORS reflects any Origin", severity: "low", confidence: "confirmed", location: loc, evidence: ev(a, probe), remediation: `Without credentials only public data is readable, but this becomes serious if credentials are ever enabled. ${FIX}` });
  } else if ((a.acao ?? "").trim() === "*" && cred(a)) {
    out.push({ issueKey: "cors_wildcard_credentials", title: "CORS allows * together with credentials", severity: "low", confidence: "confirmed", location: loc, evidence: ev(a, probe), remediation: `Browsers refuse this combination, so it does not work as intended and signals a misconfiguration. ${FIX}` });
  }
  if ((n.acao ?? "").trim() === "null") {
    out.push(cred(n)
      ? { issueKey: "cors_null_origin_credentials", title: "CORS trusts the \"null\" origin, with credentials", severity: "high", confidence: "confirmed", location: loc, evidence: ev(n, "null"), remediation: `Any sandboxed iframe on any website sends Origin: null, so it can read responses as a signed-in user. ${FIX}` }
      : { issueKey: "cors_null_origin", title: "CORS trusts the \"null\" origin", severity: "low", confidence: "confirmed", location: loc, evidence: ev(n, "null"), remediation: FIX });
  }
  return out;
}

export function createCorsAdapter(fetch: Fetch = defaultFetch, probeOrigin: () => string = () => `https://ruya-${randomBytes(6).toString("hex")}.invalid`): CheckAdapter {
  return {
    id: "http.cors@1", checkKey: "http.cors", target: "host",
    async run(ctx): Promise<CheckResult> {
      const url = `https://${ctx.host}/`;
      const probe = probeOrigin();
      const probes: Record<string, unknown>[] = [];
      try {
        const seen: { acao?: string; acac?: string }[] = [];
        for (const origin of [probe, "null"]) {
          const r = await fetch(url, ctx, origin);
          const x = { acao: one(r.headers, "access-control-allow-origin"), acac: one(r.headers, "access-control-allow-credentials") };
          probes.push({ origin, status: r.status, allowOrigin: x.acao ?? null, allowCredentials: x.acac ?? null, redirects: r.redirects });
          if (r.status === 429 || r.status >= 500) return { status: "error", reason: `http_${r.status}`, evidence: { probes } };
          seen.push(x);
        }
        return { status: "ok", findings: corsFindings(ctx.host, probe, seen[0], seen[1]), evidence: { probes, scope: "Home page only; API paths may have their own CORS policy." } };
      } catch (e) {
        if (e instanceof EgressError) return { status: "error", reason: `egress:${e.code}`, evidence: { probes } };
        throw e;
      }
    },
  };
}
