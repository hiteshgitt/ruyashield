import type { VerificationMethod } from "../db/schema";
import { EgressError, guardedGet, lookupTxtEverywhere, type EgressDeps, type TxtDeps } from "../net/egress";

export const TOKEN_PREFIX = "ruyashield-verify=";
export const DNS_LABEL = "_ruyashield";
export const FILE_PATH = "/.well-known/ruyashield-verification.txt";
export const META_NAME = "ruyashield-verification";

export type CheckOutcome = { status: "passed" | "failed" | "error"; reason: string; evidence: Record<string, unknown> };
export interface CheckDeps { egress?: EgressDeps; txt?: TxtDeps }

export function instructions(method: VerificationMethod, host: string, token: string) {
  switch (method) {
    case "dns_txt": return { where: `${DNS_LABEL}.${host}`, what: token, how: `Add a TXT record named ${DNS_LABEL}.${host} with the value below.` };
    case "http_file": return { where: `https://${host}${FILE_PATH}`, what: token, how: "Serve a plain-text file at this URL containing the value below." };
    case "meta_tag": return { where: `https://${host}/`, what: `<meta name="${META_NAME}" content="${token}">`, how: "Add this tag inside <head> of your home page." };
  }
}

/**
 * Performs one ownership check. Never reports "passed" unless the token was actually observed:
 * DNS needs every independent resolver to answer and agree; HTTP checks are https only.
 * Fetched content is treated purely as data to compare, never as instructions.
 */
export async function runCheck(method: VerificationMethod, host: string, token: string, deps: CheckDeps = {}): Promise<CheckOutcome> {
  if (method === "dns_txt") return checkDns(host, token, deps.txt);
  const url = method === "http_file" ? `https://${host}${FILE_PATH}` : `https://${host}/`;
  let res;
  try {
    res = await guardedGet(url, deps.egress);
  } catch (e) {
    if (e instanceof EgressError) {
      const inconclusive = e.code === "timeout" || e.code === "network" || e.code === "dns_failed";
      return { status: inconclusive ? "error" : "failed", reason: e.code, evidence: { url, error: e.message } };
    }
    return { status: "error", reason: "internal_error", evidence: { url } };
  }
  const evidence = { url, finalUrl: res.finalUrl, httpStatus: res.status, redirects: res.redirects, address: res.pinnedAddress };
  if (res.status >= 500) return { status: "error", reason: `http_${res.status}`, evidence };
  if (res.status !== 200) return { status: "failed", reason: `http_${res.status}`, evidence };
  const found = method === "http_file"
    ? res.body.split(/\r?\n/).some((l) => l.trim() === token)
    : metaContents(res.body, META_NAME).includes(token);
  return found ? { status: "passed", reason: "token_found", evidence } : { status: "failed", reason: "token_not_found", evidence };
}

async function checkDns(host: string, token: string, deps?: TxtDeps): Promise<CheckOutcome> {
  const name = `${DNS_LABEL}.${host}`;
  const answers = await lookupTxtEverywhere(name, deps);
  const evidence = { name, resolvers: answers.map((a) => ({ resolver: a.resolver, found: a.records?.includes(token) ?? null, error: a.error })) };
  if (!answers.length) return { status: "error", reason: "no_resolvers", evidence };
  if (answers.some((a) => a.records === null)) return { status: "error", reason: "resolver_error", evidence };
  const hits = answers.filter((a) => a.records!.includes(token)).length;
  if (hits === answers.length) return { status: "passed", reason: "token_found", evidence };
  if (hits === 0) return { status: "failed", reason: "token_not_found", evidence };
  return { status: "failed", reason: "resolver_disagreement", evidence };
}

/** Extracts content="" of <meta name="…"> tags. A tolerant scan, not an HTML engine; scripts are never run. */
export function metaContents(html: string, name: string): string[] {
  const out: string[] = [];
  for (const m of html.matchAll(/<meta\b([^>]*)>/gi)) {
    const attrs: Record<string, string> = {};
    for (const a of m[1].matchAll(/([a-zA-Z-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))/g)) {
      attrs[a[1].toLowerCase()] = a[2] ?? a[3] ?? a[4] ?? "";
    }
    if (attrs.name?.toLowerCase() === name && attrs.content !== undefined) out.push(attrs.content.trim());
  }
  return out;
}
