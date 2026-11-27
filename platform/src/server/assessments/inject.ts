import { createHash } from "node:crypto";
import { EgressError, guardedGet, type FetchResult } from "../net/egress";
import type { CheckAdapter, CheckContext, CheckResult, FindingCandidate } from "./checks";
import { crawlSite, PAGE_BYTES, type Candidate } from "./reflect";

/**
 * pt.inject (automated penetration test, step 3, class A2: verified owners who turned on intrusive checks only).
 * Detection only, never exploitation:
 *  - SQL injection, error-based: the parameter's value plus a single quote. A finding needs a database error message
 *    that the normal page does not contain.
 *  - SQL injection, boolean-based (numeric parameters only): "N AND 1=1" must match the normal page while
 *    "N AND 1=2" clearly differs, and the normal page must be stable across two loads. No time delays, no UNION, no
 *    data extraction, nothing that writes.
 *  - Path traversal (file-like parameters only): ../ sequences to /etc/passwd. A finding needs the passwd signature;
 *    the file content is never stored, only that the signature matched.
 * GET only, same host only, state-changing paths and parameters skipped by the shared crawler, at most 5 requests a
 * second, at most 4 KB read per test response. Fails closed when the site cannot be read or most requests fail.
 */

export const MAX_PARAMS = 20;
const TEST_BYTES = 4096;
const GAP_MS = 200;

const SQL_ERRORS = /You have an error in your SQL syntax|mysqli?_[a-z_]+\(\)|Warning: mysql|SQLSTATE\[|PDOException|ORA-\d{5}|PostgreSQL.{0,40}ERROR|pg_query\(\)|SQLite3?::|unrecognized token:|Unclosed quotation mark|quoted string not properly terminated|Microsoft OLE DB Provider for SQL Server|ODBC SQL Server Driver/i;
const FILE_PARAM = /^(?:file|filename|path|filepath|page|template|tpl|include|inc|doc|document|download|folder|dir|img|image|view|load|read|show|lang|module)$/i;
const PASSWD = /root:[x*!]?:0:0:/;
const TRAVERSALS = ["../../../../../../../../etc/passwd", "....//....//....//....//....//....//etc/passwd"];

export type Fetch = (url: string, ctx: CheckContext, bytes: number) => Promise<FetchResult>;
const defaultFetch: Fetch = (url, ctx, bytes) =>
  guardedGet(url, { ...ctx.egress, onHop: ctx.onHop, timeoutMs: Math.min(ctx.timeoutMs, 8000), truncateAt: bytes, accept: "text/html, */*;q=0.5", followRedirects: false, tlsLenient: true });

const hash = (s: string) => createHash("sha256").update(s, "utf8").digest("hex");
/** Pages that differ only in dynamic bits (times, nonces, CSRF tokens, numbers) compare as the same. Pure. */
export const normalise = (body: string) => body.replace(/\d+/g, "0").replace(/[a-f0-9]{16,}/gi, "h").replace(/\s+/g, " ");
const same = (a: FetchResult, b: FetchResult) => a.status === b.status && hash(normalise(a.body)) === hash(normalise(b.body));
const clearlyDifferent = (a: FetchResult, b: FetchResult) => a.status !== b.status || Math.abs(a.body.length - b.body.length) > Math.max(32, a.body.length * 0.1);

export function createInjectAdapter(fetch: Fetch = defaultFetch): CheckAdapter {
  return {
    id: "pt.inject@1", checkKey: "pt.inject", target: "host",
    async run(ctx): Promise<CheckResult> {
      const sleep = ctx.sleep ?? ((ms: number) => new Promise((r) => setTimeout(r, ms)));
      let sent = 0; let requests = 0; let failures = 0;
      const get = async (url: string, bytes = TEST_BYTES) => { if (sent++) await sleep(GAP_MS); return fetch(url, ctx, bytes); };
      const test = async (u: URL) => { const r = await get(u.href); requests++; if (r.status === 429 || r.status >= 500) failures++; return r; };
      const home = new URL(`https://${ctx.host}/`);
      const out: FindingCandidate[] = [];
      const loc = (c: Candidate) => `${c.url.origin}${c.url.pathname}?${c.param}=`.slice(0, 300);
      try {
        const crawl = await crawlSite(home, (u) => get(u, PAGE_BYTES));
        if (crawl.homeFailed) return { status: "error", reason: `http_${crawl.homeFailed}`, evidence: { crawled: crawl.crawled } };
        const params = [...crawl.candidates.values()].slice(0, MAX_PARAMS);
        for (const c of params) {
          const value = c.url.searchParams.get(c.param) ?? "";
          const withValue = (v: string) => { const u = new URL(c.url); u.searchParams.set(c.param, v); return u; };
          const base = await test(withValue(value));
          if (base.status === 429 || base.status >= 500) continue;

          // Error-based SQL injection.
          const quoted = await test(withValue(`${value}'`));
          if (SQL_ERRORS.test(quoted.body) && !SQL_ERRORS.test(base.body)) {
            out.push({ issueKey: "sql_injection", title: `SQL injection in parameter "${c.param}" (${c.url.pathname}): database error on a quote`, severity: "critical", confidence: "likely",
              location: loc(c), evidence: { parameter: c.param, path: c.url.pathname, technique: "error-based", status: quoted.status, databaseErrorShown: true },
              remediation: `Use prepared statements / parameterised queries for "${c.param}" ($wpdb->prepare in WordPress, PDO prepare in PHP, the ORM's bindings elsewhere) and hide database errors from visitors. Re-test after the fix.` });
            continue;
          }
          // Boolean-based, numeric parameters only, on a stable page.
          if (/^\d{1,9}$/.test(value)) {
            const again = await test(withValue(value));
            if (same(base, again)) {
              const yes = await test(withValue(`${value} AND 1=1`));
              const no = await test(withValue(`${value} AND 1=2`));
              if (same(base, yes) && clearlyDifferent(base, no)) {
                out.push({ issueKey: "sql_injection", title: `SQL injection in parameter "${c.param}" (${c.url.pathname}): true/false conditions change the page`, severity: "critical", confidence: "likely",
                  location: loc(c), evidence: { parameter: c.param, path: c.url.pathname, technique: "boolean-based", trueMatchesNormal: true, falseDiffers: true },
                  remediation: `Use prepared statements / parameterised queries for "${c.param}" and cast numeric input to an integer before use. Re-test after the fix.` });
                continue;
              }
            }
          }
          // Path traversal, file-like parameters only.
          if (FILE_PARAM.test(c.param)) {
            for (const t of TRAVERSALS) {
              const r = await test(withValue(t));
              if (PASSWD.test(r.body) && !PASSWD.test(base.body)) {
                out.push({ issueKey: "path_traversal", title: `Path traversal in parameter "${c.param}" (${c.url.pathname}): server files can be read`, severity: "high", confidence: "likely",
                  location: loc(c), evidence: { parameter: c.param, path: c.url.pathname, status: r.status, systemFileSignatureMatched: true },
                  remediation: `Never build file paths from "${c.param}". Map allowed values to fixed files (an allow-list), or use basename() and check the resolved path stays inside the intended folder. Re-test after the fix.` });
                break;
              }
            }
          }
        }
        if (requests >= 4 && failures * 2 > requests) return { status: "error", reason: "too_many_failed_requests", evidence: { crawled: crawl.crawled, requests, failures } };
        return { status: "ok", findings: out, evidence: { crawled: crawl.crawled, parametersTested: params.length, requests, failures } };
      } catch (e) {
        if (e instanceof EgressError) return { status: "error", reason: e.code === "network" ? "host_unreachable" : e.code, evidence: { error: e.message.slice(0, 200), requests } };
        throw e;
      }
    },
  };
}
