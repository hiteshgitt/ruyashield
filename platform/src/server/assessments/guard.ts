import { inScope, type Scope } from "./scope";

export const MIN_REQUEST_INTERVAL_MS = 500; // at most 2 requests per second per host

export type BlockReason = "out_of_scope" | "budget_exhausted" | "check_budget_exhausted" | "closed";

export class ScopeBlocked extends Error {
  readonly code = "scope_blocked";
  constructor(readonly reason: BlockReason, readonly url: string) {
    super(`Request blocked by scope guard (${reason})`);
  }
}

export interface GuardOptions { sleep?: (ms: number) => Promise<void>; now?: () => number; minIntervalMs?: number }

/**
 * Per-assessment request guard, called before every outbound request (redirect hops included).
 * It is the last line of scope enforcement: host and path must be in scope, the total and per-check
 * budgets must not be exceeded, and requests to one host are spaced out.
 */
export function createGuard(scope: Pick<Scope, "hosts" | "basePaths" | "excludedPaths" | "maxRequests">, o: GuardOptions = {}) {
  const sleep = o.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const now = o.now ?? Date.now;
  const interval = o.minIntervalMs ?? MIN_REQUEST_INTERVAL_MS;
  const used = new Map<string, number>();
  const lastAt = new Map<string, number>();
  const blocked: { checkId: string; url: string; reason: BlockReason }[] = [];
  let total = 0;
  let closed = false;

  return {
    /** Returns the onHop hook for one check. hostOnly is for connection-level probes (TLS) that send no path. */
    forCheck(checkId: string, budget: number, opts: { hostOnly?: boolean } = {}) {
      return async (url: URL) => {
        const block = (reason: BlockReason): never => {
          blocked.push({ checkId, url: url.toString(), reason });
          throw new ScopeBlocked(reason, url.toString());
        };
        if (closed) block("closed");
        if (!inScope(scope, url, opts)) block("out_of_scope");
        if (total >= scope.maxRequests) block("budget_exhausted");
        if ((used.get(checkId) ?? 0) >= budget) block("check_budget_exhausted");
        total++;
        used.set(checkId, (used.get(checkId) ?? 0) + 1);
        const host = url.hostname.toLowerCase();
        const wait = (lastAt.get(host) ?? -Infinity) + interval - now();
        lastAt.set(host, Math.max(now(), (lastAt.get(host) ?? -Infinity) + interval));
        if (wait > 0) await sleep(wait);
        if (closed) block("closed");
      };
    },
    /** Stops all further traffic, e.g. on cancel, kill switch or timeout. */
    close() { closed = true; },
    requestsFor: (checkId: string) => used.get(checkId) ?? 0,
    get total() { return total; },
    get blocked() { return blocked; },
  };
}

export type Guard = ReturnType<typeof createGuard>;
