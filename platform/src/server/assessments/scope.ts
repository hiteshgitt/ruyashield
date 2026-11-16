import { createHash } from "node:crypto";
import { z } from "zod";
import { AppError } from "../errors";
import type { CheckClass } from "../db/schema";

export const DEFAULT_WINDOW_MS = 24 * 60 * 60 * 1000;
export const MAX_WINDOW_MS = 30 * 24 * 60 * 60 * 1000;
export const DEFAULT_MAX_DURATION_S = 900;

export interface CatalogueEntry { id: string; class: CheckClass; enabled: boolean; requestBudget: number }

/** A validated, immutable assessment scope (RS-SCAN-001). Only these hosts/paths may receive traffic. */
export interface Scope {
  hosts: string[];
  basePaths: string[];
  excludedPaths: string[];
  checkIds: string[];
  classes: CheckClass[];
  windowStart: Date;
  windowEnd: Date;
  maxRequests: number;
  maxDurationS: number;
}

const path = z.string().trim().max(200)
  .refine((p) => p.startsWith("/"), "Paths must start with /")
  .refine((p) => !p.split("/").includes("..") && !/[?#\\\s]/.test(p) && !/%2e%2e/i.test(p), "Paths may not contain .., ?, # or spaces");

const input = z.object({
  checkIds: z.array(z.string().max(100)).min(1, "Choose at least one check").max(20),
  basePaths: z.array(path).max(10).optional(),
  excludedPaths: z.array(path).max(20).optional(),
  windowStart: z.coerce.date().optional(),
  windowEnd: z.coerce.date().optional(),
  maxRequests: z.coerce.number().int().optional(),
  maxDurationS: z.coerce.number().int().optional(),
});

export interface ScopeContext {
  assetHost: string;
  /** Classes the asset's ownership verification or attestation permits right now. */
  allowedClasses: readonly string[];
  catalogue: readonly CatalogueEntry[];
  planMaxRequests: number;
  now?: Date;
}

const bad = (message: string) => new AppError(422, "invalid_scope", message);

/**
 * Validates a launch request into a Scope. Fails closed: anything not explicitly permitted is rejected.
 * The only host in scope is the asset's own host; subdomains are separate assets with their own authorization.
 */
export function validateScope(raw: unknown, c: ScopeContext): Scope {
  const parsed = input.safeParse(raw);
  if (!parsed.success) throw bad(parsed.error.issues[0].message);
  const d = parsed.data;
  const now = c.now ?? new Date();

  const ids = [...new Set(d.checkIds)].sort();
  const defs = ids.map((id) => {
    const def = c.catalogue.find((x) => x.id === id);
    if (!def) throw bad(`Unknown check ${id}.`);
    return def;
  });
  for (const def of defs) {
    if (def.class === "X") throw new AppError(422, "check_prohibited", `${def.id} is a prohibited check and can never run.`);
    if (def.class === "A2" && !(c.allowedClasses as string[]).includes("A2")) {
      throw new AppError(403, "approval_required", `${def.id} is intrusive. Intrusive network checks are off for this organization: two admins must turn them on in Settings → Safety.`);
    }
    if (!def.enabled) throw bad(`${def.id} is disabled.`);
    if (!c.allowedClasses.includes(def.class)) throw new AppError(403, "authorization_required", `This asset's authorization does not cover class ${def.class} checks.`);
  }

  const windowStart = d.windowStart ?? now;
  const windowEnd = d.windowEnd ?? new Date(windowStart.getTime() + DEFAULT_WINDOW_MS);
  if (Number.isNaN(windowStart.getTime()) || Number.isNaN(windowEnd.getTime())) throw bad("Invalid window.");
  if (windowEnd <= windowStart) throw bad("The window must end after it starts.");
  if (windowEnd <= now) throw bad("The window has already ended.");
  if (windowEnd.getTime() - windowStart.getTime() > MAX_WINDOW_MS) throw bad("A window can be at most 30 days.");
  if (windowStart.getTime() - now.getTime() > MAX_WINDOW_MS) throw bad("A window must start within 30 days.");

  const hosts = [c.assetHost];
  const maxRequests = d.maxRequests ?? c.planMaxRequests;
  if (maxRequests < 1 || maxRequests > c.planMaxRequests) throw bad(`Request limit must be between 1 and ${c.planMaxRequests}.`);
  const needed = defs.reduce((n, def) => n + def.requestBudget * hosts.length, 0);
  if (maxRequests < needed) throw bad(`The selected checks need up to ${needed} requests; raise the request limit.`);
  const maxDurationS = d.maxDurationS ?? DEFAULT_MAX_DURATION_S;
  if (maxDurationS < 60 || maxDurationS > 3600) throw bad("Maximum duration must be between 60 and 3600 seconds.");

  return {
    hosts,
    basePaths: [...new Set(d.basePaths?.length ? d.basePaths : ["/"])].sort(),
    excludedPaths: [...new Set(d.excludedPaths ?? [])].sort(),
    checkIds: ids,
    classes: [...new Set(defs.map((x) => x.class))].sort(),
    windowStart, windowEnd, maxRequests, maxDurationS,
  };
}

/** Stable hash of a scope; the job token binds the worker to exactly this scope. */
export function scopeSha(s: Scope): string {
  const canonical = JSON.stringify([s.hosts, s.basePaths, s.excludedPaths, s.checkIds, s.classes,
    s.windowStart.toISOString(), s.windowEnd.toISOString(), s.maxRequests, s.maxDurationS]);
  return createHash("sha256").update(canonical).digest("hex");
}

const under = (p: string, base: string) => p === base || p.startsWith(base.endsWith("/") ? base : base + "/");

/** Is this URL inside the scope? Paths are compared decoded; exclusions case-insensitively (conservative). */
export function inScope(s: Pick<Scope, "hosts" | "basePaths" | "excludedPaths">, url: URL, opts: { hostOnly?: boolean } = {}): boolean {
  if (url.protocol !== "https:" && url.protocol !== "http:") return false;
  if (!s.hosts.includes(url.hostname.toLowerCase().replace(/\.$/, ""))) return false;
  if (opts.hostOnly) return true;
  let p: string;
  try { p = decodeURIComponent(url.pathname); } catch { return false; }
  if (p.split("/").includes("..")) return false;
  if (!s.basePaths.some((b) => under(p, b))) return false;
  const lower = p.toLowerCase();
  return !s.excludedPaths.some((x) => under(lower, x.toLowerCase()));
}
