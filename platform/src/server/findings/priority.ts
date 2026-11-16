import { sql, type SQL } from "drizzle-orm";
import type { AnyPgColumn } from "drizzle-orm/pg-core";
import type { Confidence, Criticality, Severity } from "../db/schema";

// Priority (RS-FIND-003): severity × confidence × asset criticality. The inputs and the version are shown
// with every score so a reader can see why a finding ranks where it does.

export const PRIORITY_VERSION = "prio/1";
export const SEVERITY_WEIGHT: Record<Severity, number> = { critical: 10, high: 7.5, medium: 5, low: 2.5, info: 0.5 };
export const CONFIDENCE_WEIGHT: Record<Confidence, number> = { confirmed: 1, likely: 0.8, suspected: 0.5, unknown: 0.3 };
export const CRITICALITY_WEIGHT: Record<Criticality, number> = { critical: 1.5, high: 1.2, medium: 1, low: 0.7 };

export interface Priority {
  score: number;
  version: string;
  inputs: { severity: Severity; confidence: Confidence; criticality: Criticality };
  /** True when the asset has no criticality set and "medium" was assumed. */
  criticalityDefault: boolean;
}

export function priorityOf(f: { severity: Severity; confidence: Confidence }, criticality: Criticality | null): Priority {
  const crit = criticality ?? "medium";
  const score = Math.round(SEVERITY_WEIGHT[f.severity] * CONFIDENCE_WEIGHT[f.confidence] * CRITICALITY_WEIGHT[crit] * 100) / 100;
  return { score, version: PRIORITY_VERSION, inputs: { severity: f.severity, confidence: f.confidence, criticality: crit }, criticalityDefault: criticality == null };
}

const caseOf = (col: AnyPgColumn, w: Record<string, number>, fallback: number): SQL =>
  sql`(CASE ${col} ${sql.join(Object.entries(w).map(([k, v]) => sql`WHEN ${k} THEN ${sql.raw(String(v))}`), sql` `)} ELSE ${sql.raw(String(fallback))} END)`;

/** The same score as priorityOf, as SQL, for ordering and keyset paging. */
export function prioritySql(severity: AnyPgColumn, confidence: AnyPgColumn, criticality: AnyPgColumn): SQL<number> {
  return sql<number>`round((${caseOf(severity, SEVERITY_WEIGHT, 0)} * ${caseOf(confidence, CONFIDENCE_WEIGHT, 0.3)} * ${caseOf(criticality, CRITICALITY_WEIGHT, 1)})::numeric, 2)`;
}
