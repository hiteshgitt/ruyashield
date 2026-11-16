import { z } from "zod";
import type { AiClaimType, AiConfidence } from "../db/schema";

// Output validation (blueprint §7). The model's reply is untrusted: it is parsed against the schema, then every
// claim is checked against what the model was actually given. Anything unsupported is dropped and counted;
// nothing the model says can change a finding.

const claim = z.object({
  type: z.enum(["observation", "inference", "recommendation"]),
  text: z.string().trim().min(1).max(2000),
  evidence_refs: z.array(z.string().max(20)).max(20).default([]),
  confidence: z.enum(["confirmed", "likely", "possible"]),
  verification_check_ids: z.array(z.string().max(100)).max(10).default([]),
  steps: z.array(z.string().trim().min(1).max(1000)).max(15).default([]),
  approval_required: z.boolean().default(false),
});
export const outputSchema = z.object({
  status: z.enum(["ok", "inconclusive"]),
  summary: z.string().max(2000).default(""),
  uncertainty: z.string().max(2000).default(""),
  missing_evidence: z.array(z.string().max(500)).max(20).default([]),
  claims: z.array(claim).max(30),
});
export type RawOutput = z.infer<typeof outputSchema>;

export interface ValidClaim {
  type: AiClaimType; text: string; evidenceRefs: string[]; evidenceIds: string[]; confidence: AiConfidence;
  verificationCheckIds: string[]; steps: string[]; approvalRequired: boolean;
}
export interface Validated {
  status: "completed" | "inconclusive";
  summary: string | null; uncertainty: string | null; missingEvidence: string[];
  claims: ValidClaim[]; dropped: number; flags: string[];
}
export interface ValidationContext { refs: ReadonlyMap<string, string>; checkIds: ReadonlySet<string>; corpus: string }

// Language the product never lets the AI assert (prohibited uses: claiming compromise, deciding resolution).
export const COMPROMISE = /\b(compromised|breach(?:ed|es)?|exploited|exfiltrat\w*|backdoor(?:ed)?|hacked|attacker (?:has|had|gained|obtained)|data (?:was |were |has been )?(?:stolen|leaked))\b/i;
export const RESOLUTION = /\b(is|has been|was|now) (?:fixed|resolved|remediated|mitigated|safe)\b|\b(?:mark|close|set) (?:it |this |the finding )?(?:as )?(?:resolved|closed|fixed)\b/i;
const URL = /\bhttps?:\/\/[^\s"'<>)\]]+/gi;

/** Parses provider text as JSON. Tolerates a fenced block; nothing else. */
export function parseJson(text: string): unknown {
  const t = text.trim().replace(/^```(?:json)?\s*([\s\S]*?)\s*```$/i, "$1");
  return JSON.parse(t);
}

/** Schema check only. Returns a short error for the single repair attempt. */
export function checkSchema(text: string): { ok: true; raw: RawOutput } | { ok: false; error: string } {
  let v: unknown;
  try { v = parseJson(text); } catch { return { ok: false, error: "Reply was not valid JSON." }; }
  const r = outputSchema.safeParse(v);
  if (!r.success) return { ok: false, error: r.error.issues.slice(0, 5).map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`).join("; ") };
  return { ok: true, raw: r.data };
}

const urlsNotIn = (s: string, corpus: string) => (s.match(URL) ?? []).filter((u) => !corpus.includes(u.replace(/[.,;:]+$/, "")));

/** Grounds a schema-valid reply against the input. Pure. */
export function ground(raw: RawOutput, ctx: ValidationContext): Validated {
  const flags = new Set<string>();
  const claims: ValidClaim[] = [];
  let dropped = 0;
  const drop = (flag: string) => { dropped++; flags.add(flag); };

  for (const c of raw.claims) {
    const refs = [...new Set(c.evidence_refs.map((r) => r.trim().toUpperCase()))].filter((r) => ctx.refs.has(r));
    if (!refs.length) { drop("uncited_claim"); continue; }
    const all = [c.text, ...c.steps].join("\n");
    if (COMPROMISE.test(all)) { drop("unsupported_compromise_claim"); continue; }
    if (RESOLUTION.test(all)) { drop("resolution_claim"); continue; }
    if (urlsNotIn(all, ctx.corpus).length) { drop("url_not_in_evidence"); continue; }
    let confidence = c.confidence;
    if (c.type === "inference" && confidence === "confirmed") { confidence = "likely"; flags.add("inference_confidence_capped"); }
    let checks: string[] = [];
    if (c.type === "recommendation") {
      checks = [...new Set(c.verification_check_ids)].filter((id) => ctx.checkIds.has(id));
      if (checks.length < c.verification_check_ids.length) flags.add("unknown_check_id");
      if (!checks.length) { drop("recommendation_without_check"); continue; }
    }
    claims.push({
      type: c.type, text: c.text, evidenceRefs: refs, evidenceIds: refs.map((r) => ctx.refs.get(r)!), confidence,
      verificationCheckIds: checks, steps: c.type === "recommendation" ? c.steps : [],
      // A fix to a running system always needs a human; the model can only make this stricter.
      approvalRequired: c.type === "recommendation" ? true : false,
    });
  }

  const clean = (s: string) => {
    if (!s.trim()) return null;
    if (COMPROMISE.test(s)) { flags.add("unsupported_compromise_claim"); return null; }
    if (RESOLUTION.test(s)) { flags.add("resolution_claim"); return null; }
    if (urlsNotIn(s, ctx.corpus).length) { flags.add("url_not_in_evidence"); return null; }
    return s.trim();
  };
  const summary = clean(raw.summary);
  const uncertainty = clean(raw.uncertainty);
  return {
    status: raw.status === "inconclusive" || !claims.length ? "inconclusive" : "completed",
    summary, uncertainty, missingEvidence: raw.missing_evidence.map((s) => s.trim()).filter(Boolean),
    claims, dropped, flags: [...flags].sort(),
  };
}
