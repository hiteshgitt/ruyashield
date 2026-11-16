import { and, asc, desc, eq, inArray, sql } from "drizzle-orm";
import { z } from "zod";
import { withOrg, isUuid, type Tx } from "../db/client";
import {
  aiAnalyses, aiClaims, aiPromptReleases, assets, checkDefinitions, evidenceItems, findingOccurrences, findings, orgs, usageRecords,
  type AiStatus, type AiUseCase,
} from "../db/schema";
import { audit } from "../audit/audit";
import { AppError, isAppError, notFound } from "../errors";
import { authorize, decide, type OrgFlags, type Principal, type Resource } from "../policy/policy";
import { log } from "../log";
import { AI_REDACTION_VERSION, containsSecret } from "./redact";
import { randomUUID } from "node:crypto";
import { buildBundle, buildMessages, MAX_EVIDENCE_ITEMS, MAX_HISTORY_TURNS, MAX_OUTPUT_TOKENS, MAX_QUESTION_CHARS, MAX_THREAD_TURNS, PROMPTS, SCHEMA_VERSION, templateSha256, type BuiltBundle, type ChatInput, type ChatMessage } from "./prompts";
import { callProvider, getProvider, ProviderError, type AiProvider } from "./providers";
import { checkSchema, ground, type Validated } from "./validate";

// AI gateway (RS-AI-001..006, blueprint §7). The only path from RuyaShield data to a model. It never changes a
// finding, never selects targets and never approves anything: it stores an append-only analysis for a person to
// read. Every refusal is audited.

type Ctx = { principal: Principal; org: OrgFlags & { id: string } };
type FindingRow = typeof findings.$inferSelect;
type AssetRow = typeof assets.$inferSelect;
export type AnalysisRow = typeof aiAnalyses.$inferSelect;
export type ClaimRow = typeof aiClaims.$inferSelect;

const userActor = (p: Principal) => ({ type: "user" as const, id: p.userId, ip: p.ip });
const res = (f: FindingRow, a: AssetRow): Resource => ({ type: "finding", id: f.id, clientGroupId: a.clientGroupId, ownerId: f.ownerId });
const period = (d = new Date()) => d.toISOString().slice(0, 7);
export const AI_USAGE_KIND = "ai_tokens";

export interface GatewayDeps { provider?: AiProvider | null }

async function loadFinding(tx: Tx, c: Ctx, id: string) {
  if (!isUuid(id)) throw notFound();
  const f = (await tx.select().from(findings).where(eq(findings.id, id)))[0];
  if (!f) throw notFound();
  const a = (await tx.select().from(assets).where(eq(assets.id, f.assetId)))[0];
  if (!a || !decide(c.principal, "finding.view", res(f, a), c.org).allow) throw notFound();
  return { f, a };
}

async function tokensUsed(tx: Tx) {
  return (await tx.select({ n: sql<number>`coalesce(sum(${usageRecords.quantity}), 0)::int` }).from(usageRecords)
    .where(and(eq(usageRecords.kind, AI_USAGE_KIND), eq(usageRecords.period, period()))))[0].n;
}

async function isReleased(tx: Tx, useCase: AiUseCase, p: AiProvider) {
  const t = PROMPTS[useCase];
  const r = await tx.select({ id: aiPromptReleases.evalRunId }).from(aiPromptReleases).where(and(
    eq(aiPromptReleases.promptId, t.id), eq(aiPromptReleases.promptVersion, t.version), eq(aiPromptReleases.templateSha256, templateSha256(t)),
    eq(aiPromptReleases.provider, p.name), eq(aiPromptReleases.model, p.model)));
  return r[0]?.id ?? null;
}

/** What the model may see for one finding: its record, up to five evidence items and the checks that share its key. */
async function gather(tx: Tx, f: FindingRow, chat?: ChatInput): Promise<BuiltBundle> {
  const occ = await tx.select({ id: findingOccurrences.evidenceId }).from(findingOccurrences)
    .where(eq(findingOccurrences.findingId, f.id)).orderBy(desc(findingOccurrences.seenAt)).limit(20);
  const ids = [...new Set([f.latestEvidenceId, ...occ.map((o) => o.id)].filter((x): x is string => !!x))].slice(0, MAX_EVIDENCE_ITEMS);
  const ev = ids.length ? await tx.select().from(evidenceItems).where(inArray(evidenceItems.id, ids)) : [];
  const ordered = ids.map((id) => ev.find((e) => e.id === id)).filter((e): e is NonNullable<typeof e> => !!e);
  const defs = await tx.select().from(checkDefinitions)
    .where(and(eq(checkDefinitions.checkKey, f.checkKey), eq(checkDefinitions.enabled, true))).orderBy(asc(checkDefinitions.id));
  return buildBundle(
    { id: f.id, title: f.title, severity: f.severity, confidence: f.confidence, status: f.status, checkKey: f.checkKey, location: f.location, evidence: f.evidence, remediation: f.remediation },
    ordered.map((e) => ({ id: e.id, sha256: e.sha256, contentType: e.contentType, body: e.body })),
    defs.map((d) => ({ id: d.id, title: d.title, description: d.description, verificationSupported: d.verificationSupported })),
    chat,
  );
}

/** The gates every AI call passes, in order: kill switch, org switch, provider, evaluated release, budget. */
async function gates(tx: Tx, c: Ctx, useCase: AiUseCase, provider: AiProvider | null) {
  const o = (await tx.select().from(orgs).where(eq(orgs.id, c.org.id)))[0];
  if (o.killAi) throw new AppError(423, "kill_switch_engaged", "AI features are stopped for this organization.");
  if (!o.aiEnabled) throw new AppError(409, "ai_disabled", "AI assistance is turned off for this organization.");
  if (!provider) throw new AppError(503, "ai_unavailable", "No AI provider is configured. Use the finding's remediation guidance.");
  const releaseId = await isReleased(tx, useCase, provider);
  if (!releaseId) throw new AppError(503, "ai_not_released", "This prompt has not passed evaluation for the configured model.");
  if ((await tokensUsed(tx)) >= o.aiMonthlyTokenBudget) throw new AppError(402, "quota_exceeded", "This month's AI budget is used up.");
  return releaseId;
}

// ---------- the call (provider + validation + one repair) ----------

export interface Outcome {
  status: AiStatus; validated: Validated | null; error: string | null; tokensIn: number; tokensOut: number; latencyMs: number;
}

/** Runs one analysis against a provider. Pure apart from the provider call. */
export async function analyse(p: AiProvider, messages: ChatMessage[], built: BuiltBundle): Promise<Outcome> {
  const started = Date.now();
  let tokensIn = 0, tokensOut = 0;
  try {
    let reply = await callProvider(p, { messages, maxTokens: MAX_OUTPUT_TOKENS });
    tokensIn += reply.tokensIn; tokensOut += reply.tokensOut;
    let parsed = checkSchema(reply.text);
    if (!parsed.ok) {
      // One repair attempt: show the model its own reply and the schema error, nothing new from the target.
      const repair: ChatMessage[] = [...messages, { role: "assistant", content: reply.text.slice(0, 4000) },
        { role: "user", content: `That reply did not match the required JSON shape (${parsed.error}). Reply again with the JSON object only.` }];
      reply = await callProvider(p, { messages: repair, maxTokens: MAX_OUTPUT_TOKENS });
      tokensIn += reply.tokensIn; tokensOut += reply.tokensOut;
      parsed = checkSchema(reply.text);
      if (!parsed.ok) return { status: "rejected", validated: null, error: `schema: ${parsed.error}`.slice(0, 500), tokensIn, tokensOut, latencyMs: Date.now() - started };
    }
    const v = ground(parsed.raw, built);
    return { status: v.status, validated: v, error: null, tokensIn, tokensOut, latencyMs: Date.now() - started };
  } catch (e) {
    const msg = e instanceof ProviderError ? `${e.code}: ${e.message}` : "provider: unexpected error";
    return { status: "unavailable", validated: null, error: msg, tokensIn, tokensOut, latencyMs: Date.now() - started };
  }
}

// ---------- request (RS-AI-001/002/003/006) ----------

const requestInput = z.object({ useCase: z.enum(["explain", "remediation"]), idempotencyKey: z.string().min(8).max(100) });
const BLOCKED = ["ai_disabled", "ai_unavailable", "ai_not_released", "quota_exceeded", "ai_input_blocked"];

export async function requestAnalysis(c: Ctx, findingId: string, input: unknown, deps: GatewayDeps = {}) {
  const parsed = requestInput.safeParse(input ?? {});
  if (!parsed.success) throw new AppError(422, "invalid_request", "Choose what to ask for and send a request key.");
  const { useCase, idempotencyKey } = parsed.data;
  const actor = userActor(c.principal);
  const provider = deps.provider !== undefined ? deps.provider : getProvider();
  const prompt = PROMPTS[useCase];

  let prep: { f: FindingRow; built: BuiltBundle; releaseId: string } | { replay: AnalysisRow };
  try {
    prep = await withOrg(c.org.id, async (tx) => {
      const { f, a } = await loadFinding(tx, c, findingId);
      await authorize(c.principal, "ai.request", res(f, a), c.org);
      const prior = (await tx.select().from(aiAnalyses).where(eq(aiAnalyses.idempotencyKey, idempotencyKey)))[0];
      if (prior) {
        if (prior.findingId !== f.id || prior.useCase !== useCase) throw new AppError(409, "idempotency_conflict", "This request key was already used for another request.");
        return { replay: prior };
      }
      const releaseId = await gates(tx, c, useCase, provider);
      const built = await gather(tx, f);
      return { f, built, releaseId };
    });
  } catch (e) {
    if (isAppError(e) && (BLOCKED.includes(e.code) || e.code === "kill_switch_engaged")) await auditBlocked(c, findingId, useCase, e.code);
    throw e;
  }
  if ("replay" in prep) return { analysis: prep.replay, claims: await claimsFor(c, prep.replay.id), replayed: true };

  const { f, built, releaseId } = prep;
  const messages = buildMessages(prompt, built.bundle);
  // Last line of defence: nothing that still looks like a credential leaves the service.
  if (messages.some((m) => containsSecret(m.content))) {
    await auditBlocked(c, findingId, useCase, "ai_input_blocked");
    throw new AppError(422, "ai_input_blocked", "The evidence still contains something that looks like a credential, so it was not sent.");
  }
  const out = await analyse(provider!, messages, built);
  if (out.status === "unavailable") log.warn("ai.provider_failed", { provider: provider!.name, error: out.error });

  return withOrg(c.org.id, async (tx) => {
    const v = out.validated;
    const inserted = (await tx.insert(aiAnalyses).values({
      orgId: c.org.id, findingId: f.id, useCase, promptId: prompt.id, promptVersion: prompt.version, schemaVersion: SCHEMA_VERSION,
      redactionVersion: AI_REDACTION_VERSION, provider: provider!.name, model: provider!.model, inputSha256: built.inputSha256, inputs: built.inputs,
      status: out.status, summary: v?.summary ?? null, uncertainty: v?.uncertainty ?? null, missingEvidence: v?.missingEvidence ?? [],
      droppedClaims: v?.dropped ?? 0, flags: v?.flags ?? [], tokensIn: out.tokensIn, tokensOut: out.tokensOut, latencyMs: out.latencyMs,
      error: out.error, requestedBy: c.principal.userId, idempotencyKey,
    }).onConflictDoNothing().returning())[0];
    if (!inserted) {
      // A concurrent request with the same key won; return its result.
      const prior = (await tx.select().from(aiAnalyses).where(eq(aiAnalyses.idempotencyKey, idempotencyKey)))[0];
      return { analysis: prior, claims: await tx.select().from(aiClaims).where(eq(aiClaims.analysisId, prior.id)).orderBy(asc(aiClaims.ordinal)), replayed: true };
    }
    const claims = v?.claims.length ? await tx.insert(aiClaims).values(v.claims.map((cl, i) => ({
      orgId: c.org.id, analysisId: inserted.id, ordinal: i + 1, type: cl.type, text: cl.text, evidenceIds: cl.evidenceIds,
      confidenceLabel: cl.confidence, verificationCheckIds: cl.verificationCheckIds, steps: cl.steps, approvalRequired: cl.approvalRequired,
    }))).returning() : [];
    const tokens = out.tokensIn + out.tokensOut;
    if (tokens > 0) await tx.insert(usageRecords).values({ orgId: c.org.id, kind: AI_USAGE_KIND, sourceId: inserted.id, quantity: tokens, period: period() }).onConflictDoNothing();
    await audit(tx, {
      actor, action: `ai.analysis.${out.status}`, target: { type: "finding", id: f.id }, outcome: out.status === "unavailable" ? "error" : "success",
      requestId: c.principal.requestId,
      details: {
        analysisId: inserted.id, useCase, prompt: `${prompt.id}@${prompt.version}`, provider: provider!.name, model: provider!.model, releaseEvalRunId: releaseId,
        inputSha256: built.inputSha256, redaction: AI_REDACTION_VERSION, claims: claims.length, dropped: v?.dropped ?? 0, flags: v?.flags ?? [], tokens, error: out.error,
      },
    });
    return { analysis: inserted, claims, replayed: false };
  });
}

// ---------- chat (advisory follow-up questions on one finding) ----------
// Each turn is an append-only ai_analyses row (use_case "chat") holding the REDACTED question and its thread id, so
// it gets the same release gate, budget, kill switch, grounding, citations, audit and purge as any analysis. The
// answer is advisory: it never changes the finding, and the question text is never written to the audit log.

const chatInput = z.object({
  question: z.string().trim().min(1, "Type a question.").max(MAX_QUESTION_CHARS, `Keep the question under ${MAX_QUESTION_CHARS} characters.`),
  threadId: z.string().uuid().optional(),
  idempotencyKey: z.string().min(8).max(100),
});

export async function chatOnFinding(c: Ctx, findingId: string, input: unknown, deps: GatewayDeps = {}) {
  const parsed = chatInput.safeParse(input ?? {});
  if (!parsed.success) throw new AppError(422, "invalid_request", parsed.error.issues[0].message);
  const { question, idempotencyKey } = parsed.data;
  const actor = userActor(c.principal);
  const provider = deps.provider !== undefined ? deps.provider : getProvider();
  const prompt = PROMPTS.chat;

  let prep: { f: FindingRow; built: BuiltBundle; releaseId: string; threadId: string } | { replay: AnalysisRow };
  try {
    prep = await withOrg(c.org.id, async (tx) => {
      const { f, a } = await loadFinding(tx, c, findingId);
      await authorize(c.principal, "ai.request", res(f, a), c.org);
      const prior = (await tx.select().from(aiAnalyses).where(eq(aiAnalyses.idempotencyKey, idempotencyKey)))[0];
      if (prior) {
        if (prior.findingId !== f.id || prior.useCase !== "chat") throw new AppError(409, "idempotency_conflict", "This request key was already used for another request.");
        return { replay: prior };
      }
      let threadId = parsed.data.threadId;
      let history: ChatInput["history"] = [];
      if (threadId) {
        const turns = await tx.select({ question: aiAnalyses.question, summary: aiAnalyses.summary }).from(aiAnalyses)
          .where(and(eq(aiAnalyses.threadId, threadId), eq(aiAnalyses.findingId, f.id), eq(aiAnalyses.useCase, "chat"))).orderBy(asc(aiAnalyses.createdAt));
        if (!turns.length) throw notFound();
        if (turns.length >= MAX_THREAD_TURNS) throw new AppError(409, "thread_full", `A conversation holds at most ${MAX_THREAD_TURNS} questions. Start a new one.`);
        history = turns.slice(-MAX_HISTORY_TURNS).map((t) => ({ question: t.question ?? "", answer: t.summary }));
      } else threadId = randomUUID();
      const releaseId = await gates(tx, c, "chat", provider);
      const built = await gather(tx, f, { question, history });
      return { f, built, releaseId, threadId };
    });
  } catch (e) {
    if (isAppError(e) && (BLOCKED.includes(e.code) || e.code === "kill_switch_engaged")) await auditBlocked(c, findingId, "chat", e.code);
    throw e;
  }
  if ("replay" in prep) return { analysis: prep.replay, claims: await claimsFor(c, prep.replay.id), replayed: true };

  const { f, built, releaseId, threadId } = prep;
  const storedQuestion = built.bundle.conversation!.question;
  const messages = buildMessages(prompt, built.bundle);
  if (messages.some((m) => containsSecret(m.content))) {
    await auditBlocked(c, findingId, "chat", "ai_input_blocked");
    throw new AppError(422, "ai_input_blocked", "The question or evidence still contains something that looks like a credential, so it was not sent. Remove it and ask again.");
  }
  const out = await analyse(provider!, messages, built);
  if (out.status === "unavailable") log.warn("ai.provider_failed", { provider: provider!.name, error: out.error });

  return withOrg(c.org.id, async (tx) => {
    const v = out.validated;
    const inserted = (await tx.insert(aiAnalyses).values({
      orgId: c.org.id, findingId: f.id, useCase: "chat", promptId: prompt.id, promptVersion: prompt.version, schemaVersion: SCHEMA_VERSION,
      redactionVersion: AI_REDACTION_VERSION, provider: provider!.name, model: provider!.model, inputSha256: built.inputSha256, inputs: built.inputs,
      status: out.status, summary: v?.summary ?? null, uncertainty: v?.uncertainty ?? null, missingEvidence: v?.missingEvidence ?? [],
      droppedClaims: v?.dropped ?? 0, flags: v?.flags ?? [], tokensIn: out.tokensIn, tokensOut: out.tokensOut, latencyMs: out.latencyMs,
      error: out.error, requestedBy: c.principal.userId, idempotencyKey, question: storedQuestion, threadId,
    }).onConflictDoNothing().returning())[0];
    if (!inserted) {
      const prior = (await tx.select().from(aiAnalyses).where(eq(aiAnalyses.idempotencyKey, idempotencyKey)))[0];
      return { analysis: prior, claims: await tx.select().from(aiClaims).where(eq(aiClaims.analysisId, prior.id)).orderBy(asc(aiClaims.ordinal)), replayed: true };
    }
    const claims = v?.claims.length ? await tx.insert(aiClaims).values(v.claims.map((cl, i) => ({
      orgId: c.org.id, analysisId: inserted.id, ordinal: i + 1, type: cl.type, text: cl.text, evidenceIds: cl.evidenceIds,
      confidenceLabel: cl.confidence, verificationCheckIds: cl.verificationCheckIds, steps: cl.steps, approvalRequired: cl.approvalRequired,
    }))).returning() : [];
    const tokens = out.tokensIn + out.tokensOut;
    if (tokens > 0) await tx.insert(usageRecords).values({ orgId: c.org.id, kind: AI_USAGE_KIND, sourceId: inserted.id, quantity: tokens, period: period() }).onConflictDoNothing();
    await audit(tx, {
      actor, action: `ai.chat.${out.status}`, target: { type: "finding", id: f.id }, outcome: out.status === "unavailable" ? "error" : "success",
      requestId: c.principal.requestId,
      details: {
        analysisId: inserted.id, threadId, questionChars: question.length, prompt: `${prompt.id}@${prompt.version}`, provider: provider!.name, model: provider!.model,
        releaseEvalRunId: releaseId, inputSha256: built.inputSha256, redaction: AI_REDACTION_VERSION, claims: claims.length, dropped: v?.dropped ?? 0, flags: v?.flags ?? [], tokens, error: out.error,
      },
    });
    return { analysis: inserted, claims, replayed: false };
  });
}

/** Chat threads on a finding, newest thread first, turns in order. */
export async function listChat(c: Ctx, findingId: string, threads = 3) {
  return withOrg(c.org.id, async (tx) => {
    const { f } = await loadFinding(tx, c, findingId);
    const rows = await tx.select().from(aiAnalyses).where(and(eq(aiAnalyses.findingId, f.id), eq(aiAnalyses.useCase, "chat")))
      .orderBy(desc(aiAnalyses.createdAt)).limit(threads * MAX_THREAD_TURNS);
    const claims = rows.length ? await tx.select().from(aiClaims).where(inArray(aiClaims.analysisId, rows.map((r) => r.id))).orderBy(asc(aiClaims.ordinal)) : [];
    const byThread = new Map<string, { analysis: AnalysisRow; claims: ClaimRow[] }[]>();
    for (const a of rows) {
      const t = a.threadId!;
      if (!byThread.has(t)) { if (byThread.size >= threads) continue; byThread.set(t, []); }
      byThread.get(t)!.unshift({ analysis: a, claims: claims.filter((cl) => cl.analysisId === a.id) });
    }
    return [...byThread.entries()].map(([threadId, turns]) => ({ threadId, turns, full: turns.length >= MAX_THREAD_TURNS }));
  });
}

async function auditBlocked(c: Ctx, findingId: string, useCase: string, code: string) {
  await withOrg(c.org.id, (tx) => audit(tx, {
    actor: userActor(c.principal), action: "ai.request.blocked", target: isUuid(findingId) ? { type: "finding", id: findingId } : null,
    outcome: "denied", reason: code, requestId: c.principal.requestId, details: { useCase },
  }));
}

async function claimsFor(c: Ctx, analysisId: string) {
  return withOrg(c.org.id, (tx) => tx.select().from(aiClaims).where(eq(aiClaims.analysisId, analysisId)).orderBy(asc(aiClaims.ordinal)));
}

// ---------- read ----------

export async function listAnalyses(c: Ctx, findingId: string, limit = 10) {
  return withOrg(c.org.id, async (tx) => {
    const { f } = await loadFinding(tx, c, findingId);
    const rows = await tx.select().from(aiAnalyses).where(and(eq(aiAnalyses.findingId, f.id), sql`${aiAnalyses.useCase} <> 'chat'`)).orderBy(desc(aiAnalyses.createdAt)).limit(limit);
    const claims = rows.length ? await tx.select().from(aiClaims).where(inArray(aiClaims.analysisId, rows.map((r) => r.id))).orderBy(asc(aiClaims.ordinal)) : [];
    return rows.map((a) => ({ analysis: a, claims: claims.filter((cl) => cl.analysisId === a.id) }));
  });
}

export interface AiStatusView {
  enabled: boolean; killed: boolean; provider: string | null; model: string | null;
  released: Record<AiUseCase, boolean>; budget: number; used: number; period: string;
}

export async function aiStatus(c: Ctx, deps: GatewayDeps = {}): Promise<AiStatusView> {
  const provider = deps.provider !== undefined ? deps.provider : getProvider();
  return withOrg(c.org.id, async (tx) => {
    const o = (await tx.select().from(orgs).where(eq(orgs.id, c.org.id)))[0];
    return {
      enabled: o.aiEnabled, killed: o.killAi, provider: provider?.name ?? null, model: provider?.model ?? null,
      released: {
        explain: provider ? !!(await isReleased(tx, "explain", provider)) : false,
        remediation: provider ? !!(await isReleased(tx, "remediation", provider)) : false,
        chat: provider ? !!(await isReleased(tx, "chat", provider)) : false,
      },
      budget: o.aiMonthlyTokenBudget, used: await tokensUsed(tx), period: period(),
    };
  });
}

// ---------- configure (RS-AI-006) ----------

const configInput = z.object({
  enabled: z.boolean(),
  reason: z.string().trim().min(3, "Give a reason (at least 3 characters).").max(500),
  monthlyTokenBudget: z.number().int().min(0).max(100_000_000).optional(),
});

export async function setAiSettings(c: Ctx, input: unknown) {
  await authorize(c.principal, "ai.configure", { type: "org", id: c.org.id }, c.org);
  const r = configInput.safeParse(input);
  if (!r.success) throw new AppError(422, "validation_failed", r.error.issues[0].message);
  const { enabled, reason, monthlyTokenBudget } = r.data;
  await withOrg(c.org.id, async (tx) => {
    await tx.update(orgs).set({ aiEnabled: enabled, ...(monthlyTokenBudget !== undefined ? { aiMonthlyTokenBudget: monthlyTokenBudget } : {}) }).where(eq(orgs.id, c.org.id));
    await audit(tx, {
      actor: userActor(c.principal), action: "ai.settings.changed", target: { type: "org", id: c.org.id }, reason, requestId: c.principal.requestId,
      details: { enabled, ...(monthlyTokenBudget !== undefined ? { monthlyTokenBudget } : {}) },
    });
  });
}
