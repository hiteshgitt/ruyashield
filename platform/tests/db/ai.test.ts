import { randomUUID } from "node:crypto";
import { eq, sql } from "drizzle-orm";
import { Client } from "pg";
import { describe, expect, it } from "vitest";
import { db, withOrg } from "@/server/db/client";
import { aiAnalyses, aiClaims, assets, auditEvents, findings, memberships, users } from "@/server/db/schema";
import { createOrg, setKillSwitch } from "@/server/orgs/orgs";
import { loadPrincipal, type LoadedPrincipal } from "@/server/principal";
import { launchAssessment, runAssessment } from "@/server/assessments/assessments";
import type { CheckAdapter, CheckResult } from "@/server/assessments/checks";
import type { SessionInfo } from "@/server/auth/session";
import { aiStatus, chatOnFinding, listAnalyses, listChat, requestAnalysis, setAiSettings } from "@/server/ai/gateway";
import { fixtureProvider, resetBreaker, type AiProvider } from "@/server/ai/providers";

// Needs a migrated database reachable as the runtime role, and the fixture prompts released (npm run ai:eval -- --provider fixture --promote).
const run = process.env.DATABASE_URL ? describe : describe.skip;

async function newUser(): Promise<SessionInfo> {
  const email = `t-${randomUUID()}@ruya-tests.invalid`;
  const [u] = await db.insert(users).values({ email, displayName: "Test", idpIssuer: "test", idpSubject: email }).returning();
  return { idHash: "x", userId: u.id, email, displayName: "Test", activeOrgId: null, mfa: true, amr: ["mfa"], authTime: new Date() };
}
const stub = (id: string, result: CheckResult): CheckAdapter => ({ id, checkKey: id.split("@")[0], run: async () => result });
const ok = (found: Extract<CheckResult, { status: "ok" }>["findings"] = []): CheckResult => ({ status: "ok", findings: found, evidence: { note: "captured" } });

async function fixture() {
  const user = await newUser();
  const org = await createOrg(user, { name: `AI ${randomUUID().slice(0, 8)}` });
  const ctx = (await loadPrincipal(user, org.id))!;
  const [asset] = await withOrg(org.id, (tx) => tx.insert(assets).values({
    orgId: org.id, host: `ai-${randomUUID().slice(0, 8)}.example.com`, displayName: "app", environment: "production", createdBy: user.userId, status: "verified",
  }).returning());
  const { assessment } = await launchAssessment(ctx, { assetId: asset.id, idempotencyKey: `k-${randomUUID()}`, checkIds: ["http.security_headers@1"] });
  const job = await withOrg(org.id, (tx) => tx.execute<{ payload: { assessmentId: string; token: string } }>(
    sql`SELECT payload FROM outbox WHERE business_key = ${`assessment:${assessment.id}:1`}`));
  const r = ok([{ issueKey: "hsts_missing", title: "HSTS header missing", severity: "medium", location: `https://${asset.host}/`, evidence: { missing: ["strict-transport-security"] }, remediation: "Send Strict-Transport-Security. Roll out on staging first." }]);
  await runAssessment(org.id, job.rows[0].payload, { adapters: new Map([["http.security_headers@1", stub("http.security_headers@1", r)]]), minIntervalMs: 0 });
  const [f] = await withOrg(org.id, (tx) => tx.select().from(findings).where(eq(findings.assetId, asset.id)));
  return { user, org, ctx, finding: f };
}
const enable = (ctx: LoadedPrincipal, budget?: number) => setAiSettings(ctx, { enabled: true, reason: "test", monthlyTokenBudget: budget });
const ask = (ctx: LoadedPrincipal, findingId: string, useCase = "explain", key = `ai-${randomUUID()}`, provider: AiProvider | null = fixtureProvider) =>
  requestAnalysis(ctx, findingId, { useCase, idempotencyKey: key }, { provider });
const code = (p: Promise<unknown>) => p.then(() => "ok", (e: { status?: number; code?: string }) => `${e.status} ${e.code}`);

async function member(ctx: LoadedPrincipal, role: "viewer" | "security_lead") {
  const u = await newUser();
  await withOrg(ctx.org.id, (tx) => tx.insert(memberships).values({ orgId: ctx.org.id, userId: u.userId, role, restricted: false }));
  return (await loadPrincipal(u, ctx.org.id))!;
}

run("AI gateway (P4)", () => {
  it("is off until an admin turns it on, and needs a provider and a released prompt", async () => {
    resetBreaker();
    const { ctx, finding } = await fixture();
    expect(await code(ask(ctx, finding.id))).toBe("409 ai_disabled");
    await enable(ctx);
    expect(await code(ask(ctx, finding.id, "explain", undefined, null))).toBe("503 ai_unavailable");
    const unreleased: AiProvider = { ...fixtureProvider, model: "never-evaluated/1" };
    expect(await code(ask(ctx, finding.id, "explain", undefined, unreleased))).toBe("503 ai_not_released");
    const blocked = await withOrg(ctx.org.id, (tx) => tx.select().from(auditEvents).where(eq(auditEvents.action, "ai.request.blocked")));
    expect(blocked.map((b) => b.reason).sort()).toEqual(["ai_disabled", "ai_not_released", "ai_unavailable"]);
  });

  it("stores a grounded analysis with provenance, usage and audit, and replays by key", async () => {
    const { ctx, finding } = await fixture();
    await enable(ctx);
    const key = `ai-${randomUUID()}`;
    const r = await ask(ctx, finding.id, "remediation", key);
    expect(r.analysis).toMatchObject({ status: "completed", provider: "fixture", useCase: "remediation", promptId: "finding.remediation", redactionVersion: "ai-redact/1" });
    expect(r.analysis.inputSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(r.claims.length).toBeGreaterThan(0);
    for (const c of r.claims) expect(c.evidenceIds.length).toBeGreaterThan(0);
    expect(r.claims.find((c) => c.type === "recommendation")).toMatchObject({ approvalRequired: true });
    expect(r.claims.find((c) => c.type === "inference")?.confidenceLabel).not.toBe("confirmed");

    const again = await ask(ctx, finding.id, "remediation", key);
    expect(again).toMatchObject({ replayed: true, analysis: { id: r.analysis.id } });
    expect(await code(ask(ctx, finding.id, "explain", key))).toBe("409 idempotency_conflict");

    // The analysis never changes the finding.
    const [after] = await withOrg(ctx.org.id, (tx) => tx.select().from(findings).where(eq(findings.id, finding.id)));
    expect(after.status).toBe(finding.status);
    const st = await aiStatus(ctx, { provider: fixtureProvider });
    expect(st.used).toBe(r.analysis.tokensIn + r.analysis.tokensOut);
    expect((await listAnalyses(ctx, finding.id))[0].analysis.id).toBe(r.analysis.id);
    const ev = await withOrg(ctx.org.id, (tx) => tx.select().from(auditEvents).where(eq(auditEvents.action, "ai.analysis.completed")));
    expect(ev).toHaveLength(1);
  });

  it("records a rejected analysis without claims when the model output is invalid", async () => {
    resetBreaker();
    const { ctx, finding } = await fixture();
    await enable(ctx);
    const bad: AiProvider = { ...fixtureProvider, complete: async () => ({ text: "not json", tokensIn: 5, tokensOut: 5 }) };
    // Only released provider/models may be called, so reuse the fixture's identity.
    const r = await ask(ctx, finding.id, "explain", undefined, bad);
    expect(r.analysis.status).toBe("rejected");
    expect(r.claims).toEqual([]);
  });

  it("enforces the budget, the kill switch and role", async () => {
    const { user, ctx, finding } = await fixture();
    await enable(ctx, 0);
    expect(await code(ask(ctx, finding.id))).toBe("402 quota_exceeded");
    await enable(ctx, 200000);
    await setKillSwitch(ctx, "ai", true, "incident drill");
    // The principal snapshot holds the org's kill flags, so reload it after flipping one.
    const killed = (await loadPrincipal(user, ctx.org.id))!;
    expect(await code(ask(killed, finding.id))).toBe("423 kill_switch_engaged");
    await setKillSwitch(ctx, "ai", false, "drill over");
    const viewer = await member(ctx, "viewer");
    expect(await code(ask(viewer, finding.id))).toBe("403 forbidden");
    const lead = await member(ctx, "security_lead");
    expect(await code(setAiSettings(lead, { enabled: false, reason: "x y z" }))).toBe("ok");
  });

  it("isolates analyses by org and keeps them append-only", async () => {
    const a = await fixture();
    const b = await fixture();
    await enable(a.ctx);
    const r = await ask(a.ctx, a.finding.id);
    expect(await code(listAnalyses(b.ctx, a.finding.id))).toBe("404 not_found");
    const seen = await withOrg(b.org.id, (tx) => tx.select().from(aiAnalyses).where(eq(aiAnalyses.id, r.analysis.id)));
    expect(seen).toEqual([]);
    await expect(withOrg(a.org.id, (tx) => tx.update(aiClaims).set({ text: "edited" }).where(eq(aiClaims.analysisId, r.analysis.id)))).rejects.toThrow();
    const owner = new Client({ connectionString: process.env.DATABASE_OWNER_URL });
    await owner.connect();
    try {
      await expect(owner.query("DELETE FROM ai_analyses WHERE id = $1", [r.analysis.id])).rejects.toThrow(/append-only/);
      const fail = await owner.query<{ id: string }>(`INSERT INTO ai_eval_runs (prompt_id, prompt_version, template_sha256, provider, model, metrics, thresholds, passed)
        VALUES ('explain', 999, $1, 'test', 'm', '{}', '{}', false) RETURNING id`, ["a".repeat(64)]);
      await expect(owner.query(`INSERT INTO ai_prompt_releases (prompt_id, prompt_version, template_sha256, provider, model, eval_run_id) VALUES ('explain', 999, $1, 'test', 'm', $2)`,
        ["a".repeat(64), fail.rows[0].id])).rejects.toThrow(/passing eval/);
    } finally {
      await owner.end();
    }
  });

  it("chat: threads, history, redaction, limits, replay and audit without the question text", async () => {
    resetBreaker();
    const { ctx, finding } = await fixture();
    await enable(ctx);
    const say = (question: string, threadId?: string, key = `c-${randomUUID()}`) => chatOnFinding(ctx, finding.id, { question, threadId, idempotencyKey: key }, { provider: fixtureProvider });
    const key = `c-${randomUUID()}`;
    const SECRET = "sk-live-" + "dbchatcanaryQWERTY987654";
    const first = await say(`How do I fix this? my key ${SECRET}`, undefined, key);
    expect(first.analysis).toMatchObject({ status: "completed", useCase: "chat", promptId: "finding.chat" });
    expect(first.analysis.threadId).toMatch(/^[0-9a-f-]{36}$/);
    expect(first.analysis.question).not.toContain("dbchatcanary");
    expect(await say("x", undefined, key)).toMatchObject({ replayed: true, analysis: { id: first.analysis.id } });
    expect(await code(ask(ctx, finding.id, "explain", key))).toBe("409 idempotency_conflict");

    const second = await say("And on Apache?", first.analysis.threadId!);
    expect(second.analysis.threadId).toBe(first.analysis.threadId);
    expect(await code(say("x", randomUUID()))).toBe("404 not_found");
    expect(await code(say("   "))).toBe("422 invalid_request");
    expect(await code(say("x".repeat(1001)))).toBe("422 invalid_request");

    const threads = await listChat(ctx, finding.id);
    expect(threads).toHaveLength(1);
    expect(threads[0].turns.map((t) => t.analysis.id)).toEqual([first.analysis.id, second.analysis.id]);
    expect((await listAnalyses(ctx, finding.id)).map((e) => e.analysis.useCase)).not.toContain("chat");
    expect((await aiStatus(ctx)).released.chat).toBe(true);

    for (let i = 2; i < 10; i++) await say(`q${i}`, first.analysis.threadId!);
    expect((await listChat(ctx, finding.id))[0].full).toBe(true);
    expect(await code(say("one more", first.analysis.threadId!))).toBe("409 thread_full");

    const audits = await withOrg(ctx.org.id, (tx) => tx.select().from(auditEvents).where(sql`${auditEvents.action} LIKE 'ai.chat.%'`));
    expect(audits.length).toBeGreaterThanOrEqual(10);
    expect(JSON.stringify(audits)).not.toMatch(/dbchatcanary|How do I fix|Apache/);

    const viewer = await member(ctx, "viewer");
    expect(await code(chatOnFinding(viewer, finding.id, { question: "hi", idempotencyKey: `c-${randomUUID()}` }, { provider: fixtureProvider }))).toBe("403 forbidden");
  });
});
