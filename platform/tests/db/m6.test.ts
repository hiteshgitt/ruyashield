import { randomUUID } from "node:crypto";
import { eq, sql } from "drizzle-orm";
import { describe, expect, it } from "vitest";
import { db, withOrg } from "@/server/db/client";
import { assets, findings, users } from "@/server/db/schema";
import { createOrg } from "@/server/orgs/orgs";
import { loadPrincipal, type LoadedPrincipal } from "@/server/principal";
import type { SessionInfo } from "@/server/auth/session";
import { launchAssessment, runAssessment } from "@/server/assessments/assessments";
import type { CheckAdapter } from "@/server/assessments/checks";
import { createExposureAdapter, type Fetch } from "@/server/assessments/exposure";
import { createTlsConfigAdapter, WEAK_CIPHERS, type Handshake, type LegacyProbe } from "@/server/assessments/tlsconfig";
import { transition } from "@/server/findings/findings";
import { requestVerification, runVerification } from "@/server/verification/verification";
import { EgressError, type FetchResult, type HandshakeResult } from "@/server/net/egress";

/** Never spawn the real legacy OpenSSL client in tests. */
const noLegacy: LegacyProbe = async () => ({ outcome: "untestable", code: "legacy_openssl_unavailable" });

// Scanner M6 end to end: tls.config and http.exposure raise findings, and removing the problem then re-testing
// resolves them as verified; a re-test that cannot reach the site does not. Network is faked; the adapters' logic
// is covered by tests/unit/tlsconfig.test.ts and tests/unit/exposure.test.ts.
const run = process.env.DATABASE_URL ? describe : describe.skip;

async function fixture() {
  const email = `t-${randomUUID()}@ruya-tests.invalid`;
  const [u] = await db.insert(users).values({ email, displayName: "Test", idpIssuer: "test", idpSubject: email }).returning();
  const user: SessionInfo = { idHash: "x", userId: u.id, email, displayName: "Test", activeOrgId: null, mfa: true, amr: ["mfa"], authTime: new Date() };
  const org = await createOrg(user, { name: `M6 ${randomUUID().slice(0, 8)}` });
  const ctx = (await loadPrincipal(user, org.id))!;
  const [asset] = await withOrg(org.id, (tx) => tx.insert(assets).values({
    orgId: org.id, host: `m6-${randomUUID().slice(0, 8)}.example.com`, displayName: "site", environment: "production", createdBy: user.userId, status: "verified",
  }).returning());
  return { ctx, asset };
}
const deps = (id: string, a: CheckAdapter) => ({ adapters: new Map([[id, a]]), minIntervalMs: 0 });
async function scan(ctx: LoadedPrincipal, assetId: string, id: string, a: CheckAdapter) {
  const { assessment } = await launchAssessment(ctx, { assetId, idempotencyKey: `k-${randomUUID()}`, checkIds: [id] });
  const job = await withOrg(ctx.org.id, (tx) => tx.execute<{ payload: { assessmentId: string; token: string } }>(
    sql`SELECT payload FROM outbox WHERE business_key = ${`assessment:${assessment.id}:1`}`));
  await runAssessment(ctx.org.id, job.rows[0].payload, deps(id, a));
}
const findingsOf = (orgId: string, assetId: string) => withOrg(orgId, (tx) => tx.select().from(findings).where(eq(findings.assetId, assetId)));
async function retest(ctx: LoadedPrincipal, findingId: string, id: string, a: CheckAdapter) {
  for (const k of ["triage", "confirm", "start_remediation", "mark_fix_applied"]) await transition(ctx, findingId, k);
  const { run: r } = await requestVerification(ctx, findingId, { idempotencyKey: `v-${randomUUID()}` });
  return runVerification(ctx.org.id, { runId: r.id }, deps(id, a));
}

// --- tls.config fakes
const A = "203.0.113.10";
const ok = (protocol: string): HandshakeResult => ({ outcome: "accepted", protocol, cipher: "ECDHE-RSA-AES128-GCM-SHA256", keyBits: 2048, keyType: "RSA", authorizationError: null, pinnedAddress: A });
const refused: HandshakeResult = { outcome: "refused", code: "alert", pinnedAddress: A };
const tlsServer = (tls10: boolean): Handshake => async (_h, o) =>
  o.ciphers === WEAK_CIPHERS ? refused : !o.minVersion ? ok("TLSv1.3") : o.minVersion === "TLSv1" ? (tls10 ? ok("TLSv1") : refused) : o.minVersion === "TLSv1.1" ? refused : ok(o.minVersion);

// --- http.exposure fakes
const page = (status: number, body = "", contentType = "text/html"): FetchResult =>
  ({ status, body, contentType, truncated: false, redirects: 0, finalUrl: "", pinnedAddress: A, headers: {} } as FetchResult);
const site = (envExposed: boolean): Fetch => async (url) =>
  new URL(url).pathname === "/.env" && envExposed ? page(200, "DB_PASSWORD=zq7-canary-value\n", "text/plain") : page(404, "nope");

run("scanner M6 (database)", () => {
  it("tls.config: TLS 1.0 finding resolves as verified once TLS 1.0 is disabled", async () => {
    const { ctx, asset } = await fixture();
    await scan(ctx, asset.id, "tls.config@1", createTlsConfigAdapter(tlsServer(true), noLegacy));
    const [f] = await findingsOf(ctx.org.id, asset.id);
    expect(f).toMatchObject({ checkKey: "tls.config", issueKey: "tls10_enabled", severity: "medium", status: "new", location: `${asset.host}:443` });
    expect(await retest(ctx, f.id, "tls.config@1", createTlsConfigAdapter(tlsServer(false), noLegacy))).toBe("completed:verified");
    expect((await findingsOf(ctx.org.id, asset.id))[0].status).toBe("resolved_verified");
  });

  it("http.exposure: .env finding resolves as verified once the file is gone, and stores no contents", async () => {
    const { ctx, asset } = await fixture();
    await scan(ctx, asset.id, "http.exposure@1", createExposureAdapter(site(true)));
    const [f] = await findingsOf(ctx.org.id, asset.id);
    expect(f).toMatchObject({ checkKey: "http.exposure", issueKey: "env-exposed", severity: "critical", status: "new", location: `https://${asset.host}/.env` });
    expect(JSON.stringify(f)).not.toContain("zq7-canary");
    expect(await retest(ctx, f.id, "http.exposure@1", createExposureAdapter(site(false)))).toBe("completed:verified");
    expect((await findingsOf(ctx.org.id, asset.id))[0].status).toBe("resolved_verified");
  });

  it("http.exposure: a re-test that cannot reach the site does not resolve the finding", async () => {
    const { ctx, asset } = await fixture();
    await scan(ctx, asset.id, "http.exposure@1", createExposureAdapter(site(true)));
    const [f] = await findingsOf(ctx.org.id, asset.id);
    const down = createExposureAdapter(async () => { throw new EgressError("network", "ECONNREFUSED"); });
    expect(await retest(ctx, f.id, "http.exposure@1", down)).not.toBe("completed:verified");
    expect((await findingsOf(ctx.org.id, asset.id))[0].status).not.toBe("resolved_verified");
  });
});
