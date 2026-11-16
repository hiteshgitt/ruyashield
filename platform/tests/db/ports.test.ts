import { randomUUID } from "node:crypto";
import { eq, sql } from "drizzle-orm";
import { describe, expect, it } from "vitest";
import { db, withOrg } from "@/server/db/client";
import { assets, findings, memberships, users } from "@/server/db/schema";
import { createOrg, getIntrusiveNetwork, setIntrusiveNetwork } from "@/server/orgs/orgs";
import { loadPrincipal, type LoadedPrincipal } from "@/server/principal";
import type { SessionInfo } from "@/server/auth/session";
import { launchAssessment, listCatalogue, runAssessment } from "@/server/assessments/assessments";
import { createExposedServicesAdapter, type Probe } from "@/server/assessments/ports";
import { transition } from "@/server/findings/findings";
import { requestVerification, runVerification } from "@/server/verification/verification";
import type { PortState } from "@/server/net/egress";

// net.exposed_services end to end: opt-in by two admins, an open port becomes a finding, closing it and re-testing
// resolves it as verified, and port checks are limited to one launch an hour per asset. The probe is faked; the
// TCP probe itself is covered by tests/unit/ports.test.ts.
const run = process.env.DATABASE_URL ? describe : describe.skip;
const ID = "net.exposed_services@1";

async function newUser(): Promise<SessionInfo> {
  const email = `t-${randomUUID()}@ruya-tests.invalid`;
  const [u] = await db.insert(users).values({ email, displayName: "Test", idpIssuer: "test", idpSubject: email }).returning();
  return { idHash: "x", userId: u.id, email, displayName: "Test", activeOrgId: null, mfa: true, amr: ["mfa"], authTime: new Date() };
}

async function fixture() {
  const user = await newUser();
  const org = await createOrg(user, { name: `Ports ${randomUUID().slice(0, 8)}` });
  const ctx = (await loadPrincipal(user, org.id))!;
  const second = await newUser();
  await withOrg(org.id, (tx) => tx.insert(memberships).values({ orgId: org.id, userId: second.userId, role: "org_admin", restricted: false }));
  const ctx2 = (await loadPrincipal(second, org.id))!;
  const [asset] = await withOrg(org.id, (tx) => tx.insert(assets).values({
    orgId: org.id, host: `ports-${randomUUID().slice(0, 8)}.example.com`, displayName: "server", environment: "production",
    createdBy: user.userId, status: "verified",
  }).returning());
  return { ctx, ctx2, asset };
}

const probe = (open: number[]): Probe => async (_h, ports) => ({
  pinnedAddress: "203.0.113.7",
  results: ports.map((port) => ({ port, state: (open.includes(port) ? "open" : "closed") as PortState })),
});
const deps = (open: number[]) => ({ adapters: new Map([[ID, createExposedServicesAdapter(probe(open))]]), minIntervalMs: 0 });

async function scan(ctx: LoadedPrincipal, assetId: string, open: number[]) {
  const { assessment } = await launchAssessment(ctx, { assetId, idempotencyKey: `k-${randomUUID()}`, checkIds: [ID] });
  const job = await withOrg(ctx.org.id, (tx) => tx.execute<{ payload: { assessmentId: string; token: string } }>(
    sql`SELECT payload FROM outbox WHERE business_key = ${`assessment:${assessment.id}:1`}`));
  await runAssessment(ctx.org.id, job.rows[0].payload, deps(open));
  return assessment.id;
}
const findingsOf = (orgId: string, assetId: string) => withOrg(orgId, (tx) => tx.select().from(findings).where(eq(findings.assetId, assetId)));

run("net.exposed_services (database)", () => {
  it("is refused until two different admins opt the organization in", async () => {
    const { ctx, ctx2, asset } = await fixture();
    await expect(scan(ctx, asset.id, [])).rejects.toMatchObject({ code: "approval_required" });
    const cat = await listCatalogue(ctx);
    expect(cat.find((d) => d.id === ID)).toBeDefined();

    expect(await setIntrusiveNetwork(ctx, true, "quarterly port review")).toBe("requested");
    expect(await getIntrusiveNetwork(ctx)).toMatchObject({ enabled: false, pending: true, requestedBy: ctx.principal.userId });
    await expect(setIntrusiveNetwork(ctx, true, "again")).rejects.toMatchObject({ code: "second_person_required" });
    await expect(scan(ctx, asset.id, [])).rejects.toMatchObject({ code: "approval_required" });

    expect(await setIntrusiveNetwork(ctx2, true, "confirmed")).toBe("enabled");
    expect(await getIntrusiveNetwork(ctx)).toMatchObject({ enabled: true, pending: false });
  });

  it("raises an open-port finding, resolves it as verified once closed, and limits launches to one an hour", async () => {
    const { ctx, ctx2, asset } = await fixture();
    await setIntrusiveNetwork(ctx, true, "enable");
    await setIntrusiveNetwork(ctx2, true, "confirm");
    await scan(ctx, asset.id, [6379, 443]);
    const [f] = await findingsOf(ctx.org.id, asset.id);
    expect(f).toMatchObject({ checkKey: "net.exposed_services", status: "new", severity: "critical", location: `${asset.host}:6379` });
    expect(f.evidence).toMatchObject({ port: 6379, service: "Redis", pinnedAddress: "203.0.113.7" });

    // A second launch within the hour is refused, even though the first one finished.
    await expect(scan(ctx, asset.id, [])).rejects.toMatchObject({ status: 429, code: "rate_limited" });

    for (const k of ["triage", "confirm", "start_remediation", "mark_fix_applied"]) await transition(ctx, f.id, k);
    // Still open on re-test: the fix is rejected and the finding reopens.
    const { run: r } = await requestVerification(ctx, f.id, { idempotencyKey: `v-${randomUUID()}` });
    expect(await runVerification(ctx.org.id, { runId: r.id }, deps([6379]))).toBe("completed:failed");
    expect((await findingsOf(ctx.org.id, asset.id))[0].status).toBe("reopened");

    for (const k of ["start_remediation", "mark_fix_applied"]) await transition(ctx, f.id, k);
    const { run: r2 } = await requestVerification(ctx, f.id, { idempotencyKey: `v-${randomUUID()}` });
    expect(await runVerification(ctx.org.id, { runId: r2.id }, deps([]))).toBe("completed:verified");
    expect((await findingsOf(ctx.org.id, asset.id))[0].status).toBe("resolved_verified");
  });

  it("does not resolve the finding when the host is unreachable on re-test (fails closed)", async () => {
    const { ctx, ctx2, asset } = await fixture();
    await setIntrusiveNetwork(ctx, true, "enable");
    await setIntrusiveNetwork(ctx2, true, "confirm");
    await scan(ctx, asset.id, [3389]);
    const [f] = await findingsOf(ctx.org.id, asset.id);
    for (const k of ["triage", "confirm", "start_remediation", "mark_fix_applied"]) await transition(ctx, f.id, k);
    const { run: r } = await requestVerification(ctx, f.id, { idempotencyKey: `v-${randomUUID()}` });
    const { EgressError } = await import("@/server/net/egress");
    const down: Probe = async () => { throw new EgressError("network", "EHOSTUNREACH on port 22"); };
    const out = await runVerification(ctx.org.id, { runId: r.id }, { adapters: new Map([[ID, createExposedServicesAdapter(down)]]), minIntervalMs: 0 });
    expect(out).not.toBe("completed:verified");
    expect((await findingsOf(ctx.org.id, asset.id))[0].status).not.toBe("resolved_verified");
  });
});
