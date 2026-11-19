import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { signHandoff } from "@/server/webmonitor/adapter";
import { lookupPackageReport, receivePackageReport } from "@/server/webmonitor/packages";
import { eq, sql } from "drizzle-orm";
import { db, withOrg } from "@/server/db/client";
import { assets, findings, users } from "@/server/db/schema";
import { createOrg } from "@/server/orgs/orgs";
import { loadPrincipal } from "@/server/principal";
import { launchAssessment, runAssessment } from "@/server/assessments/assessments";
import type { SessionInfo } from "@/server/auth/session";

const run = process.env.DATABASE_URL ? describe : describe.skip;
const KEY = "k".repeat(40);
const hoursAgo = (h: number) => new Date(Date.now() - h * 3600_000).toISOString();

function signed(body: object, at = new Date()) {
  const text = JSON.stringify(body);
  const ts = String(Math.floor(at.getTime() / 1000));
  return { h: { timestamp: ts, signature: signHandoff(ts, text, KEY) }, text };
}

run("WebMonitor package reports (database)", () => {
  it("stores a signed report by host, keeps the newest, refuses bad signatures, and finds the www twin", async () => {
    const prev = process.env.WEBMONITOR_HANDOFF_SECRET;
    process.env.WEBMONITOR_HANDOFF_SECRET = KEY;
    try {
      const host = `pkg-${randomUUID().slice(0, 8)}.example.com`;
      const pkg = { name: "next", version: "16.4.3", severity: "moderate", ids: ["GHSA-mfr8-8qww-v76h"], aliases: [], fixed: "16.4.5", summary: null };
      const newer = signed({ host: `www.${host}`, ecosystem: "npm", observedAt: hoursAgo(1), packages: [pkg] });
      const first = await receivePackageReport(newer.h, newer.text);
      expect(first.body).toMatchObject({ status: "received" });
      const older = signed({ host: `www.${host}`, ecosystem: "npm", observedAt: hoursAgo(25), packages: [] });
      expect((await receivePackageReport(older.h, older.text)).status).toBe(202);
      const got = await lookupPackageReport(host); // bare host finds the www. report
      expect(got?.packages.map((p) => p.name)).toEqual(["next"]); // the older empty report did not replace it
      const forged = { h: { ...newer.h, signature: "sha256=" + "0".repeat(64) }, text: newer.text };
      expect((await receivePackageReport(forged.h, forged.text)).status).toBe(401);
      const bad = signed({ host, ecosystem: "npm", observedAt: hoursAgo(1), packages: [{ ...pkg, name: "bad name; drop" }] });
      expect((await receivePackageReport(bad.h, bad.text)).status).toBe(422);
    } finally {
      process.env.WEBMONITOR_HANDOFF_SECRET = prev;
    }
  });

  it("an assessment with webmonitor.packages turns the report into findings; a clean report alone does not close them (FixProof does)", async () => {
    const prev = process.env.WEBMONITOR_HANDOFF_SECRET;
    process.env.WEBMONITOR_HANDOFF_SECRET = KEY;
    try {
      const email = `t-${randomUUID()}@ruya-tests.invalid`;
      const [u] = await db.insert(users).values({ email, displayName: "T", idpIssuer: "test", idpSubject: email }).returning();
      const s: SessionInfo = { idHash: "x", userId: u.id, email, displayName: "T", activeOrgId: null, mfa: true, amr: ["mfa"], authTime: new Date() };
      const org = await createOrg(s, { name: `Pkg ${randomUUID().slice(0, 8)}` });
      const ctx = (await loadPrincipal(s, org.id))!;
      const host = `pkgrun-${randomUUID().slice(0, 8)}.example.com`;
      const [a] = await withOrg(org.id, (tx) => tx.insert(assets).values({ orgId: org.id, host, displayName: "shop", environment: "production", createdBy: u.id, status: "verified" }).returning());
      const pkg = { name: "next", version: "16.4.3", severity: "high", ids: ["GHSA-mfr8-8qww-v76h"], aliases: ["CVE-2026-119790"], fixed: "16.4.5", summary: null };
      const send = async (packages: unknown[], hoursOld: number) => {
        const r = signed({ host, ecosystem: "npm", observedAt: hoursAgo(hoursOld), packages });
        expect((await receivePackageReport(r.h, r.text)).status).toBe(202);
      };
      const assess = async () => {
        const { assessment } = await launchAssessment(ctx, { assetId: a.id, idempotencyKey: `k-${randomUUID()}`, checkIds: ["webmonitor.packages@1"] });
        const job = await withOrg(org.id, (tx) => tx.execute<{ payload: { assessmentId: string; token: string } }>(sql`SELECT payload FROM outbox WHERE business_key = ${`assessment:${assessment.id}:1`}`));
        await runAssessment(org.id, job.rows[0].payload, { minIntervalMs: 0 });
        return withOrg(org.id, (tx) => tx.select().from(findings).where(eq(findings.assetId, a.id)));
      };
      await send([pkg], 2);
      const [f] = await assess();
      expect(f).toMatchObject({ issueKey: "pkg.npm.next", severity: "high", checkKey: "webmonitor.packages" });
      expect(f.title).toContain("CVE-2026-119790");
      await send([], 1); // upgraded: the next report no longer lists it
      const after = await assess();
      // Like every RuyaShield check, absence does not close a finding: only a FixProof re-test of this check does.
      expect(after).toHaveLength(1);
      expect(after[0].id).toBe(f.id);
    } finally {
      process.env.WEBMONITOR_HANDOFF_SECRET = prev;
    }
  });
});
