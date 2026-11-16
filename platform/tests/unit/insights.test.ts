import { describe, expect, it } from "vitest";
import { exposureScore, SECURITY_AREAS, weekStart } from "@/server/reports/insights";

const sev = (o: Partial<Record<"critical" | "high" | "medium" | "low" | "info", number>> = {}) =>
  ({ critical: 0, high: 0, medium: 0, low: 0, info: 0, ...o });

describe("exposureScore", () => {
  it("is null without a completed assessment, so no data never reads as 100", () => {
    expect(exposureScore(sev(), 0)).toBeNull();
    expect(exposureScore(sev({ critical: 3 }), 0)).toBeNull();
  });

  it("is 100 / A when assessed assets have no open findings", () => {
    expect(exposureScore(sev(), 2)).toEqual({ value: 100, grade: "A", penalty: 0, assessedAssets: 2 });
  });

  it("weights severities and averages per assessed asset; info costs nothing", () => {
    // 1 critical (20) + 2 high (20) + 3 medium (12) + 4 low (4) = 56 over 2 assets = 28 → 72
    const s = exposureScore(sev({ critical: 1, high: 2, medium: 3, low: 4, info: 50 }), 2)!;
    expect(s.penalty).toBe(56);
    expect(s.value).toBe(72);
    expect(s.grade).toBe("C");
  });

  it("floors at 0 / F", () => {
    expect(exposureScore(sev({ critical: 10 }), 1)).toMatchObject({ value: 0, grade: "F" });
  });

  it("grade boundaries", () => {
    const g = (penalty: number) => exposureScore(sev({ low: penalty }), 1)!.grade;
    expect([g(10), g(11), g(25), g(26), g(40), g(41), g(60), g(61)]).toEqual(["A", "B", "B", "C", "C", "D", "D", "F"]);
  });
});

describe("weekStart", () => {
  it("returns Monday 00:00 UTC", () => {
    expect(weekStart(new Date("2026-11-09T15:00:00Z")).toISOString()).toBe("2026-11-09T00:00:00.000Z"); // Monday
    expect(weekStart(new Date("2026-11-15T23:59:00Z")).toISOString()).toBe("2026-11-09T00:00:00.000Z"); // Sunday
    expect(weekStart(new Date("2026-11-01T01:00:00Z")).toISOString()).toBe("2026-10-26T00:00:00.000Z");
  });
});

describe("SECURITY_AREAS", () => {
  it("only claims coverage for check keys the platform actually runs", () => {
    const covered = SECURITY_AREAS.flatMap((a) => a.checks).sort();
    expect(covered).toEqual(["code.iac", "code.sast", "code.secrets", "container.image", "deps.osv", "discovery.ct", "dns.caa", "dns.email_posture", "dns.takeover", "http.compromise", "http.cors", "http.exposure", "http.security_headers", "net.exposed_services", "tls.cert_expiry", "tls.config", "web.blocklist"]);
  });
});

describe("security areas and next step", async () => {
  const { SECURITY_AREAS: AREAS, areaByKey } = await import("@/server/reports/areas");
  const { areaState, nextStep } = await import("@/server/reports/nextStep");
  type Row = import("@/server/reports/insights").AreaRow;
  const row = (o: Partial<Row> = {}): Row => ({ key: "secrets", label: "Leaked secrets", tier: "essential", why: "x", covered: true, open: 0, worst: null, bySeverity: sev(), assetsChecked: 0, lastRunAt: null, ...o });

  it("lists areas by tier (essential, important, hygiene), each with a why and unique key", () => {
    const rank = { essential: 0, important: 1, hygiene: 2 } as const;
    const tiers = AREAS.map((a) => rank[a.tier]);
    expect(tiers).toEqual([...tiers].sort((x, y) => x - y));
    expect(AREAS.every((a) => a.why.length > 20 && a.checks.length > 0)).toBe(true);
    expect(new Set(AREAS.map((a) => a.key)).size).toBe(AREAS.length);
    expect(areaByKey("secrets")?.checks).toEqual(["code.secrets"]);
    expect(areaByKey("nope")).toBeUndefined();
  });

  it("never shows a covered area that never ran as clean", () => {
    expect(areaState(row()).cls).toBe("notrun");
    expect(areaState(row({ assetsChecked: 2 }))).toEqual({ cls: "clean", text: "No open findings · 2 assets checked" });
    expect(areaState(row({ open: 3, worst: "high", bySeverity: sev({ high: 3 }) })).cls).toBe("sev-high");
    expect(areaState(row({ covered: false })).cls).toBe("off");
  });

  const summary = (o: Record<string, unknown> = {}) => ({
    windowDays: 30,
    onboarding: { hasAsset: true, hasVerifiedAsset: true, hasAssessment: true, hasCompletedAssessment: true, hasTeammate: true },
    findings: { open: sev(), openTotal: 0, untriagedCritical: 0, overdue: 0, resolvedVerifiedInWindow: 0 },
    verification: { verified: 0, partiallyVerified: 0, failed: 0, unverified: 0, notRun: 0 },
    assessments: { total: 1, completed: 1, completedWithErrors: 0, failed: 0, lastCompletedAt: null },
    ...o,
  }) as unknown as Parameters<typeof nextStep>[0];

  it("prioritises onboarding, then criticals, failed re-tests, overdue, staleness, gaps", () => {
    const base = summary();
    expect(nextStep(summary({ onboarding: { ...base.onboarding, hasVerifiedAsset: false } }), []).title).toMatch(/Verify/);
    const crit = summary({ findings: { ...base.findings, untriagedCritical: 2, overdue: 4 }, verification: { ...base.verification, failed: 1 } });
    expect(nextStep(crit, []).title).toBe("Triage 2 critical findings");
    expect(nextStep(summary({ verification: { ...base.verification, failed: 1 }, findings: { ...base.findings, overdue: 4 } }), []).title).toMatch(/did not pass/);
    expect(nextStep(summary({ findings: { ...base.findings, overdue: 1 } }), []).title).toBe("1 finding past the due date");
    expect(nextStep(summary({ assessments: { ...base.assessments, total: 0 } }), []).title).toMatch(/No assessment/);
    expect(nextStep(base, [row(), row({ key: "x", assetsChecked: 1 })]).title).toBe("1 security area never checked");
  });

  it("never says all clear when nothing is open", () => {
    const s = nextStep(summary(), [row({ assetsChecked: 1 })]);
    expect(s.tone).toBe("ok");
    expect(s.detail).toMatch(/not a guarantee/);
  });
});
