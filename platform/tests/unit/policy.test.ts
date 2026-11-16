import { describe, expect, it } from "vitest";
import { decide, STEP_UP_MAX_AGE_MS, type Principal } from "@/server/policy/policy";
import { ACTIONS, grantFor, ROLES, type Role } from "@/server/policy/matrix";

const now = new Date("2026-10-29T12:00:00Z");
const p = (role: Role, extra: Partial<Principal> = {}): Principal => ({
  userId: "u1", orgId: "o1", role, restricted: false, clientGroupIds: [], mfa: true, authTime: now, ...extra,
});
const open = { killScanning: false, killAi: false, plan: "pro" };

describe("decide", () => {
  it("denies by default for every N grant", () => {
    for (const role of ROLES) for (const a of ACTIONS) {
      if (grantFor(role, a) !== "N") continue;
      expect(decide(p(role), a, {}, open, now)).toMatchObject({ allow: false, status: 403, code: "forbidden" });
    }
  });

  it("never lets a human role perform system-only actions", () => {
    for (const role of ROLES.filter((r) => r !== "service")) {
      expect(decide(p(role), "verification.set_result", {}, open, now).allow).toBe(false);
      expect(decide(p(role), "remediation.open_pr", {}, open, now).allow).toBe(false);
    }
    expect(decide(p("service"), "verification.set_result", {}, open, now).allow).toBe(false); // Sys is not a user grant
  });

  it("requires MFA for privileged roles", () => {
    for (const role of ["org_admin", "security_lead", "approver"] as const) {
      expect(decide(p(role, { mfa: false }), "asset.view", {}, open, now)).toMatchObject({ allow: false, status: 401, code: "step_up_required" });
    }
    expect(decide(p("analyst", { mfa: false }), "asset.view", {}, open, now).allow).toBe(true);
  });

  it("limits restricted members to their client groups on S grants", () => {
    const r = p("analyst", { restricted: true, clientGroupIds: ["g1"] });
    expect(decide(r, "asset.edit", { clientGroupId: "g1" }, open, now).allow).toBe(true);
    expect(decide(r, "asset.edit", { clientGroupId: "g2" }, open, now)).toMatchObject({ allow: false, code: "forbidden" });
    expect(decide(r, "asset.edit", { clientGroupId: null }, open, now).allow).toBe(false);
    expect(decide(r, "asset.edit", { clientGroupId: "g2", ownerId: "u1" }, open, now).allow).toBe(true);
    expect(decide(p("analyst"), "asset.edit", { clientGroupId: "g2" }, open, now).allow).toBe(true);
  });

  it("forbids approving your own request", () => {
    expect(decide(p("approver"), "approval.decide", { requesterId: "u1" }, open, now)).toMatchObject({ allow: false, code: "self_approval" });
    expect(decide(p("approver"), "approval.decide", { requesterId: "u2" }, open, now).allow).toBe(true);
  });

  it("stops scanning and AI actions when the kill switches are engaged", () => {
    const killed = { killScanning: true, killAi: true, plan: "pro" };
    for (const a of ["assessment.launch", "verification.request", "ai.request"] as const) {
      expect(decide(p("org_admin"), a, {}, killed, now)).toMatchObject({ allow: false, status: 423, code: "kill_switch_engaged" });
    }
    expect(decide(p("org_admin"), "asset.view", {}, killed, now).allow).toBe(true);
    expect(decide(p("org_admin"), "killswitch.manage", {}, killed, now).allow).toBe(true); // can always release
  });

  it("requires a fresh sign-in for step-up actions", () => {
    const stale = new Date(now.getTime() - STEP_UP_MAX_AGE_MS - 1000);
    expect(decide(p("org_admin", { authTime: stale }), "killswitch.manage", {}, open, now)).toMatchObject({ allow: false, code: "step_up_required" });
    expect(decide(p("org_admin"), "killswitch.manage", {}, open, now).allow).toBe(true);
  });

  it("flags A grants as needing a second person", () => {
    expect(decide(p("org_admin"), "scope.enable_a2", {}, open, now)).toEqual({ allow: true, needsSecondPerson: true });
    expect(decide(p("org_admin"), "asset.view", {}, open, now)).toEqual({ allow: true, needsSecondPerson: false });
  });
});

describe("plans: Pro-only actions", () => {
  const admin = { userId: "u1", orgId: "o1", role: "org_admin" as const, restricted: false, clientGroupIds: [], mfa: true, authTime: new Date() };
  const free = { killScanning: false, killAi: false, plan: "free" };
  const pro = { killScanning: false, killAi: false, plan: "pro" };
  it.each(["report.generate", "evidence.download_raw", "audit.export"] as const)("%s needs Pro", (action) => {
    expect(decide(admin, action, { type: "org", ownerId: "u1" }, free)).toMatchObject({ allow: false, status: 402, code: "pro_required" });
    expect(decide(admin, action, { type: "org", ownerId: "u1" }, pro).allow).toBe(true);
  });
  it("leaves scanning, findings and the dashboard open on Free", () => {
    for (const action of ["finding.view", "dashboard.view", "assessment.launch", "asset.edit"] as const) {
      expect(decide(admin, action, { type: "org", ownerId: "u1" }, free).allow).toBe(true);
    }
  });
});
