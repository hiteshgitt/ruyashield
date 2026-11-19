import { describe, expect, it } from "vitest";
import { decide } from "@/server/plans/lifecycle";

const now = new Date("2026-11-19T12:00:00Z");
const inDays = (d: number) => new Date(now.getTime() + d * 86_400_000);
const org = (o: Partial<Parameters<typeof decide>[0]> = {}) => ({
  id: "o", name: "Acme", plan: "pro", plan_source: "trial", trial_ends_at: inDays(10), trial_reminded: 0, owner_ruyalab_sub: null, ...o,
});

describe("plan lifecycle decisions", () => {
  it("ends a finished trial, and reminds 3 days then 1 day before", () => {
    expect(decide(org({ trial_ends_at: inDays(-0.01) }), undefined, now)).toEqual({ change: "trial_ended" });
    expect(decide(org({ trial_ends_at: inDays(10) }), undefined, now)).toBeNull();
    expect(decide(org({ trial_ends_at: inDays(2.5) }), undefined, now)).toEqual({ remind: 3 });
    expect(decide(org({ trial_ends_at: inDays(2.5), trial_reminded: 3 }), undefined, now)).toBeNull();
    expect(decide(org({ trial_ends_at: inDays(0.5), trial_reminded: 3 }), undefined, now)).toEqual({ remind: 1 });
    expect(decide(org({ trial_ends_at: inDays(0.5), trial_reminded: 1 }), undefined, now)).toBeNull();
  });

  it("Ruya Lab Pro upgrades free and trial organizations, never touches manual Pro, and ends only its own", () => {
    expect(decide(org({ plan: "free", plan_source: null }), "pro", now)).toEqual({ change: "to_ruyalab" });
    expect(decide(org(), "pro", now)).toEqual({ change: "to_ruyalab" });
    expect(decide(org({ plan_source: "manual" }), "pro", now)).toBeNull();
    expect(decide(org({ plan_source: "manual" }), "free", now)).toBeNull();
    expect(decide(org({ plan_source: "ruyalab" }), "pro", now)).toBeNull();
    expect(decide(org({ plan_source: "ruyalab" }), "free", now)).toEqual({ change: "ruyalab_ended" });
    // No answer from Ruya Lab: nothing changes on its account.
    expect(decide(org({ plan_source: "ruyalab" }), undefined, now)).toBeNull();
  });
});
