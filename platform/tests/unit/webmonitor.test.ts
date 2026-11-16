import { describe, expect, it } from "vitest";
import { HANDOFF_TOLERANCE_MS, provisionalAdapter, signHandoff, verifyHandoffSignature } from "@/server/webmonitor/adapter";

const key = "k".repeat(32);
const now = 1_800_000_000_000;
const ts = String(now / 1000);
const body = JSON.stringify({ nonce: "n".repeat(16) });

describe("WebMonitor handoff signature (TC-WMON-002)", () => {
  it("accepts a correctly signed, fresh handoff", () => {
    expect(verifyHandoffSignature({ timestamp: ts, signature: signHandoff(ts, body, key) }, body, key, now)).toEqual({ ok: true });
  });

  it("rejects a bad signature, a changed body and a missing header", () => {
    const sig = signHandoff(ts, body, key);
    expect(verifyHandoffSignature({ timestamp: ts, signature: signHandoff(ts, body, "x".repeat(32)) }, body, key, now)).toMatchObject({ ok: false, status: 401, code: "bad_signature" });
    expect(verifyHandoffSignature({ timestamp: ts, signature: sig }, body + " ", key, now)).toMatchObject({ code: "bad_signature" });
    expect(verifyHandoffSignature({ timestamp: ts, signature: null }, body, key, now)).toMatchObject({ code: "bad_signature" });
    expect(verifyHandoffSignature({ timestamp: "abc", signature: sig }, body, key, now)).toMatchObject({ code: "bad_signature" });
  });

  it("rejects a stale or future timestamp", () => {
    const old = String((now - HANDOFF_TOLERANCE_MS - 1000) / 1000);
    const future = String((now + HANDOFF_TOLERANCE_MS + 1000) / 1000);
    expect(verifyHandoffSignature({ timestamp: old, signature: signHandoff(old, body, key) }, body, key, now)).toMatchObject({ status: 401, code: "stale_timestamp" });
    expect(verifyHandoffSignature({ timestamp: future, signature: signHandoff(future, body, key) }, body, key, now)).toMatchObject({ code: "stale_timestamp" });
  });

  it("is disabled without a configured secret", () => {
    expect(verifyHandoffSignature({ timestamp: ts, signature: "sha256=00" }, body, null, now)).toMatchObject({ ok: false, status: 503, code: "handoffs_disabled" });
  });

  it("does not send anything outbound while no contract exists (D-14)", async () => {
    await expect(provisionalAdapter.publishResult({ externalRef: "r", assessmentStatus: null, severityCounts: null, fixproofStatus: null, link: "x" }))
      .resolves.toEqual({ sent: false, reason: "no_contract" });
  });
});
