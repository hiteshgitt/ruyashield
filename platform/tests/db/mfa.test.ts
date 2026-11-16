import { randomUUID } from "node:crypto";
import { eq } from "drizzle-orm";
import { beforeAll, describe, expect, it } from "vitest";
import { db } from "@/server/db/client";
import { mfaRecoveryCodes, pendingLogins, sessions, userMfa, users } from "@/server/db/schema";
import { open } from "@/server/attacks/secretbox";
import { readSession } from "@/server/auth/session";
import { codeAt, stepAt } from "@/server/auth/totp";
import { challengeFor, completeMfaLogin, createPendingLogin, dismissReveal, issueRecoveryReveal, PENDING_MAX_ATTEMPTS, pendingReveal, remainingRecoveryCodes, resetMfa, stepUp } from "@/server/auth/mfa";

// Needs a migrated database reachable as the runtime role. Skipped otherwise.
const run = process.env.DATABASE_URL ? describe : describe.skip;
const meta = { ip: "203.0.113.9", userAgent: "vitest" };

async function newUser() {
  const email = `mfa-${randomUUID()}@ruya-tests.invalid`;
  const [u] = await db.insert(users).values({ email, displayName: "MFA", idpIssuer: "https://accounts.google.com", idpSubject: email }).returning();
  return u;
}
const pending = (userId: string) => createPendingLogin({ userId, amr: [], issuer: "https://accounts.google.com", returnTo: "/dashboard" });
const secretOf = async (userId: string) => open((await db.select().from(userMfa).where(eq(userMfa.userId, userId)))[0].secret, `user_mfa:${userId}`);
// A code for a later step than any used so far, so tests never trip the replay guard.
const freshCode = (secret: string, ahead = 0) => codeAt(secret, stepAt(Date.now()) + ahead);

run("built-in MFA after Google sign-in (database)", () => {
  beforeAll(() => { process.env.RUYA_SECRETS_KEY ??= "test-secrets-key-0123456789abcdef-0123456789"; });

  it("enrolls on first sign-in, creates an MFA session and hands out recovery codes once", async () => {
    const u = await newUser();
    const token = await pending(u.id);
    const c1 = await challengeFor(token);
    expect(c1?.kind).toBe("enroll");
    // Reloading the page keeps the same secret.
    const c2 = await challengeFor(token);
    expect(c2 && c2.kind === "enroll" && c1 && c1.kind === "enroll" && c2.secret === c1.secret).toBe(true);
    expect(c1 && c1.kind === "enroll" && c1.qrSvg.startsWith("<svg")).toBe(true);
    // Stored sealed, never in plain text.
    const row = (await db.select().from(userMfa).where(eq(userMfa.userId, u.id)))[0];
    expect(row.secret).not.toContain((c1 as { secret: string }).secret);

    const r = await completeMfaLogin(token, freshCode(await secretOf(u.id)), meta);
    expect(r).toMatchObject({ returnTo: "/dashboard", enrolled: true });
    // The codes wait on the server (sealed) until shown, so a page reload cannot lose them.
    const reveal = await pendingReveal(u.id);
    expect(reveal?.codes).toHaveLength(10);
    expect(reveal?.codes[0]).toMatch(/^[A-Z2-7]{5}-[A-Z2-7]{5}$/);
    expect(await pendingReveal(u.id)).toEqual(reveal);
    expect(await dismissReveal(u.id)).toBe("/dashboard");
    expect(await pendingReveal(u.id)).toBeNull();
    const recoveryCodes = reveal!.codes;
    const s = await readSession(r.token);
    expect(s).toMatchObject({ userId: u.id, mfa: true });
    expect(s!.amr).toEqual(expect.arrayContaining(["otp", "mfa"]));
    // The pending login is single-use.
    await expect(completeMfaLogin(token, "000000", meta)).rejects.toMatchObject({ code: "mfa_login_expired" });
    // Only hashes are stored.
    const hashes = await db.select().from(mfaRecoveryCodes).where(eq(mfaRecoveryCodes.userId, u.id));
    expect(JSON.stringify(hashes)).not.toContain(recoveryCodes[0].replace("-", ""));
  });

  it("asks enrolled users for a code, refuses replays, and accepts each recovery code once", async () => {
    const u = await newUser();
    const first = await completeMfaLogin(await pending(u.id), "x", meta).catch(() => null);
    expect(first).toBeNull(); // nothing to verify against before the page created a secret
    const t0 = await pending(u.id);
    await challengeFor(t0);
    const secret = await secretOf(u.id);
    await completeMfaLogin(t0, freshCode(secret), meta);
    const recoveryCodes = (await pendingReveal(u.id))!.codes;

    const t1 = await pending(u.id);
    expect((await challengeFor(t1))?.kind).toBe("verify");
    // The code just used cannot be used again.
    await expect(completeMfaLogin(t1, freshCode(secret), meta)).rejects.toMatchObject({ code: "mfa_code_invalid" });
    expect((await completeMfaLogin(t1, freshCode(secret, 1), meta)).enrolled).toBe(false);

    const t2 = await pending(u.id);
    const viaRecovery = await completeMfaLogin(t2, recoveryCodes![3].toLowerCase(), meta);
    expect(viaRecovery.usedRecovery).toBe(true);
    expect(await remainingRecoveryCodes(u.id)).toBe(9);
    await expect(completeMfaLogin(await pending(u.id), recoveryCodes![3], meta)).rejects.toMatchObject({ code: "mfa_code_invalid" });
  });

  it("operator tools: new recovery codes replace the old ones; reset forces re-enrollment and signs out", async () => {
    const u = await newUser();
    const t = await pending(u.id);
    await challengeFor(t);
    const r = await completeMfaLogin(t, freshCode(await secretOf(u.id)), meta);
    const first = (await pendingReveal(u.id))!.codes;
    await issueRecoveryReveal(u.id);
    const second = (await pendingReveal(u.id))!.codes;
    expect(second).not.toEqual(first);
    await expect(completeMfaLogin(await pending(u.id), first[0], meta)).rejects.toMatchObject({ code: "mfa_code_invalid" });

    await resetMfa(u.id);
    expect(await readSession(r.token)).toBeNull();
    expect((await challengeFor(await pending(u.id)))?.kind).toBe("enroll");
  });

  it("ends a pending login after too many wrong codes", async () => {
    const u = await newUser();
    const t = await pending(u.id);
    await challengeFor(t);
    for (let i = 1; i < PENDING_MAX_ATTEMPTS; i++) {
      await expect(completeMfaLogin(t, "000000", meta)).rejects.toMatchObject({ code: "mfa_code_invalid" });
    }
    await expect(completeMfaLogin(t, "000000", meta)).rejects.toMatchObject({ code: "mfa_login_expired" });
    expect(await db.select().from(pendingLogins).where(eq(pendingLogins.userId, u.id))).toHaveLength(0);
  });

  it("step-up renews the session's authentication time", async () => {
    const u = await newUser();
    const t = await pending(u.id);
    await challengeFor(t);
    const secret = await secretOf(u.id);
    const r = await completeMfaLogin(t, freshCode(secret), meta);
    await db.update(sessions).set({ authTime: new Date(Date.now() - 60 * 60_000) }).where(eq(sessions.userId, u.id));
    const old = (await readSession(r.token))!;
    await expect(stepUp(old, "000000", meta)).rejects.toMatchObject({ code: "mfa_code_invalid" });
    await stepUp(old, freshCode(secret, 1), meta);
    const renewed = (await readSession(r.token))!;
    expect(Date.now() - renewed.authTime.getTime()).toBeLessThan(10_000);
  });
});
