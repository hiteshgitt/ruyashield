import { randomUUID } from "node:crypto";
import { eq } from "drizzle-orm";
import { beforeAll, describe, expect, it } from "vitest";
import { db } from "@/server/db/client";
import { memberships, sessions, userMfa, users } from "@/server/db/schema";
import { open } from "@/server/attacks/secretbox";
import { readSession } from "@/server/auth/session";
import { codeAt, stepAt } from "@/server/auth/totp";
import { challengeFor, completeMfaLogin } from "@/server/auth/mfa";
import { passwordSignIn, signUp, verifyEmail } from "@/server/auth/password";
import { changePassword, deleteAccount, deviceLabel, getAccount, resetAuthenticator, signOutOtherSessions, signOutSession, soleAdminOrgs, updateProfile } from "@/server/account/account";
import { createOrg, listUserOrgs } from "@/server/orgs/orgs";
import { withOrg } from "@/server/db/client";

// Needs the migrated database and the local Mailpit (sign-up sends a verification email).
const MAILPIT = process.env.MAILPIT_API ?? "http://127.0.0.1:8035";
const run = process.env.DATABASE_URL ? describe : describe.skip;
const meta = { ip: "10.8.0.1", userAgent: "Mozilla/5.0 (Windows NT 10.0) AppleWebKit Chrome/140.0 Safari" };
const secretOf = async (userId: string) => open((await db.select().from(userMfa).where(eq(userMfa.userId, userId)))[0].secret, `user_mfa:${userId}`);
const code = (secret: string, ahead = 0) => codeAt(secret, stepAt(Date.now()) + ahead);

async function verifyLink(to: string) {
  for (let i = 0; i < 20; i++) {
    const list = await (await fetch(`${MAILPIT}/api/v1/search?query=${encodeURIComponent(`to:${to}`)}`)).json() as { messages: { ID: string }[] };
    if (list.messages?.length) {
      const m = await (await fetch(`${MAILPIT}/api/v1/message/${list.messages[0].ID}`)).json() as { Text: string };
      const t = m.Text.match(/\/auth\/verify\?token=([A-Za-z0-9_-]+)/);
      if (t) return t[1];
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error("no verification email");
}

/** A verified password account, enrolled in MFA, with two signed-in sessions. */
async function signedInTwice() {
  const email = `acct-${randomUUID().slice(0, 8)}@ruya-tests.invalid`;
  // Each account signs up from its own address: the email rate limit is per IP.
  await signUp({ name: "Acct", email, password: "a long and unusual phrase" }, { ...meta, ip: `10.${Math.floor(Math.random() * 250)}.${Math.floor(Math.random() * 250)}.${Math.floor(Math.random() * 250)}` });
  await verifyEmail(await verifyLink(email));
  const login = async () => {
    const pending = await passwordSignIn({ email, password: "a long and unusual phrase" }, meta);
    const ch = await challengeFor(pending);
    const u = (await db.select().from(users).where(eq(users.email, email)))[0];
    const secret = ch?.kind === "enroll" ? ch.secret : await secretOf(u.id);
    const r = await completeMfaLogin(pending, code(secret, ch?.kind === "enroll" ? 0 : 1), meta);
    return { token: r.token, userId: u.id, secret };
  };
  const a = await login();
  await new Promise((r) => setTimeout(r, 50));
  const b = await login();
  // Each code works once; forget the codes the two sign-ins used, as if the next 30-second step had started.
  await db.update(userMfa).set({ lastStep: 0 }).where(eq(userMfa.userId, a.userId));
  return { email, a, b, s: (await readSession(a.token))!, secret: a.secret };
}

run("account settings (database + Mailpit)", () => {
  beforeAll(() => { process.env.RUYA_SECRETS_KEY ??= "test-secrets-key-0123456789abcdef-0123456789"; });

  it("labels devices", () => {
    expect(deviceLabel(meta.userAgent)).toBe("Chrome on Windows");
    expect(deviceLabel(null)).toBe("Unknown device");
  });

  it("shows the account, renames, changes the password and signs other devices out", async () => {
    const { email, a, b, s } = await signedInTwice();
    const acct = await getAccount(s);
    expect(acct).toMatchObject({ email, method: "password", mfaEnabled: true });
    expect(acct.sessions.filter((x) => x.current)).toHaveLength(1);
    expect(acct.sessions.length).toBeGreaterThanOrEqual(2);

    await updateProfile(s, { displayName: "Renamed" }, meta);
    expect((await db.select().from(users).where(eq(users.id, a.userId)))[0].displayName).toBe("Renamed");
    await expect(updateProfile(s, { displayName: "" }, meta)).rejects.toMatchObject({ status: 422 });

    await expect(changePassword(s, { current: "wrong one entirely", next: "another long new phrase" }, meta)).rejects.toMatchObject({ code: "bad_credentials" });
    await changePassword(s, { current: "a long and unusual phrase", next: "another long new phrase" }, meta);
    expect(await readSession(a.token)).not.toBeNull();
    expect(await readSession(b.token)).toBeNull();
    await expect(passwordSignIn({ email, password: "another long new phrase" }, meta)).resolves.toBeTruthy();
  });

  it("signs out one device or all others, but not this one", async () => {
    const { a, b, s } = await signedInTwice();
    const other = (await getAccount(s)).sessions.find((x) => !x.current)!;
    await expect(signOutSession(s, (await getAccount(s)).sessions.find((x) => x.current)!.key, meta)).rejects.toMatchObject({ status: 409 });
    await signOutSession(s, other.key, meta);
    expect(await readSession(b.token)).toBeNull();
    expect(await signOutOtherSessions(s, meta)).toBe(0);
    expect(await readSession(a.token)).not.toBeNull();
  });

  it("resets the authenticator only with a valid code, and signs out everywhere", async () => {
    const { a, s, secret } = await signedInTwice();
    await expect(resetAuthenticator(s, "000000", meta)).rejects.toMatchObject({ code: "mfa_code_invalid" });
    await resetAuthenticator(s, code(secret, 0), meta);
    expect(await readSession(a.token)).toBeNull();
    expect((await db.select().from(userMfa).where(eq(userMfa.userId, a.userId))).length).toBe(0);
  });

  it("blocks deletion while the only org admin; otherwise leaves orgs and anonymises the account", async () => {
    const { email, a, s, secret } = await signedInTwice();
    const org = await createOrg(s, { name: `Acct ${randomUUID().slice(0, 6)}` });
    expect((await soleAdminOrgs(a.userId)).map((o) => o.id)).toContain(org.id);
    await expect(deleteAccount(s, { confirm: "someone@else.invalid", code: code(secret, 0) }, meta)).rejects.toMatchObject({ status: 422 });
    await expect(deleteAccount(s, { confirm: email, code: code(secret, 0) }, meta)).rejects.toMatchObject({ code: "last_admin" });

    // A second admin joins, so this person may leave.
    const other = (await db.insert(users).values({ email: `adm-${randomUUID()}@ruya-tests.invalid`, displayName: "Admin 2", idpIssuer: "test", idpSubject: randomUUID() }).returning())[0];
    await withOrg(org.id, (tx) => tx.insert(memberships).values({ orgId: org.id, userId: other.id, role: "org_admin" }));
    await deleteAccount(s, { confirm: email.toUpperCase(), code: code(secret, 1) }, meta);
    const u = (await db.select().from(users).where(eq(users.id, a.userId)))[0];
    expect(u.email).toMatch(/@deleted\.invalid$/);
    expect(u.disabledAt).not.toBeNull();
    expect(await listUserOrgs(a.userId)).toHaveLength(0);
    expect(await readSession(a.token)).toBeNull();
    expect((await db.select().from(sessions).where(eq(sessions.userId, a.userId))).every((x) => x.revokedAt)).toBe(true);
    await expect(passwordSignIn({ email, password: "a long and unusual phrase" }, meta)).rejects.toMatchObject({ code: "bad_credentials" });
  });
});
