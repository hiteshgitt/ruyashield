import { randomUUID } from "node:crypto";
import { eq } from "drizzle-orm";
import { describe, expect, it } from "vitest";
import { db } from "@/server/db/client";
import { users } from "@/server/db/schema";
import { passwordSignIn, requestPasswordReset, resetPassword, signUp, verifyEmail } from "@/server/auth/password";

// Needs the migrated database and the local Mailpit (docker compose up mailpit; SMTP 1035, API 8035).
const MAILPIT = process.env.MAILPIT_API ?? "http://127.0.0.1:8035";
const run = process.env.DATABASE_URL ? describe : describe.skip;
const meta = { ip: `10.9.${Math.floor(Math.random() * 250)}.${Math.floor(Math.random() * 250)}`, userAgent: "vitest" };

async function lastLink(to: string, path: string): Promise<string> {
  for (let i = 0; i < 20; i++) {
    const list = await (await fetch(`${MAILPIT}/api/v1/search?query=${encodeURIComponent(`to:${to}`)}`)).json() as { messages: { ID: string }[] };
    if (list.messages?.length) {
      const msg = await (await fetch(`${MAILPIT}/api/v1/message/${list.messages[0].ID}`)).json() as { Text: string };
      const m = msg.Text.match(new RegExp(`${path}\\?token=([A-Za-z0-9_-]+)`));
      if (m) return m[1];
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error(`no ${path} email for ${to}`);
}

run("email + password sign-in (database + Mailpit)", () => {
  it("signs up, needs the verified email, signs in to the code step, and resets the password", async () => {
    const email = `pw-${randomUUID().slice(0, 8)}@ruya-tests.invalid`;
    await signUp({ name: "Pat", email, password: "a long and unusual phrase" }, meta);
    const u = (await db.select().from(users).where(eq(users.email, email)))[0];
    expect(u).toMatchObject({ idpIssuer: "password", emailVerifiedAt: null });

    await expect(passwordSignIn({ email, password: "a long and unusual phrase" }, meta)).rejects.toMatchObject({ code: "email_not_verified" });
    expect(await verifyEmail(await lastLink(email, "/auth/verify"))).toBe(true);
    expect(await verifyEmail("not-a-token")).toBe(false);

    await expect(passwordSignIn({ email, password: "wrong password here" }, meta)).rejects.toMatchObject({ code: "bad_credentials" });
    const pending = await passwordSignIn({ email: email.toUpperCase(), password: "a long and unusual phrase", returnTo: "https://evil.example" }, meta);
    expect(pending.length).toBeGreaterThan(20);

    await requestPasswordReset(email, meta);
    const token = await lastLink(email, "/auth/reset");
    await expect(resetPassword(token, "short", meta)).rejects.toMatchObject({ code: "weak_password" });
    await resetPassword(token, "another long new phrase", meta);
    await expect(resetPassword(token, "another long new phrase", meta)).rejects.toMatchObject({ code: "link_expired" });
    await expect(passwordSignIn({ email, password: "a long and unusual phrase" }, meta)).rejects.toMatchObject({ code: "bad_credentials" });
    await expect(passwordSignIn({ email, password: "another long new phrase" }, meta)).resolves.toBeTruthy();
  });

  it("gives the same answer for an address that already has an account", async () => {
    const email = `pw-${randomUUID().slice(0, 8)}@ruya-tests.invalid`;
    await signUp({ name: "A", email, password: "a long and unusual phrase" }, meta);
    await expect(signUp({ name: "B", email, password: "a different long phrase" }, meta)).resolves.toBeUndefined();
    expect((await db.select().from(users).where(eq(users.email, email))).length).toBe(1);
    await expect(requestPasswordReset(`nobody-${randomUUID()}@ruya-tests.invalid`, meta)).resolves.toBeUndefined();
  });
});
