"use server";
import { cookies } from "next/headers";
import { redirect, unstable_rethrow } from "next/navigation";
import { requestMeta } from "@/server/context";
import { isAppError } from "@/server/errors";
import { log } from "@/server/log";
import { PENDING_COOKIE, PENDING_LOGIN_TTL_MS } from "@/server/auth/mfa";
import { secureCookies } from "@/server/auth/session";
import { passwordSignIn, requestPasswordReset, resendVerification, resetPassword, signUp } from "@/server/auth/password";

// Email + password forms on /auth/signin, /auth/forgot and /auth/reset. Each one ends in a redirect; messages
// travel as ?error=<code>&msg=... or a status flag, so the pages stay server-rendered and work without JS.

const str = (f: FormData, k: string) => { const v = f.get(k); return typeof v === "string" ? v : ""; };

function back(path: string, params: Record<string, string>): never {
  redirect(`${path}?${new URLSearchParams(params)}`);
}

async function attempt(path: string, keep: Record<string, string>, fn: () => Promise<void>) {
  try {
    await fn();
  } catch (e) {
    unstable_rethrow(e);
    if (isAppError(e)) back(path, { ...keep, error: e.code, msg: e.message.slice(0, 200) });
    log.error("auth form failed", { err: e instanceof Error ? e.message : String(e) });
    back(path, { ...keep, error: "internal", msg: "Something went wrong. Please try again." });
  }
}

export async function passwordSignInAction(f: FormData) {
  const email = str(f, "email"), returnTo = str(f, "returnTo") || "/";
  let pending = "";
  await attempt("/auth/signin", { email, returnTo }, async () => {
    pending = await passwordSignIn({ email, password: str(f, "password"), returnTo }, await requestMeta());
  });
  (await cookies()).set(PENDING_COOKIE, pending, { httpOnly: true, sameSite: "lax", secure: secureCookies(), path: "/auth", maxAge: PENDING_LOGIN_TTL_MS / 1000 });
  redirect("/auth/mfa");
}

export async function signUpAction(f: FormData) {
  const email = str(f, "email"), name = str(f, "name");
  if (str(f, "password") !== str(f, "confirm")) back("/auth/signin", { new: "1", email, name, error: "password_mismatch", msg: "The two passwords do not match." });
  await attempt("/auth/signin", { new: "1", email, name }, async () => signUp({ name, email, password: str(f, "password") }, await requestMeta()));
  back("/auth/signin", { sent: "verify", email });
}

export async function resendVerificationAction(f: FormData) {
  const email = str(f, "email");
  await attempt("/auth/signin", { email }, async () => resendVerification(email, await requestMeta()));
  back("/auth/signin", { sent: "verify", email });
}

export async function forgotPasswordAction(f: FormData) {
  const email = str(f, "email");
  await attempt("/auth/forgot", { email }, async () => requestPasswordReset(email, await requestMeta()));
  back("/auth/forgot", { sent: "1", email });
}

export async function resetPasswordAction(f: FormData) {
  const token = str(f, "token");
  if (str(f, "password") !== str(f, "confirm")) back("/auth/reset", { token, error: "password_mismatch", msg: "The two passwords do not match." });
  await attempt("/auth/reset", { token }, async () => resetPassword(token, str(f, "password"), await requestMeta()));
  back("/auth/signin", { reset: "1" });
}
