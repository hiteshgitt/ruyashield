import { refresh } from "next/cache";
import { unstable_rethrow } from "next/navigation";
import { isAppError } from "@/server/errors";
import { log } from "@/server/log";
import { messageFor } from "./messages";

export type ActionState = { ok?: string; error?: string; stepUp?: boolean; tone?: "ok" | "warn" | "bad"; secret?: string } | null;

/** Wraps a server action body: maps AppErrors to friendly state and refreshes the router on success. */
export async function run(fn: () => Promise<ActionState | void>): Promise<ActionState> {
  try {
    const r = await fn();
    refresh();
    return r ?? { ok: "Saved." };
  } catch (e) {
    unstable_rethrow(e);
    if (isAppError(e)) return { error: messageFor(e.code, e.message), stepUp: e.code === "step_up_required" || e.code === "mfa_required" };
    log.error("action failed", { err: e instanceof Error ? e.message : String(e) });
    return { error: messageFor("internal") };
  }
}

export const str = (f: FormData, k: string) => {
  const v = f.get(k);
  return typeof v === "string" ? v : "";
};
