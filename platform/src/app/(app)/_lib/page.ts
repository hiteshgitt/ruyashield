import { redirect } from "next/navigation";
import { getContext } from "@/server/context";

/** For pages that need a signed-in member of an active org. Redirects otherwise. */
export async function pageOrg(returnTo: string) {
  const c = await getContext();
  if (!c) redirect(`/auth/login?returnTo=${encodeURIComponent(returnTo)}`);
  if (!c.ctx) redirect("/orgs");
  return { session: c.session, ...c.ctx };
}

export const fmt = (d: Date | null | undefined) => (d ? d.toISOString().replace("T", " ").slice(0, 16) + " UTC" : "—");
