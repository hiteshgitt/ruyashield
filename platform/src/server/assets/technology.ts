import { and, desc, eq } from "drizzle-orm";
import type { Tx } from "../db/client";
import { assessments, checkRuns } from "../db/schema";
import type { Technology } from "../assessments/technology";

/** The stack the latest successful technology check saw on this asset, or null when it has not run. */
export async function assetTechnologies(tx: Tx, assetId: string): Promise<{ technologies: Technology[]; seenAt: Date | null } | null> {
  const rows = await tx.select({ evidence: checkRuns.evidence, finishedAt: checkRuns.finishedAt })
    .from(checkRuns).innerJoin(assessments, eq(assessments.id, checkRuns.assessmentId))
    .where(and(eq(assessments.assetId, assetId), eq(checkRuns.checkId, "web.technology@1"), eq(checkRuns.status, "ok")))
    .orderBy(desc(checkRuns.finishedAt)).limit(1);
  const ev = rows[0]?.evidence as { technologies?: Technology[] } | null | undefined;
  if (!rows[0] || !Array.isArray(ev?.technologies)) return null;
  return { technologies: ev.technologies, seenAt: rows[0].finishedAt };
}
