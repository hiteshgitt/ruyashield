import { createHash } from "node:crypto";
import { and, desc, eq } from "drizzle-orm";
import { z } from "zod";
import { withOrg, isUuid } from "../db/client";
import { reports } from "../db/schema";
import { audit } from "../audit/audit";
import { AppError, notFound } from "../errors";
import { authorize, type Principal } from "../policy/policy";
import { grantFor } from "../policy/matrix";
import { richPdf } from "../richpdf";
import { securitySummary, type Ctx } from "./summary";
import { reportBlocks, reportCsvDetailed, reportTitle } from "./render";
import { reportDetail, resolveOptions, type ResolvedOptions } from "./content";

const userActor = (p: Principal) => ({ type: "user" as const, id: p.userId, ip: p.ip });
const Input = z.object({ format: z.enum(["csv", "pdf"]), clientGroupId: z.string().uuid().nullish() });

/** Generates a CSV or PDF summary and stores it immutably with its SHA-256 (RS-RPT-002). */
export async function generateReport(c: Ctx & { org: { name?: string } }, input: unknown, now = new Date()) {
  const v = Input.safeParse(input);
  if (!v.success) throw new AppError(422, "validation_failed", "Choose CSV or PDF, and optionally one client group.");
  let o: ResolvedOptions;
  try {
    o = resolveOptions((input as { options?: unknown })?.options);
  } catch {
    throw new AppError(422, "validation_failed", "Choose a report type and at least one section.");
  }
  const s = await securitySummary(c, { clientGroupId: v.data.clientGroupId ?? null, action: "report.generate" }, now);
  const orgName = c.org.name ?? "Organization";
  const detail = await reportDetail(c, o, s.scope.clientGroupId);
  const content = v.data.format === "csv"
    ? Buffer.from(reportCsvDetailed(s, detail, o, orgName), "utf8")
    : richPdf(reportBlocks(s, detail, o, orgName), `${reportTitle(o, orgName)} - generated ${now.toISOString().slice(0, 16).replace("T", " ")} UTC - not a certification`);
  const sha256 = createHash("sha256").update(content).digest("hex");
  // What the report contained, kept beside the file so the report page can describe it without opening it.
  const snapshot = {
    openTotal: s.findings.openTotal, open: s.findings.open, overdue: s.findings.overdue, fixedVerified: s.findings.resolvedVerifiedInWindow,
    assets: s.assets.total, verifiedAssets: s.assets.verified, assessments: s.assessments.total,
    failedVerifications: s.failedVerifications.length, incomplete: s.incompleteAssessments.length, acceptedRisks: s.acceptedRisks.length,
    findingsListed: detail.findings.length, findingsTotal: detail.findingsTotal,
    attacks: detail.attacks && detail.attacks.coverage !== "none" ? detail.attacks.total : null,
  };
  return withOrg(c.org.id, async (tx) => {
    const [row] = await tx.insert(reports).values({
      orgId: c.org.id, createdBy: c.principal.userId, format: v.data.format, clientGroupId: s.scope.clientGroupId,
      params: { windowDays: s.windowDays, restrictedToGroups: s.scope.restrictedToGroups, title: reportTitle(o, orgName), preset: o.preset, sections: o.sections, minSeverity: o.minSeverity, includeFixes: o.includeFixes, snapshot },
      sha256, sizeBytes: content.length, content,
    }).returning({ id: reports.id, createdAt: reports.createdAt });
    await audit(tx, {
      actor: userActor(c.principal), action: "report.generated", target: { type: "report", id: row.id }, requestId: c.principal.requestId,
      details: { format: v.data.format, clientGroupId: s.scope.clientGroupId, sha256, sizeBytes: content.length, preset: o.preset, sections: o.sections },
    });
    return { id: row.id, format: v.data.format, sha256, sizeBytes: content.length, createdAt: row.createdAt };
  });
}

/** Restricted members see only reports they generated: someone else's report may cover groups they can't see. */
function ownOnly(p: Principal) { return grantFor(p.role, "report.generate") === "S" && p.restricted; }

export async function listReports(c: Ctx) {
  const p = c.principal;
  await authorize(p, "report.generate", { type: "org", id: c.org.id, ownerId: p.userId }, c.org);
  return withOrg(c.org.id, (tx) => tx.select({
    id: reports.id, format: reports.format, clientGroupId: reports.clientGroupId, sha256: reports.sha256,
    sizeBytes: reports.sizeBytes, createdBy: reports.createdBy, createdAt: reports.createdAt, params: reports.params,
  }).from(reports).where(ownOnly(p) ? eq(reports.createdBy, p.userId) : undefined).orderBy(desc(reports.createdAt)).limit(50));
}

export async function getReport(c: Ctx, id: string) {
  const p = c.principal;
  if (!isUuid(id)) throw notFound();
  return withOrg(c.org.id, async (tx) => {
    const [r] = await tx.select().from(reports).where(and(eq(reports.id, id), ownOnly(p) ? eq(reports.createdBy, p.userId) : undefined)).limit(1);
    if (!r) throw notFound();
    await authorize(p, "report.generate", { type: "report", id, ownerId: r.createdBy }, c.org);
    await audit(tx, { actor: userActor(p), action: "report.downloaded", target: { type: "report", id }, requestId: p.requestId, details: { sha256: r.sha256 } });
    return r;
  });
}

/** A report's description for its page (no file content, no download audit). */
export async function getReportInfo(c: Ctx, id: string) {
  const p = c.principal;
  if (!isUuid(id)) throw notFound();
  await authorize(p, "report.generate", { type: "org", id: c.org.id, ownerId: p.userId }, c.org);
  return withOrg(c.org.id, async (tx) => {
    const [r] = await tx.select({
      id: reports.id, format: reports.format, clientGroupId: reports.clientGroupId, sha256: reports.sha256, sizeBytes: reports.sizeBytes,
      createdBy: reports.createdBy, createdAt: reports.createdAt, params: reports.params,
    }).from(reports).where(and(eq(reports.id, id), ownOnly(p) ? eq(reports.createdBy, p.userId) : undefined)).limit(1);
    if (!r) throw notFound();
    return r;
  });
}
