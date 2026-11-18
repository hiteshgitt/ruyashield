"use server";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { revalidatePath } from "next/cache";
import { getSession, requestMeta, requireOrgContext, requireSession } from "@/server/context";
import { revokeSessionByToken, secureCookies, sessionCookieName, setActiveOrg } from "@/server/auth/session";
import { auditLogout } from "@/server/auth/login";
import { loadPrincipal } from "@/server/principal";
import * as orgSvc from "@/server/orgs/orgs";
import * as assetSvc from "@/server/assets/assets";
import * as suggestionSvc from "@/server/assets/suggestions";
import * as assessmentSvc from "@/server/assessments/assessments";
import * as findingSvc from "@/server/findings/findings";
import { requestVerification } from "@/server/verification/verification";
import * as aiSvc from "@/server/ai/gateway";
import * as planSvc from "@/server/remediation/plans";
import * as approvalSvc from "@/server/remediation/approvals";
import * as integrationSvc from "@/server/remediation/integrations";
import * as attackSvc from "@/server/attacks/attacks";
import { verifyOrgAuditChain } from "@/server/audit/view";
import * as referralSvc from "@/server/webmonitor/referrals";
import { generateReport } from "@/server/reports/reports";
import * as notifySvc from "@/server/notifications/notifications";
import * as lifecycleSvc from "@/server/orgs/lifecycle";
import * as tokenSvc from "@/server/tokens/tokens";
import { createWebMonitorToken } from "@/server/webmonitor/watch";
import * as breakGlassSvc from "@/server/operator/breakglass";
import * as orgPlanSvc from "@/server/operator/plans";
import * as accountSvc from "@/server/account/account";
import { allowPrivateFromEnv } from "@/server/net/egress";
import { AppError } from "@/server/errors";
import { run, str, type ActionState } from "./_lib/action";

// Every action re-loads session and principal from the DB (RS-IAM-004); the services authorize each call.

export async function logoutAction() {
  const jar = await cookies();
  const name = sessionCookieName();
  const token = jar.get(name)?.value;
  const s = await getSession();
  if (token) await revokeSessionByToken(token);
  if (s) await auditLogout(s.userId, (await requestMeta()).ip);
  jar.set(name, "", { maxAge: 0, path: "/", secure: secureCookies(), httpOnly: true, sameSite: "lax" });
  redirect("/auth/signin?signedOut=1");
}

export async function selectOrgAction(f: FormData) {
  const s = await requireSession();
  const orgId = str(f, "orgId");
  if (!(await loadPrincipal(s, orgId, await requestMeta()))) throw new AppError(404, "not_found");
  await setActiveOrg(s.idHash, orgId);
  revalidatePath("/", "layout"); // the shell (org switcher, nav) lives in the layout; drop the client's cached copy
  redirect("/assets");
}

export async function createOrgAction(_: ActionState, f: FormData): Promise<ActionState> {
  let orgId: string | null = null;
  const r = await run(async () => {
    const s = await requireSession();
    const o = await orgSvc.createOrg(s, { name: str(f, "name"), slug: str(f, "slug") || undefined }, await requestMeta());
    await setActiveOrg(s.idHash, o.id);
    orgId = o.id;
  });
  if (orgId) { revalidatePath("/", "layout"); redirect("/assets"); }
  return r;
}

export async function addAssetAction(_: ActionState, f: FormData): Promise<ActionState> {
  let id: string | null = null;
  const r = await run(async () => {
    const c = await requireOrgContext();
    try {
      const a = await assetSvc.addAsset(c, {
        host: str(f, "host"), displayName: str(f, "displayName") || undefined,
        environment: str(f, "environment") || undefined, clientGroupId: str(f, "clientGroupId") || null,
      });
      id = a.id;
    } catch (e) {
      // Adding a host that is already here opens the existing asset rather than showing an error.
      if (e instanceof AppError && e.code === "asset_exists" && typeof e.extra?.assetId === "string") { id = e.extra.assetId; return; }
      throw e;
    }
  });
  if (id) redirect(`/assets/${id}`);
  return r;
}

export async function addRepositoryAssetAction(_: ActionState, f: FormData): Promise<ActionState> {
  let id: string | null = null;
  const r = await run(async () => {
    const { asset } = await assetSvc.addRepositoryAsset(await requireOrgContext(), str(f, "integrationId"));
    id = asset.id;
  });
  if (id) redirect(`/assets/${id}`);
  return r;
}

export async function addSuggestionAction(_: ActionState, f: FormData): Promise<ActionState> {
  let id: string | null = null;
  const r = await run(async () => {
    const env = str(f, "environment");
    const a = await suggestionSvc.addSuggestion(await requireOrgContext(), str(f, "suggestionId"),
      env === "staging" || env === "development" ? env : "production");
    id = a.id;
  });
  if (id) redirect(`/assets/${id}`);
  return r;
}

export async function dismissSuggestionAction(_: ActionState, f: FormData): Promise<ActionState> {
  return run(async () => {
    await suggestionSvc.dismissSuggestion(await requireOrgContext(), str(f, "suggestionId"));
    return { ok: "Suggestion dismissed." };
  });
}

export async function startVerificationAction(_: ActionState, f: FormData): Promise<ActionState> {
  return run(async () => {
    const c = await requireOrgContext();
    await assetSvc.startVerification(c, str(f, "assetId"), str(f, "method"));
    return { ok: "Challenge created. Publish the value shown, then run the check." };
  });
}

const REASONS: Record<string, string> = {
  token_not_found: "The verification value was not found.",
  dns_failed: "The domain could not be resolved.",
  egress_blocked: "The domain resolves to a private or reserved address, which RuyaShield will not contact.",
  timeout: "The site did not respond in time.",
  network: "The site could not be reached.",
  resolver_disagreement: "DNS resolvers gave inconsistent answers.",
  resolver_error: "DNS resolvers could not be queried.",
  redirect_refused: "The site redirected to a different host, which is not accepted as proof.",
  too_large: "The response was too large.",
  internal_error: "The check could not be completed.",
  no_resolvers: "No DNS resolvers are configured.",
};
const reasonText = (r: string) => REASONS[r] ?? (/^http_\d+$/.test(r) ? `The site answered HTTP ${r.slice(5)}.` : r);

export async function checkVerificationAction(_: ActionState, f: FormData): Promise<ActionState> {
  return run(async () => {
    const c = await requireOrgContext();
    const o = await assetSvc.checkVerification(c, str(f, "verificationId"), { egress: { allowPrivate: allowPrivateFromEnv() } });
    const why = reasonText(o.reason);
    // Only a passed check is reported as success. Failed and inconclusive results say so plainly.
    if (o.status === "passed") return { ok: "Ownership verified.", tone: "ok" };
    if (o.status === "failed") return { ok: `Not verified: ${why} Fix the record and check again.`, tone: "bad" };
    return { ok: `Inconclusive, not verified: ${why} You can retry.`, tone: "warn" };
  });
}

export async function launchAssessmentAction(_: ActionState, f: FormData): Promise<ActionState> {
  let id: string | null = null;
  const r = await run(async () => {
    const c = await requireOrgContext();
    const lines = (k: string) => str(f, k).split(/[\n,]/).map((x) => x.trim()).filter(Boolean);
    const out = await assessmentSvc.launchAssessment(c, {
      assetId: str(f, "assetId"), idempotencyKey: str(f, "idempotencyKey"),
      checkIds: f.getAll("checkIds").map(String),
      basePaths: lines("basePaths"), excludedPaths: lines("excludedPaths"),
      referralId: str(f, "referralId") || undefined,
    });
    id = out.assessment.id;
  });
  if (id) redirect(`/assessments/${id}`);
  return r;
}

/**
 * "Run again": launches a new assessment of the same asset with every check that is allowed for it today
 * (so checks added since the last run are included), keeping the earlier run's base and excluded paths.
 * launchAssessment re-checks verification, authorization, classes, quota and rate limits as for any launch.
 */
export async function rerunAssessmentAction(_: ActionState, f: FormData): Promise<ActionState> {
  let id: string | null = null;
  const r = await run(async () => {
    const c = await requireOrgContext();
    const prev = await assessmentSvc.getAssessment(c, str(f, "assessmentId"));
    const { asset, eligibility: el } = await assetSvc.getAsset(c, prev.asset.id);
    if (!el.eligible) throw new AppError(403, "authorization_required", el.reason);
    const allowed = el.allowedClasses as readonly string[];
    const checkIds = (await assessmentSvc.listCatalogue(c, asset.kind)).filter((d) => d.launchable && allowed.includes(d.class)).map((d) => d.id);
    if (!checkIds.length) throw new AppError(422, "invalid_scope", "No checks are available for this asset.");
    const out = await assessmentSvc.launchAssessment(c, {
      assetId: asset.id, idempotencyKey: str(f, "idempotencyKey"), checkIds,
      basePaths: prev.scope?.basePaths ?? [], excludedPaths: prev.scope?.excludedPaths ?? [],
    });
    id = out.assessment.id;
  });
  if (id) redirect(`/assessments/${id}`);
  return r;
}

export async function cancelAssessmentAction(_: ActionState, f: FormData): Promise<ActionState> {
  return run(async () => {
    const c = await requireOrgContext();
    const x = await assessmentSvc.cancelAssessment(c, str(f, "assessmentId"));
    return x.status === "cancelled"
      ? { ok: "Assessment cancelled. No further requests will be sent.", tone: "ok" }
      : { ok: "Cancellation requested. The running check is stopped before the next one starts.", tone: "warn" };
  });
}

export async function recordAttestationAction(_: ActionState, f: FormData): Promise<ActionState> {
  return run(async () => {
    const c = await requireOrgContext();
    await assetSvc.recordAttestation(c, str(f, "assetId"), {
      partyName: str(f, "partyName"), partyRole: str(f, "partyRole"), partyEmail: str(f, "partyEmail"),
      relationship: str(f, "relationship"), allowedClasses: f.getAll("allowedClasses").map(String),
      validFrom: str(f, "validFrom"), validTo: str(f, "validTo"), confirm: f.get("confirm") === "on" ? true : undefined,
    });
    return { ok: "Authorization recorded." };
  });
}

export async function revokeAttestationAction(_: ActionState, f: FormData): Promise<ActionState> {
  return run(async () => {
    const c = await requireOrgContext();
    await assetSvc.revokeAttestation(c, str(f, "attestationId"), str(f, "reason"));
    return { ok: "Authorization revoked." };
  });
}

export async function createInviteAction(_: ActionState, f: FormData): Promise<ActionState> {
  return run(async () => {
    const c = await requireOrgContext();
    await orgSvc.createInvite(c, { email: str(f, "email"), role: str(f, "role"), clientGroupIds: f.getAll("clientGroupIds").map(String) });
    return { ok: "Invitation queued. It will be emailed shortly." };
  });
}

export async function revokeInviteAction(_: ActionState, f: FormData): Promise<ActionState> {
  return run(async () => {
    await orgSvc.revokeInvite(await requireOrgContext(), str(f, "inviteId"));
    return { ok: "Invitation revoked." };
  });
}

export async function changeRoleAction(_: ActionState, f: FormData): Promise<ActionState> {
  return run(async () => {
    await orgSvc.changeRole(await requireOrgContext(), str(f, "userId"), str(f, "role"));
    return { ok: "Role updated." };
  });
}

export async function removeMemberAction(_: ActionState, f: FormData): Promise<ActionState> {
  return run(async () => {
    await orgSvc.removeMember(await requireOrgContext(), str(f, "userId"));
    return { ok: "Member removed." };
  });
}

export async function createClientGroupAction(_: ActionState, f: FormData): Promise<ActionState> {
  return run(async () => {
    await orgSvc.createClientGroup(await requireOrgContext(), str(f, "name"));
    return { ok: "Client group created." };
  });
}

export async function killSwitchAction(_: ActionState, f: FormData): Promise<ActionState> {
  return run(async () => {
    const which = str(f, "which") === "ai" ? "ai" : "scanning";
    const engaged = str(f, "engaged") === "true";
    await orgSvc.setKillSwitch(await requireOrgContext(), which, engaged, str(f, "reason"));
    return { ok: engaged ? "Kill switch engaged." : "Kill switch released.", tone: engaged ? "warn" : "ok" };
  });
}

export async function verifyAuditChainAction(): Promise<ActionState> {
  return run(async () => {
    const r = await verifyOrgAuditChain(await requireOrgContext());
    if (r.firstBrokenSeq == null) return { ok: `Chain intact: ${r.checked} events checked.`, tone: "ok" };
    return { ok: `Chain BROKEN at event #${r.firstBrokenSeq} (${r.checked} checked). Treat the log as tampered.`, tone: "bad" };
  });
}

export async function acceptInviteAction(_: ActionState, f: FormData): Promise<ActionState> {
  let joined = false;
  const r = await run(async () => {
    const s = await requireSession();
    const { orgId } = await orgSvc.acceptInvite(s, str(f, "token"), await requestMeta());
    await setActiveOrg(s.idHash, orgId);
    joined = true;
  });
  if (joined) { revalidatePath("/", "layout"); redirect("/assets"); }
  return r;
}

// ---------- findings & triage (P3) ----------

const TRANSITION_OK: Record<string, string> = {
  triage: "Marked as triaged.", confirm: "Confirmed.", false_positive: "Marked as a false positive. It is re-opened for triage if the evidence changes.",
  reopen_false_positive: "Re-opened for triage.", accept_risk: "Risk accepted until the expiry date. It returns to triage when it expires.",
  revoke_risk: "Risk acceptance revoked; the finding is back in triage.", start_remediation: "Remediation started.",
  mark_fix_applied: "Marked as fix applied. It stays open until a verification re-test confirms the fix.",
};

export async function findingTransitionAction(_: ActionState, f: FormData): Promise<ActionState> {
  return run(async () => {
    const c = await requireOrgContext();
    const kind = str(f, "kind");
    await findingSvc.transition(c, str(f, "findingId"), kind, {
      justification: str(f, "justification"), controls: str(f, "controls"), reason: str(f, "reason"),
      expiresAt: str(f, "expiresAt") ? `${str(f, "expiresAt")}T23:59:59Z` : "",
    });
    return { ok: TRANSITION_OK[kind] ?? "Saved." };
  });
}

export async function overrideSeverityAction(_: ActionState, f: FormData): Promise<ActionState> {
  return run(async () => {
    const c = await requireOrgContext();
    await findingSvc.overrideSeverity(c, str(f, "findingId"), { severity: str(f, "severity"), confidence: str(f, "confidence"), reason: str(f, "reason") });
    return { ok: "Severity and confidence updated." };
  });
}

export async function assignFindingAction(_: ActionState, f: FormData): Promise<ActionState> {
  return run(async () => {
    const c = await requireOrgContext();
    const due = str(f, "dueAt");
    const r = await findingSvc.assign(c, str(f, "findingId"), { assigneeId: str(f, "assigneeId") || null, dueAt: due ? `${due}T23:59:59Z` : null });
    return { ok: r.ownerId ? "Assigned." : "Unassigned." };
  });
}

export async function commentFindingAction(_: ActionState, f: FormData): Promise<ActionState> {
  return run(async () => {
    const c = await requireOrgContext();
    const row = await findingSvc.addComment(c, str(f, "findingId"), str(f, "body"));
    return { ok: row.mentions.length ? `Comment added; ${row.mentions.length} member(s) notified.` : "Comment added." };
  });
}

export async function setCriticalityAction(_: ActionState, f: FormData): Promise<ActionState> {
  return run(async () => {
    const c = await requireOrgContext();
    await findingSvc.setAssetCriticality(c, str(f, "assetId"), str(f, "criticality"));
    return { ok: "Business criticality saved. Finding priorities use it from now on." };
  });
}

export async function requestVerificationAction(_: ActionState, f: FormData): Promise<ActionState> {
  return run(async () => {
    const c = await requireOrgContext();
    const out = await requestVerification(c, str(f, "findingId"), { idempotencyKey: str(f, "idempotencyKey") });
    return { ok: out.replayed ? "This re-test was already queued." : "Re-test queued. Results appear here when it finishes." };
  });
}

export async function requestAiAction(_: ActionState, f: FormData): Promise<ActionState> {
  return run(async () => {
    const c = await requireOrgContext();
    const out = await aiSvc.requestAnalysis(c, str(f, "findingId"), { useCase: str(f, "useCase"), idempotencyKey: str(f, "idempotencyKey") });
    const s = out.analysis.status;
    if (s === "completed") return { ok: "AI analysis ready below. Review it before acting on it.", tone: "ok" };
    if (s === "inconclusive") return { ok: "The AI could not support any conclusion from the evidence. See what is missing below.", tone: "warn" };
    if (s === "rejected") return { ok: "The AI reply failed validation and was discarded. Nothing was changed.", tone: "bad" };
    return { ok: "The AI provider was unavailable. Use the finding's remediation guidance.", tone: "bad" };
  });
}

export async function chatAiAction(_: ActionState, f: FormData): Promise<ActionState> {
  return run(async () => {
    const c = await requireOrgContext();
    const threadId = str(f, "threadId");
    const out = await aiSvc.chatOnFinding(c, str(f, "findingId"), {
      question: str(f, "question"), threadId: threadId || undefined, idempotencyKey: str(f, "idempotencyKey"),
    });
    const s = out.analysis.status;
    if (s === "completed") return { ok: "Answer ready below. It is advisory; review it before acting on it.", tone: "ok" };
    if (s === "inconclusive") return { ok: "The evidence could not answer that question. See what is missing below.", tone: "warn" };
    if (s === "rejected") return { ok: "The AI reply failed validation and was discarded. Nothing was changed.", tone: "bad" };
    return { ok: "The AI provider was unavailable. Use the finding's remediation guidance.", tone: "bad" };
  });
}

export async function aiSettingsAction(_: ActionState, f: FormData): Promise<ActionState> {
  return run(async () => {
    const enabled = str(f, "enabled") === "true";
    const budget = str(f, "budget");
    await aiSvc.setAiSettings(await requireOrgContext(), {
      enabled, reason: str(f, "reason"), ...(budget ? { monthlyTokenBudget: Number(budget) } : {}),
    });
    return { ok: enabled ? "AI assistance is on." : "AI assistance is off.", tone: enabled ? "ok" : "warn" };
  });
}

// ---------- remediation (P5) ----------

const lines = (f: FormData, k: string) => str(f, k).split("\n").map((l) => l.trim()).filter(Boolean);

export async function createPlanAction(_: ActionState, f: FormData): Promise<ActionState> {
  return run(async () => {
    const c = await requireOrgContext();
    const type = str(f, "type") === "patch" ? "patch" : "guided";
    const out = await planSvc.createPlan(c, str(f, "findingId"), {
      idempotencyKey: str(f, "idempotencyKey"), type, title: str(f, "title"), description: str(f, "description"),
      affectedComponents: lines(f, "affectedComponents"), rollbackNotes: str(f, "rollbackNotes"), verificationChecks: lines(f, "verificationChecks"),
      ...(type === "patch" ? { integrationId: str(f, "integrationId") || undefined, baseCommit: str(f, "baseCommit").trim() || undefined, diff: str(f, "diff") || undefined } : {}),
    });
    return { ok: out.replayed ? "This plan was already created." : "Draft plan created. Submit it when it is ready for review." };
  });
}

export async function createPlanFromAiAction(_: ActionState, f: FormData): Promise<ActionState> {
  return run(async () => {
    const c = await requireOrgContext();
    await planSvc.createPlanFromAi(c, str(f, "findingId"), { idempotencyKey: str(f, "idempotencyKey"), claimId: str(f, "claimId") });
    return { ok: "Draft guided plan created from the AI recommendation. Review and edit it before submitting; it is not verified.", tone: "warn" };
  });
}

export async function editPlanAction(_: ActionState, f: FormData): Promise<ActionState> {
  return run(async () => {
    const c = await requireOrgContext();
    const patch = str(f, "planType") === "patch";
    const out = await planSvc.editPlan(c, str(f, "planId"), {
      version: Number(str(f, "version")), title: str(f, "title"), description: str(f, "description"),
      affectedComponents: lines(f, "affectedComponents"), rollbackNotes: str(f, "rollbackNotes"), verificationChecks: lines(f, "verificationChecks"),
      ...(patch ? { baseCommit: str(f, "baseCommit").trim() || undefined, diff: str(f, "diff") || undefined } : {}),
    });
    return out.changed ? { ok: "Plan updated. Any earlier sandbox result or approval no longer applies to it.", tone: "warn" } : { ok: "No changes." };
  });
}

export async function submitPlanAction(_: ActionState, f: FormData): Promise<ActionState> {
  return run(async () => {
    const out = await planSvc.submitPlan(await requireOrgContext(), str(f, "planId"));
    return { ok: out.changed ? "Plan proposed." : "Plan was already proposed." };
  });
}

export async function sandboxAction(_: ActionState, f: FormData): Promise<ActionState> {
  return run(async () => {
    const out = await planSvc.requestSandbox(await requireOrgContext(), str(f, "planId"), { idempotencyKey: str(f, "idempotencyKey") });
    return { ok: out.replayed ? "This sandbox run was already queued." : "Sandbox test queued. The result appears here when the worker finishes it." };
  });
}

export async function requestApprovalAction(_: ActionState, f: FormData): Promise<ActionState> {
  return run(async () => {
    const out = await approvalSvc.requestApproval(await requireOrgContext(), str(f, "planId"), {
      idempotencyKey: str(f, "idempotencyKey"), note: str(f, "note") || undefined, untestedOverride: str(f, "untestedOverride") === "on",
    });
    return { ok: out.replayed ? "Approval was already requested." : "Approval requested. Someone other than you must decide it." };
  });
}

export async function decideApprovalAction(_: ActionState, f: FormData): Promise<ActionState> {
  return run(async () => {
    const c = await requireOrgContext();
    const decision = str(f, "decision") === "approve" ? "approve" : "reject";
    const session = await getSession();
    await approvalSvc.decideApproval(c, str(f, "approvalId"), { decision, reason: str(f, "reason") || undefined, subjectSha256: str(f, "subjectSha256") }, { ref: session?.idHash.slice(0, 16) ?? null });
    return decision === "approve" ? { ok: "Approved. The change is not applied or verified yet." } : { ok: "Rejected.", tone: "warn" };
  });
}

export async function revokeApprovalAction(_: ActionState, f: FormData): Promise<ActionState> {
  return run(async () => {
    await approvalSvc.revokeApproval(await requireOrgContext(), str(f, "approvalId"), { reason: str(f, "reason") });
    return { ok: "Approval revoked.", tone: "warn" };
  });
}

export async function markAppliedAction(_: ActionState, f: FormData): Promise<ActionState> {
  return run(async () => {
    await approvalSvc.markApplied(await requireOrgContext(), str(f, "planId"), { note: str(f, "note") });
    return { ok: "Recorded as applied by you. The finding stays open until a re-test passes.", tone: "warn" };
  });
}

export async function createIntegrationAction(_: ActionState, f: FormData): Promise<ActionState> {
  return run(async () => {
    const testCommands = lines(f, "testCommands").map((l) => l.split(/\s+/));
    await integrationSvc.createIntegration(await requireOrgContext(), {
      name: str(f, "name"), externalId: str(f, "externalId"), defaultBranch: str(f, "defaultBranch") || "main", testCommands,
    });
    return { ok: "Repository connected." };
  });
}

export async function disableIntegrationAction(_: ActionState, f: FormData): Promise<ActionState> {
  return run(async () => {
    await integrationSvc.disableIntegration(await requireOrgContext(), str(f, "integrationId"));
    return { ok: "Repository disconnected.", tone: "warn" };
  });
}

export async function decideReferralAction(_: ActionState, f: FormData): Promise<ActionState> {
  return run(async () => {
    const decision = str(f, "decision");
    const r = await referralSvc.decideReferral(await requireOrgContext(), str(f, "token"), {
      decision, textVersion: str(f, "textVersion"), acceptCharges: f.get("acceptCharges") === "on", shareStatus: f.get("shareStatus") === "on",
    });
    if (r.status === "consented") return { ok: "Consent recorded. Nothing has been scanned yet: launch the assessment below when you are ready." };
    return { ok: r.status === "declined" ? "Referral declined." : "Referral deleted.", tone: "warn" };
  });
}

export async function deleteReferralAction(_: ActionState, f: FormData): Promise<ActionState> {
  return run(async () => {
    await referralSvc.deleteReferral(await requireOrgContext(), str(f, "referralId"));
    return { ok: "Referral deleted.", tone: "warn" };
  });
}

export async function intrusiveNetworkAction(_: ActionState, f: FormData): Promise<ActionState> {
  return run(async () => {
    const r = await orgSvc.setIntrusiveNetwork(await requireOrgContext(), str(f, "enable") === "true", str(f, "reason"));
    if (r === "requested") return { ok: "Requested. A different admin must confirm before port scans can run.", tone: "warn" };
    return r === "enabled" ? { ok: "Intrusive network checks are on.", tone: "warn" } : { ok: "Intrusive network checks are off." };
  });
}

export async function regressionIntervalAction(_: ActionState, f: FormData): Promise<ActionState> {
  return run(async () => {
    const raw = str(f, "days").trim();
    const days = raw === "" ? null : Number(raw);
    await orgSvc.setRegressionInterval(await requireOrgContext(), days, str(f, "reason"));
    return days === null ? { ok: "Scheduled regression re-tests are off.", tone: "warn" } : { ok: `Verified fixes will be re-tested every ${days} days.` };
  });
}

export async function generateReportAction(_: ActionState, f: FormData): Promise<ActionState> {
  return run(async () => {
    const r = await generateReport(await requireOrgContext(), {
      format: str(f, "format"), clientGroupId: str(f, "clientGroupId") || null,
      options: {
        title: str(f, "title"), preset: str(f, "preset") || "client",
        sections: f.getAll("sections").filter((x): x is string => typeof x === "string"),
        minSeverity: str(f, "minSeverity") || undefined, includeFixes: f.get("includeFixes") === "on",
      },
    });
    return { ok: `Report generated (${r.format.toUpperCase()}, SHA-256 ${r.sha256.slice(0, 12)}…). Open or download it from the list.` };
  });
}

export async function markReadAction(_: ActionState, f: FormData): Promise<ActionState> {
  return run(async () => {
    await notifySvc.markRead(await requireOrgContext(), str(f, "id"));
    return { ok: "Marked as read." };
  });
}

export async function setNotificationPrefAction(_: ActionState, f: FormData): Promise<ActionState> {
  return run(async () => {
    await notifySvc.setPref(await requireOrgContext(), { kind: str(f, "kind"), email: f.get("email") === "on", inApp: f.get("inApp") === "on" });
    return { ok: "Preference saved." };
  });
}

export async function requestOrgDeletionAction(_: ActionState, f: FormData): Promise<ActionState> {
  return run(async () => {
    await lifecycleSvc.requestOrgDeletion(await requireOrgContext(), { confirmSlug: str(f, "confirmSlug"), reason: str(f, "reason") });
    return { ok: `Deletion requested. It is finalized after ${lifecycleSvc.DELETION_GRACE_DAYS} days unless cancelled.`, tone: "bad" };
  });
}

export async function cancelOrgDeletionAction(_: ActionState, f: FormData): Promise<ActionState> {
  return run(async () => {
    await lifecycleSvc.cancelOrgDeletion(await requireOrgContext(), str(f, "reason"));
    return { ok: "Deletion cancelled." };
  });
}

export async function legalHoldAction(_: ActionState, f: FormData): Promise<ActionState> {
  return run(async () => {
    const on = str(f, "on") === "true";
    await lifecycleSvc.setLegalHold(await requireOrgContext(), on, str(f, "reason"));
    return on ? { ok: "Legal hold placed. Retention purges and deletion are suspended.", tone: "warn" } : { ok: "Legal hold released." };
  });
}

export async function createTokenAction(_: ActionState, f: FormData): Promise<ActionState> {
  return run(async () => {
    const t = await tokenSvc.createApiToken(await requireOrgContext(), {
      name: str(f, "name"), scopes: f.getAll("scopes").filter((v) => typeof v === "string"), days: Number(str(f, "days") || "0"),
    });
    return { ok: `Token created; it expires ${t.expiresAt.toISOString().slice(0, 10)}. Copy it now: it is not shown again.`, tone: "warn", secret: t.token };
  });
}

export async function createWebMonitorTokenAction(): Promise<ActionState> {
  return run(async () => {
    const t = await createWebMonitorToken(await requireOrgContext());
    return { ok: `Token created; it expires ${t.expiresAt.toISOString().slice(0, 10)}. Copy it now: it is not shown again.`, tone: "warn", secret: t.token };
  });
}

export async function revokeTokenAction(_: ActionState, f: FormData): Promise<ActionState> {
  return run(async () => {
    await tokenSvc.revokeApiToken(await requireOrgContext(), str(f, "tokenId"));
    return { ok: "Token revoked.", tone: "warn" };
  });
}

export async function requestProAction(): Promise<ActionState> {
  return run(async () => {
    await orgPlanSvc.requestPro(await requireOrgContext(), await requestMeta());
    return { ok: "Pro requested. We will switch your organization and let your admins know." };
  });
}

export async function setOrgPlanAction(_: ActionState, f: FormData): Promise<ActionState> {
  return run(async () => {
    const r = await orgPlanSvc.setOrgPlan(await requireSession(), { orgSlug: str(f, "orgSlug"), plan: str(f, "plan") }, await requestMeta());
    return { ok: `${r.name} is now on ${r.plan === "pro" ? "Pro" : "Free"}.` };
  });
}

export async function startBreakGlassAction(_: ActionState, f: FormData): Promise<ActionState> {
  let started = false;
  const r = await run(async () => {
    await breakGlassSvc.startBreakGlass(await requireSession(), {
      orgSlug: str(f, "orgSlug"), reason: str(f, "reason"), minutes: Number(str(f, "minutes") || "0"),
    }, await requestMeta());
    started = true;
  });
  if (started) redirect("/dashboard");
  return r;
}

export async function endBreakGlassAction(_: ActionState, f: FormData): Promise<ActionState> {
  return run(async () => {
    await breakGlassSvc.endBreakGlass(await requireSession(), str(f, "orgId"), await requestMeta());
    return { ok: "Support access ended." };
  });
}

export async function createCloudflareSourceAction(_: ActionState, f: FormData): Promise<ActionState> {
  return run(async () => {
    await attackSvc.createCloudflareSource(await requireOrgContext(), {
      assetId: str(f, "assetId"), name: str(f, "name"), zoneId: str(f, "zoneId"), token: str(f, "token"),
    });
    return { ok: "Cloudflare connected. The first poll runs within a few minutes; the token is stored encrypted and is not shown again." };
  });
}

export async function createLogAgentSourceAction(_: ActionState, f: FormData): Promise<ActionState> {
  return run(async () => {
    const r = await attackSvc.createLogAgentSource(await requireOrgContext(), { assetId: str(f, "assetId"), name: str(f, "name") });
    return { ok: "Log agent created. Copy this ingest token now: it is not shown again. Put it in the agent's env file (chmod 600).", tone: "warn", secret: r.token };
  });
}

export async function disableAttackSourceAction(_: ActionState, f: FormData): Promise<ActionState> {
  return run(async () => {
    await attackSvc.disableSource(await requireOrgContext(), str(f, "sourceId"));
    return { ok: "Source disabled. Its stored credential no longer works; events already recorded stay until the 90-day purge.", tone: "warn" };
  });
}

// ---------- account (the signed-in person's own settings) ----------

async function clearSessionCookie() {
  const jar = await cookies();
  jar.set(sessionCookieName(), "", { maxAge: 0, path: "/", secure: secureCookies(), httpOnly: true, sameSite: "lax" });
}

export async function updateProfileAction(_: ActionState, f: FormData): Promise<ActionState> {
  return run(async () => {
    await accountSvc.updateProfile(await requireSession(), { displayName: str(f, "displayName") }, await requestMeta());
    return { ok: "Name saved." };
  });
}

export async function changePasswordAction(_: ActionState, f: FormData): Promise<ActionState> {
  return run(async () => {
    if (str(f, "next") !== str(f, "confirm")) throw new AppError(422, "validation_failed", "The two new passwords do not match.");
    await accountSvc.changePassword(await requireSession(), { current: str(f, "current"), next: str(f, "next") }, await requestMeta());
    return { ok: "Password changed. Other devices were signed out." };
  });
}

export async function newRecoveryCodesAction(_: ActionState, f: FormData): Promise<ActionState> {
  let done = false;
  const r = await run(async () => {
    await accountSvc.newRecoveryCodes(await requireSession(), str(f, "code"), await requestMeta());
    done = true;
  });
  if (done) redirect("/auth/mfa");
  return r;
}

export async function resetAuthenticatorAction(_: ActionState, f: FormData): Promise<ActionState> {
  let done = false;
  const r = await run(async () => {
    await accountSvc.resetAuthenticator(await requireSession(), str(f, "code"), await requestMeta());
    done = true;
  });
  if (done) {
    await clearSessionCookie();
    redirect("/auth/signin?mfaReset=1");
  }
  return r;
}

export async function signOutSessionAction(_: ActionState, f: FormData): Promise<ActionState> {
  return run(async () => {
    await accountSvc.signOutSession(await requireSession(), str(f, "key"), await requestMeta());
    return { ok: "Signed out of that device." };
  });
}

export async function signOutOtherSessionsAction(): Promise<ActionState> {
  return run(async () => {
    const n = await accountSvc.signOutOtherSessions(await requireSession(), await requestMeta());
    return { ok: n ? `Signed out of ${n} other device${n === 1 ? "" : "s"}.` : "No other devices were signed in." };
  });
}

export async function deleteAccountAction(_: ActionState, f: FormData): Promise<ActionState> {
  let done = false;
  const r = await run(async () => {
    await accountSvc.deleteAccount(await requireSession(), { confirm: str(f, "confirm"), code: str(f, "code") }, await requestMeta());
    done = true;
  });
  if (done) {
    await clearSessionCookie();
    redirect("/auth/signin?deleted=1");
  }
  return r;
}
