// Typed mirror of db/migrations/*.sql (the SQL files are the source of truth;
// RLS policies, grants and SECURITY DEFINER helpers live only there).
import {
  bigint, bigserial, boolean, customType, date, integer, jsonb, pgEnum, pgTable, primaryKey, text, timestamp, uuid,
} from "drizzle-orm/pg-core";

const ts = (name: string) => timestamp(name, { withTimezone: true, mode: "date" });

export const memberRole = pgEnum("member_role", [
  "org_admin", "security_lead", "analyst", "developer", "approver", "viewer",
]);
export type MemberRole = (typeof memberRole.enumValues)[number];

export const assetStatus = pgEnum("asset_status", ["unverified", "verified", "lapsed", "revoked"]);

export const users = pgTable("users", {
  id: uuid("id").primaryKey().defaultRandom(),
  email: text("email").notNull(),
  displayName: text("display_name").notNull(),
  idpIssuer: text("idp_issuer").notNull(),
  idpSubject: text("idp_subject").notNull(),
  disabledAt: ts("disabled_at"),
  createdAt: ts("created_at").notNull().defaultNow(),
});

export const sessions = pgTable("sessions", {
  idHash: text("id_hash").primaryKey(),
  userId: uuid("user_id").notNull(),
  activeOrgId: uuid("active_org_id"),
  mfa: boolean("mfa").notNull(),
  amr: text("amr").array().notNull().default([]),
  authTime: ts("auth_time").notNull(),
  createdAt: ts("created_at").notNull().defaultNow(),
  lastSeenAt: ts("last_seen_at").notNull().defaultNow(),
  expiresAt: ts("expires_at").notNull(),
  revokedAt: ts("revoked_at"),
  ip: text("ip"),
  userAgent: text("user_agent"),
});

export const loginStates = pgTable("login_states", {
  state: text("state").primaryKey(),
  nonce: text("nonce").notNull(),
  codeVerifier: text("code_verifier").notNull(),
  returnTo: text("return_to").notNull().default("/"),
  createdAt: ts("created_at").notNull().defaultNow(),
});

/** Built-in authenticator (0023_totp_mfa.sql). secret is sealed; enabledAt null = enrollment not confirmed. */
export const userMfa = pgTable("user_mfa", {
  userId: uuid("user_id").primaryKey(),
  secret: text("secret").notNull(),
  enabledAt: ts("enabled_at"),
  lastStep: bigint("last_step", { mode: "number" }).notNull().default(0),
  createdAt: ts("created_at").notNull().defaultNow(),
});

export const mfaRecoveryCodes = pgTable("mfa_recovery_codes", {
  userId: uuid("user_id").notNull(),
  codeHash: text("code_hash").notNull(),
  usedAt: ts("used_at"),
  createdAt: ts("created_at").notNull().defaultNow(),
}, (t) => [primaryKey({ columns: [t.userId, t.codeHash] })]);

/** Recovery codes waiting to be shown once (0024). codes is sealed JSON. */
export const mfaRecoveryReveals = pgTable("mfa_recovery_reveals", {
  userId: uuid("user_id").primaryKey(),
  codes: text("codes").notNull(),
  returnTo: text("return_to").notNull().default("/"),
  createdAt: ts("created_at").notNull().defaultNow(),
});

export const pendingLogins = pgTable("pending_logins", {
  tokenHash: text("token_hash").primaryKey(),
  userId: uuid("user_id").notNull(),
  amr: text("amr").array().notNull().default([]),
  issuer: text("issuer").notNull(),
  returnTo: text("return_to").notNull().default("/"),
  attempts: integer("attempts").notNull().default(0),
  createdAt: ts("created_at").notNull().defaultNow(),
});

export const loginAttempts = pgTable("login_attempts", {
  id: bigserial("id", { mode: "number" }).primaryKey(),
  key: text("key").notNull(),
  createdAt: ts("created_at").notNull().defaultNow(),
});

export const orgs = pgTable("orgs", {
  id: uuid("id").primaryKey(),
  name: text("name").notNull(),
  slug: text("slug").notNull(),
  plan: text("plan").notNull().default("pilot"),
  region: text("region").notNull(),
  approverMustDiffer: boolean("approver_must_differ").notNull().default(true),
  aiEnabled: boolean("ai_enabled").notNull().default(false),
  agencyRequiresAttestation: boolean("agency_requires_attestation").notNull().default(true),
  killScanning: boolean("kill_scanning").notNull().default(false),
  killAi: boolean("kill_ai").notNull().default(false),
  /** Scanner M3: class A2 network checks (port scan). Two-person opt-in; off by default. */
  allowIntrusiveNetwork: boolean("allow_intrusive_network").notNull().default(false),
  intrusiveNetworkRequestedBy: uuid("intrusive_network_requested_by"),
  intrusiveNetworkRequestedAt: ts("intrusive_network_requested_at"),
  aiMonthlyTokenBudget: integer("ai_monthly_token_budget").notNull().default(200000),
  regressionIntervalDays: integer("regression_interval_days"),
  legalHold: boolean("legal_hold").notNull().default(false),
  deletionRequestedAt: ts("deletion_requested_at"),
  deletionRequestedBy: uuid("deletion_requested_by"),
  deletedAt: ts("deleted_at"),
  createdBy: uuid("created_by").notNull(),
  createdAt: ts("created_at").notNull().defaultNow(),
});

export const memberships = pgTable("memberships", {
  orgId: uuid("org_id").notNull(),
  userId: uuid("user_id").notNull(),
  role: memberRole("role").notNull(),
  restricted: boolean("restricted").notNull().default(false),
  createdAt: ts("created_at").notNull().defaultNow(),
}, (t) => [primaryKey({ columns: [t.orgId, t.userId] })]);

export const clientGroups = pgTable("client_groups", {
  id: uuid("id").primaryKey().defaultRandom(),
  orgId: uuid("org_id").notNull(),
  name: text("name").notNull(),
  createdAt: ts("created_at").notNull().defaultNow(),
});

export const memberClientGroups = pgTable("member_client_groups", {
  orgId: uuid("org_id").notNull(),
  userId: uuid("user_id").notNull(),
  clientGroupId: uuid("client_group_id").notNull(),
}, (t) => [primaryKey({ columns: [t.orgId, t.userId, t.clientGroupId] })]);

export const invites = pgTable("invites", {
  id: uuid("id").primaryKey().defaultRandom(),
  orgId: uuid("org_id").notNull(),
  email: text("email").notNull(),
  role: memberRole("role").notNull(),
  clientGroupIds: uuid("client_group_ids").array().notNull().default([]),
  tokenHash: text("token_hash").notNull(),
  invitedBy: uuid("invited_by").notNull(),
  expiresAt: ts("expires_at").notNull(),
  acceptedAt: ts("accepted_at"),
  revokedAt: ts("revoked_at"),
  createdAt: ts("created_at").notNull().defaultNow(),
});

export const assets = pgTable("assets", {
  id: uuid("id").primaryKey().defaultRandom(),
  orgId: uuid("org_id").notNull(),
  clientGroupId: uuid("client_group_id"),
  kind: text("kind").$type<AssetKind>().notNull().default("domain"),
  host: text("host").notNull(),
  displayName: text("display_name").notNull(),
  environment: text("environment").notNull().default("production"),
  status: assetStatus("status").notNull().default("unverified"),
  verifiedAt: ts("verified_at"),
  verifiedMethod: text("verified_method"),
  nextReverifyAt: ts("next_reverify_at"),
  reverifyFailures: integer("reverify_failures").notNull().default(0),
  killScanning: boolean("kill_scanning").notNull().default(false),
  createdBy: uuid("created_by").notNull(),
  createdAt: ts("created_at").notNull().defaultNow(),
  criticality: text("criticality").$type<Criticality>(),
  /** Set only for kind = "repository": the integration this asset scans (1:1). */
  repositoryIntegrationId: uuid("repository_integration_id"),
});
export type AssetKind = "domain" | "repository";

export const assetVerifications = pgTable("asset_verifications", {
  id: uuid("id").primaryKey().defaultRandom(),
  orgId: uuid("org_id").notNull(),
  assetId: uuid("asset_id").notNull(),
  method: text("method").$type<VerificationMethod>().notNull(),
  token: text("token").notNull(),
  status: text("status").$type<VerificationStatus>().notNull().default("pending"),
  reason: text("reason"),
  evidence: jsonb("evidence"),
  expiresAt: ts("expires_at").notNull(),
  checkedAt: ts("checked_at"),
  createdBy: uuid("created_by"),
  createdAt: ts("created_at").notNull().defaultNow(),
});
export type VerificationMethod = "dns_txt" | "http_file" | "meta_tag";
export type VerificationStatus = "pending" | "checking" | "passed" | "failed" | "error" | "expired";

export const attestations = pgTable("attestations", {
  id: uuid("id").primaryKey().defaultRandom(),
  orgId: uuid("org_id").notNull(),
  assetId: uuid("asset_id").notNull(),
  partyName: text("party_name").notNull(),
  partyRole: text("party_role").notNull(),
  partyEmail: text("party_email").notNull(),
  relationship: text("relationship").notNull(),
  allowedClasses: text("allowed_classes").array().notNull(),
  validFrom: date("valid_from", { mode: "string" }).notNull(),
  validTo: date("valid_to", { mode: "string" }).notNull(),
  documentName: text("document_name"),
  documentSha256: text("document_sha256"),
  documentPath: text("document_path"),
  recordedBy: uuid("recorded_by").notNull(),
  revokedAt: ts("revoked_at"),
  createdAt: ts("created_at").notNull().defaultNow(),
});

export const auditEvents = pgTable("audit_events", {
  id: bigserial("id", { mode: "number" }).primaryKey(),
  orgId: uuid("org_id"),
  seq: bigint("seq", { mode: "number" }).notNull(),
  ts: ts("ts").notNull(),
  actorType: text("actor_type").notNull(),
  actorId: text("actor_id"),
  actorIp: text("actor_ip"),
  action: text("action").notNull(),
  targetType: text("target_type"),
  targetId: text("target_id"),
  outcome: text("outcome").notNull(),
  reason: text("reason"),
  requestId: text("request_id"),
  details: jsonb("details").notNull(),
  prevHash: text("prev_hash").notNull(),
  hash: text("hash").notNull(),
});

export const outbox = pgTable("outbox", {
  id: uuid("id").primaryKey().defaultRandom(),
  orgId: uuid("org_id").notNull(),
  topic: text("topic").notNull(),
  businessKey: text("business_key").notNull(),
  payload: jsonb("payload").notNull(),
  status: text("status").notNull().default("pending"),
  attempts: integer("attempts").notNull().default(0),
  availableAt: ts("available_at").notNull().defaultNow(),
  lockedUntil: ts("locked_until"),
  lastError: text("last_error"),
  createdAt: ts("created_at").notNull().defaultNow(),
  processedAt: ts("processed_at"),
});

export const processedMessages = pgTable("processed_messages", {
  consumer: text("consumer").notNull(),
  messageId: uuid("message_id").notNull(),
  orgId: uuid("org_id").notNull(),
  processedAt: ts("processed_at").notNull().defaultNow(),
}, (t) => [primaryKey({ columns: [t.consumer, t.messageId] })]);

// ---------- P2: assessments (0002_assessments.sql) ----------

export type CheckClass = "P" | "A1" | "A2" | "X";
export const checkDefinitions = pgTable("check_definitions", {
  id: text("id").primaryKey(),
  checkKey: text("check_key").notNull(),
  version: integer("version").notNull(),
  class: text("class").$type<CheckClass>().notNull(),
  engine: text("engine").notNull(),
  title: text("title").notNull(),
  description: text("description").notNull(),
  timeoutMs: integer("timeout_ms").notNull(),
  requestBudget: integer("request_budget").notNull(),
  verificationSupported: boolean("verification_supported").notNull(),
  enabled: boolean("enabled").notNull(),
  notes: text("notes"),
});

export const plans = pgTable("plans", {
  id: text("id").primaryKey(),
  maxAssessmentsPerMonth: integer("max_assessments_per_month").notNull(),
  maxRequestsPerAssessment: integer("max_requests_per_assessment").notNull(),
});

export const scopeVersions = pgTable("scope_versions", {
  id: uuid("id").primaryKey().defaultRandom(),
  orgId: uuid("org_id").notNull(),
  assetId: uuid("asset_id").notNull(),
  version: integer("version").notNull(),
  hosts: text("hosts").array().notNull(),
  basePaths: text("base_paths").array().notNull(),
  excludedPaths: text("excluded_paths").array().notNull().default([]),
  checkIds: text("check_ids").array().notNull(),
  classes: text("classes").array().notNull(),
  windowStart: ts("window_start").notNull(),
  windowEnd: ts("window_end").notNull(),
  maxRequests: integer("max_requests").notNull(),
  maxDurationS: integer("max_duration_s").notNull(),
  sha256: text("sha256").notNull(),
  createdBy: uuid("created_by").notNull(),
  createdAt: ts("created_at").notNull().defaultNow(),
});

export type AssessmentStatus =
  | "draft" | "queued" | "running" | "cancelling" | "cancelled" | "completed"
  | "completed_with_errors" | "failed" | "timed_out" | "rejected";
export const assessments = pgTable("assessments", {
  id: uuid("id").primaryKey().defaultRandom(),
  orgId: uuid("org_id").notNull(),
  assetId: uuid("asset_id").notNull(),
  scopeVersionId: uuid("scope_version_id").notNull(),
  scopeSha256: text("scope_sha256").notNull(),
  status: text("status").$type<AssessmentStatus>().notNull().default("queued"),
  reason: text("reason"),
  requestedBy: uuid("requested_by").notNull(),
  idempotencyKey: text("idempotency_key").notNull(),
  attempts: integer("attempts").notNull().default(0),
  leaseUntil: ts("lease_until"),
  cancelRequestedAt: ts("cancel_requested_at"),
  cancelledBy: uuid("cancelled_by"),
  coverage: jsonb("coverage").$type<Coverage>(),
  engineVersion: text("engine_version"),
  queuedAt: ts("queued_at").notNull().defaultNow(),
  startedAt: ts("started_at"),
  finishedAt: ts("finished_at"),
  referralId: uuid("referral_id"),
});
export interface Coverage { planned: number; ok: number; error: number; timeout: number; skipped: number; requests: number; complete: boolean }

export type CheckRunStatus = "pending" | "ok" | "error" | "timeout" | "skipped";
export const checkRuns = pgTable("check_runs", {
  id: uuid("id").primaryKey().defaultRandom(),
  orgId: uuid("org_id").notNull(),
  assessmentId: uuid("assessment_id").notNull(),
  checkId: text("check_id").notNull(),
  status: text("status").$type<CheckRunStatus>().notNull().default("pending"),
  reason: text("reason"),
  requestsUsed: integer("requests_used").notNull().default(0),
  engineVersion: text("engine_version"),
  evidence: jsonb("evidence"),
  startedAt: ts("started_at"),
  finishedAt: ts("finished_at"),
});

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Confidence = "confirmed" | "likely" | "suspected" | "unknown";
export type Criticality = "low" | "medium" | "high" | "critical";
export type FindingStatus =
  | "new" | "triaged" | "confirmed" | "false_positive" | "accepted_risk" | "in_remediation"
  | "fix_pending_verification" | "resolved_verified" | "reopened" | "stale";
export const findings = pgTable("findings", {
  id: uuid("id").primaryKey().defaultRandom(),
  orgId: uuid("org_id").notNull(),
  assetId: uuid("asset_id").notNull(),
  fingerprint: text("fingerprint").notNull(),
  checkKey: text("check_key").notNull(),
  issueKey: text("issue_key").notNull(),
  title: text("title").notNull(),
  severity: text("severity").$type<Severity>().notNull(),
  location: text("location").notNull(),
  status: text("status").$type<FindingStatus>().notNull().default("new"),
  firstSeen: ts("first_seen").notNull().defaultNow(),
  lastSeen: ts("last_seen").notNull().defaultNow(),
  lastAssessmentId: uuid("last_assessment_id").notNull(),
  evidence: jsonb("evidence").notNull().default({}),
  remediation: text("remediation"),
  // P3 (0004_findings_triage.sql)
  confidence: text("confidence").$type<Confidence>().notNull().default("confirmed"),
  sourceSeverity: text("source_severity").$type<Severity>(),
  sourceConfidence: text("source_confidence").$type<Confidence>(),
  cvssVector: text("cvss_vector"),
  severityReason: text("severity_reason"),
  severitySetBy: uuid("severity_set_by"),
  ownerId: uuid("owner_id"),
  dueAt: ts("due_at"),
  latestEvidenceId: uuid("latest_evidence_id"),
  fpEvidenceClass: text("fp_evidence_class"),
  missedRuns: integer("missed_runs").notNull().default(0),
  statusChangedAt: ts("status_changed_at").notNull().defaultNow(),
});

export const findingOccurrences = pgTable("finding_occurrences", {
  id: uuid("id").primaryKey().defaultRandom(),
  orgId: uuid("org_id").notNull(),
  findingId: uuid("finding_id").notNull(),
  assessmentId: uuid("assessment_id").notNull(),
  evidence: jsonb("evidence").notNull().default({}),
  evidenceId: uuid("evidence_id"),
  seenAt: ts("seen_at").notNull().defaultNow(),
});

// ---------- P3: findings & triage (0004_findings_triage.sql) ----------

export const evidenceItems = pgTable("evidence_items", {
  id: uuid("id").primaryKey().defaultRandom(),
  orgId: uuid("org_id").notNull(),
  sha256: text("sha256").notNull(),
  contentType: text("content_type").notNull(),
  sizeBytes: integer("size_bytes").notNull(),
  truncated: boolean("truncated").notNull().default(false),
  body: text("body").notNull(),
  assessmentId: uuid("assessment_id"),
  checkRunId: uuid("check_run_id"),
  capturedAt: ts("captured_at").notNull().defaultNow(),
});

export const findingStatusHistory = pgTable("finding_status_history", {
  id: uuid("id").primaryKey().defaultRandom(),
  orgId: uuid("org_id").notNull(),
  findingId: uuid("finding_id").notNull(),
  fromStatus: text("from_status").$type<FindingStatus>(),
  toStatus: text("to_status").$type<FindingStatus>().notNull(),
  actorType: text("actor_type").$type<"user" | "service">().notNull(),
  actorId: text("actor_id").notNull(),
  reason: text("reason"),
  createdAt: ts("created_at").notNull().defaultNow(),
});

export const riskAcceptances = pgTable("risk_acceptances", {
  id: uuid("id").primaryKey().defaultRandom(),
  orgId: uuid("org_id").notNull(),
  findingId: uuid("finding_id").notNull(),
  justification: text("justification").notNull(),
  compensatingControls: text("compensating_controls").notNull(),
  expiresAt: ts("expires_at").notNull(),
  acceptedBy: uuid("accepted_by").notNull(),
  createdAt: ts("created_at").notNull().defaultNow(),
  revokedAt: ts("revoked_at"),
  revokedBy: uuid("revoked_by"),
  expiredAt: ts("expired_at"),
});

export const findingComments = pgTable("finding_comments", {
  id: uuid("id").primaryKey().defaultRandom(),
  orgId: uuid("org_id").notNull(),
  findingId: uuid("finding_id").notNull(),
  authorId: uuid("author_id").notNull(),
  body: text("body").notNull(),
  mentions: uuid("mentions").array().notNull().default([]),
  createdAt: ts("created_at").notNull().defaultNow(),
});

export const usageRecords = pgTable("usage_records", {
  id: uuid("id").primaryKey().defaultRandom(),
  orgId: uuid("org_id").notNull(),
  kind: text("kind").notNull(),
  sourceId: uuid("source_id").notNull(),
  quantity: integer("quantity").notNull().default(1),
  period: text("period").notNull(),
  createdAt: ts("created_at").notNull().defaultNow(),
});

export const killSwitches = pgTable("kill_switches", {
  id: uuid("id").primaryKey().defaultRandom(),
  orgId: uuid("org_id").notNull(),
  assetId: uuid("asset_id"),
  which: text("which").$type<"scanning" | "ai">().notNull(),
  engaged: boolean("engaged").notNull(),
  reason: text("reason").notNull(),
  actorId: uuid("actor_id").notNull(),
  createdAt: ts("created_at").notNull().defaultNow(),
});

// ---------- P6: verification & FixProof (0005_verification_fixproof.sql) ----------

export type VerificationRunStatus = "queued" | "running" | "completed" | "not_run";
export type VerificationOutcome = "verified" | "partially_verified" | "failed" | "unverified";
export type CheckVerdict = "passed" | "failed" | "inconclusive" | "error";
export interface VerificationCheckResult {
  checkId: string; engineVersion: string; status: CheckVerdict; reason: string | null;
  evidenceId: string | null; evidenceSha256: string | null; sameVersionAsDetection: boolean | null; requests: number;
}
export type VerificationTrigger = "manual" | "scheduled_regression";
export const verificationRuns = pgTable("verification_runs", {
  id: uuid("id").primaryKey().defaultRandom(),
  orgId: uuid("org_id").notNull(),
  findingId: uuid("finding_id").notNull(),
  assetId: uuid("asset_id").notNull(),
  status: text("status").$type<VerificationRunStatus>().notNull().default("queued"),
  outcome: text("outcome").$type<VerificationOutcome>(),
  reason: text("reason"),
  results: jsonb("results").$type<VerificationCheckResult[]>().notNull().default([]),
  requestedBy: uuid("requested_by"),
  trigger: text("trigger").$type<VerificationTrigger>().notNull().default("manual"),
  idempotencyKey: text("idempotency_key").notNull(),
  fixproofId: uuid("fixproof_id"),
  attempts: integer("attempts").notNull().default(0),
  createdAt: ts("created_at").notNull().defaultNow(),
  startedAt: ts("started_at"),
  finishedAt: ts("finished_at"),
});

export const fixproofRecords = pgTable("fixproof_records", {
  id: uuid("id").primaryKey(),
  orgId: uuid("org_id").notNull(),
  seq: bigint("seq", { mode: "number" }).notNull(),
  findingId: uuid("finding_id").notNull(),
  verificationRunId: uuid("verification_run_id").notNull(),
  version: integer("version").notNull(),
  status: text("status").$type<VerificationOutcome>().notNull(),
  content: jsonb("content").$type<Record<string, unknown>>().notNull(),
  sha256: text("sha256").notNull(),
  prevSha256: text("prev_sha256"),
  createdAt: ts("created_at").notNull().defaultNow(),
  supersededAt: ts("superseded_at"),
  supersededReason: text("superseded_reason").$type<"newer_verification" | "regression">(),
});

// ---------- P4: AI analysis (0006_ai.sql) ----------

export type AiUseCase = "explain" | "remediation" | "chat";
export type AiStatus = "completed" | "inconclusive" | "rejected" | "unavailable";
export type AiClaimType = "observation" | "inference" | "recommendation";
export type AiConfidence = "confirmed" | "likely" | "possible";
export interface AiInputRef { sourceType: "finding" | "evidence" | "check_definition"; id: string; sha256: string }

export const aiEvalRuns = pgTable("ai_eval_runs", {
  id: uuid("id").primaryKey().defaultRandom(),
  promptId: text("prompt_id").notNull(),
  promptVersion: integer("prompt_version").notNull(),
  templateSha256: text("template_sha256").notNull(),
  provider: text("provider").notNull(),
  model: text("model").notNull(),
  metrics: jsonb("metrics").$type<Record<string, number>>().notNull(),
  thresholds: jsonb("thresholds").$type<Record<string, number>>().notNull(),
  passed: boolean("passed").notNull(),
  createdAt: ts("created_at").notNull().defaultNow(),
});

export const aiPromptReleases = pgTable("ai_prompt_releases", {
  promptId: text("prompt_id").notNull(),
  promptVersion: integer("prompt_version").notNull(),
  templateSha256: text("template_sha256").notNull(),
  provider: text("provider").notNull(),
  model: text("model").notNull(),
  evalRunId: uuid("eval_run_id").notNull(),
  releasedAt: ts("released_at").notNull().defaultNow(),
}, (t) => [primaryKey({ columns: [t.promptId, t.promptVersion, t.provider, t.model] })]);

export const aiAnalyses = pgTable("ai_analyses", {
  id: uuid("id").primaryKey().defaultRandom(),
  orgId: uuid("org_id").notNull(),
  findingId: uuid("finding_id").notNull(),
  useCase: text("use_case").$type<AiUseCase>().notNull(),
  promptId: text("prompt_id").notNull(),
  promptVersion: integer("prompt_version").notNull(),
  schemaVersion: text("schema_version").notNull(),
  redactionVersion: text("redaction_version").notNull(),
  provider: text("provider").notNull(),
  model: text("model").notNull(),
  inputSha256: text("input_sha256").notNull(),
  inputs: jsonb("inputs").$type<AiInputRef[]>().notNull(),
  status: text("status").$type<AiStatus>().notNull(),
  summary: text("summary"),
  uncertainty: text("uncertainty"),
  missingEvidence: jsonb("missing_evidence").$type<string[]>().notNull().default([]),
  droppedClaims: integer("dropped_claims").notNull().default(0),
  flags: jsonb("flags").$type<string[]>().notNull().default([]),
  tokensIn: integer("tokens_in").notNull().default(0),
  tokensOut: integer("tokens_out").notNull().default(0),
  latencyMs: integer("latency_ms").notNull().default(0),
  error: text("error"),
  requestedBy: uuid("requested_by").notNull(),
  idempotencyKey: text("idempotency_key").notNull(),
  /** Chat turns only (0020): the redacted question and the thread it belongs to. */
  question: text("question"),
  threadId: uuid("thread_id"),
  createdAt: ts("created_at").notNull().defaultNow(),
});

export const aiClaims = pgTable("ai_claims", {
  id: uuid("id").primaryKey().defaultRandom(),
  orgId: uuid("org_id").notNull(),
  analysisId: uuid("analysis_id").notNull(),
  ordinal: integer("ordinal").notNull(),
  type: text("type").$type<AiClaimType>().notNull(),
  text: text("text").notNull(),
  evidenceIds: uuid("evidence_ids").array().notNull(),
  confidenceLabel: text("confidence_label").$type<AiConfidence>().notNull(),
  verificationCheckIds: text("verification_check_ids").array().notNull().default([]),
  steps: jsonb("steps").$type<string[]>().notNull().default([]),
  approvalRequired: boolean("approval_required").notNull().default(false),
});

// ---------- P5: remediation and approvals (0007_remediation.sql) ----------

export type PlanType = "guided" | "patch";
export type PlanState =
  | "draft" | "proposed" | "sandbox_testing" | "test_passed" | "test_failed" | "awaiting_approval" | "approved" | "rejected"
  | "change_submitted" | "applied_by_customer" | "merged_observed" | "closed_unmerged" | "verifying" | "completed" | "remediation_failed";
export type SandboxResult = "test_passed" | "test_failed" | "apply_failed" | "timeout" | "error";
export type ApprovalPolicy = "two_person" | "single_approver";
export type ApprovalState = "pending" | "approved" | "rejected" | "expired" | "invalidated" | "revoked" | "consumed";
export type CodeChangeState = "pending" | "open" | "merged" | "closed" | "failed";
export type RepoScope = "contents:read" | "pull_requests:write" | "metadata:read";

export const repositoryIntegrations = pgTable("repository_integrations", {
  id: uuid("id").primaryKey().defaultRandom(),
  orgId: uuid("org_id").notNull(),
  type: text("type").$type<"local_git">().notNull(),
  name: text("name").notNull(),
  externalId: text("external_id").notNull(),
  defaultBranch: text("default_branch").notNull().default("main"),
  scopes: text("scopes").$type<RepoScope>().array().notNull(),
  testCommands: jsonb("test_commands").$type<string[][]>().notNull().default([]),
  status: text("status").$type<"active" | "disabled">().notNull().default("active"),
  createdBy: uuid("created_by").notNull(),
  createdAt: ts("created_at").notNull().defaultNow(),
});

export const remediationPlans = pgTable("remediation_plans", {
  id: uuid("id").primaryKey().defaultRandom(),
  orgId: uuid("org_id").notNull(),
  findingId: uuid("finding_id").notNull(),
  type: text("type").$type<PlanType>().notNull(),
  state: text("state").$type<PlanState>().notNull().default("draft"),
  title: text("title").notNull(),
  description: text("description").notNull(),
  affectedComponents: jsonb("affected_components").$type<string[]>().notNull().default([]),
  rollbackNotes: text("rollback_notes").notNull().default(""),
  verificationChecks: text("verification_checks").array().notNull().default([]),
  integrationId: uuid("integration_id"),
  baseCommit: text("base_commit"),
  diff: text("diff"),
  diffSha256: text("diff_sha256"),
  contentSha256: text("content_sha256").notNull(),
  version: integer("version").notNull().default(1),
  aiAnalysisId: uuid("ai_analysis_id"),
  aiClaimId: uuid("ai_claim_id"),
  createdBy: uuid("created_by").notNull(),
  updatedBy: uuid("updated_by").notNull(),
  idempotencyKey: text("idempotency_key").notNull(),
  createdAt: ts("created_at").notNull().defaultNow(),
  updatedAt: ts("updated_at").notNull().defaultNow(),
});

export const remediationPlanHistory = pgTable("remediation_plan_history", {
  id: uuid("id").primaryKey().defaultRandom(),
  orgId: uuid("org_id").notNull(),
  planId: uuid("plan_id").notNull(),
  fromState: text("from_state").$type<PlanState>(),
  toState: text("to_state").$type<PlanState>().notNull(),
  contentSha256: text("content_sha256").notNull(),
  actorType: text("actor_type").$type<"user" | "service">().notNull(),
  actorId: text("actor_id").notNull(),
  reason: text("reason"),
  details: jsonb("details").$type<Record<string, unknown>>().notNull().default({}),
  createdAt: ts("created_at").notNull().defaultNow(),
});

export const sandboxRuns = pgTable("sandbox_runs", {
  id: uuid("id").primaryKey().defaultRandom(),
  orgId: uuid("org_id").notNull(),
  planId: uuid("plan_id").notNull(),
  patchSha256: text("patch_sha256").notNull(),
  contentSha256: text("content_sha256").notNull(),
  baseCommit: text("base_commit").notNull(),
  status: text("status").$type<"queued" | "running" | "completed">().notNull().default("queued"),
  result: text("result").$type<SandboxResult>(),
  reason: text("reason"),
  isolation: text("isolation").notNull(),
  limits: jsonb("limits").$type<Record<string, number>>().notNull(),
  commands: jsonb("commands").$type<string[][]>().notNull(),
  exitCode: integer("exit_code"),
  egressBlocked: boolean("egress_blocked").notNull().default(true),
  logsEvidenceId: uuid("logs_evidence_id"),
  requestedBy: uuid("requested_by").notNull(),
  idempotencyKey: text("idempotency_key").notNull(),
  createdAt: ts("created_at").notNull().defaultNow(),
  startedAt: ts("started_at"),
  finishedAt: ts("finished_at"),
});

export const approvals = pgTable("approvals", {
  id: uuid("id").primaryKey().defaultRandom(),
  orgId: uuid("org_id").notNull(),
  subjectType: text("subject_type").$type<"remediation_plan">().notNull(),
  subjectId: uuid("subject_id").notNull(),
  subjectSha256: text("subject_sha256").notNull(),
  policy: text("policy").$type<ApprovalPolicy>().notNull(),
  untestedOverride: boolean("untested_override").notNull().default(false),
  sandboxRunId: uuid("sandbox_run_id"),
  requesterId: uuid("requester_id").notNull(),
  requestNote: text("request_note"),
  state: text("state").$type<ApprovalState>().notNull().default("pending"),
  approverId: uuid("approver_id"),
  selfApproved: boolean("self_approved").notNull().default(false),
  decisionReason: text("decision_reason"),
  authTime: ts("auth_time"),
  sessionRef: text("session_ref"),
  decidedAt: ts("decided_at"),
  expiresAt: ts("expires_at").notNull(),
  consumedAt: ts("consumed_at"),
  revokedBy: uuid("revoked_by"),
  revokedAt: ts("revoked_at"),
  endReason: text("end_reason"),
  idempotencyKey: text("idempotency_key").notNull(),
  createdAt: ts("created_at").notNull().defaultNow(),
});

export const codeChanges = pgTable("code_changes", {
  id: uuid("id").primaryKey().defaultRandom(),
  orgId: uuid("org_id").notNull(),
  planId: uuid("plan_id").notNull(),
  approvalId: uuid("approval_id").notNull(),
  integrationId: uuid("integration_id").notNull(),
  diffSha256: text("diff_sha256").notNull(),
  baseCommit: text("base_commit").notNull(),
  branch: text("branch").notNull(),
  headSha: text("head_sha"),
  prUrl: text("pr_url"),
  state: text("state").$type<CodeChangeState>().notNull().default("pending"),
  mergeSha: text("merge_sha"),
  error: text("error"),
  createdAt: ts("created_at").notNull().defaultNow(),
  observedAt: ts("observed_at"),
});

export const repositoryWebhookDeliveries = pgTable("repository_webhook_deliveries", {
  id: uuid("id").primaryKey().defaultRandom(),
  orgId: uuid("org_id").notNull(),
  integrationId: uuid("integration_id").notNull(),
  deliveryId: text("delivery_id").notNull(),
  event: text("event").notNull(),
  receivedAt: ts("received_at").notNull().defaultNow(),
});

// P7: WebMonitor referrals (provisional adapter shape, DEP-WM-01) and consent records.
export type ReferralStatus = "pending_consent" | "consented" | "declined" | "deleted" | "expired";
export const webmonitorReferrals = pgTable("webmonitor_referrals", {
  id: uuid("id").primaryKey().defaultRandom(),
  orgId: uuid("org_id"),
  externalRef: text("external_ref").notNull(),
  nonce: text("nonce").notNull(),
  payloadSha256: text("payload_sha256").notNull(),
  signalType: text("signal_type").notNull(),
  host: text("host").notNull(),
  observedAt: ts("observed_at").notNull(),
  summary: text("summary").notNull().default(""),
  status: text("status").$type<ReferralStatus>().notNull().default("pending_consent"),
  tokenHash: text("token_hash").notNull(),
  expiresAt: ts("expires_at").notNull(),
  consumedAt: ts("consumed_at"),
  claimedBy: uuid("claimed_by"),
  shareStatus: boolean("share_status").notNull().default(false),
  assessmentId: uuid("assessment_id"),
  receivedAt: ts("received_at").notNull().defaultNow(),
  decidedAt: ts("decided_at"),
});

export type ConsentSubject = "referral_assessment" | "referral_charges" | "referral_share_status" | "referral_declined";
export const consents = pgTable("consents", {
  id: uuid("id").primaryKey().defaultRandom(),
  orgId: uuid("org_id").notNull(),
  subject: text("subject").$type<ConsentSubject>().notNull(),
  textVersion: text("text_version").notNull(),
  userId: uuid("user_id").notNull(),
  referralId: uuid("referral_id").notNull(),
  createdAt: ts("created_at").notNull().defaultNow(),
});

export const referralEvents = pgTable("referral_events", {
  id: uuid("id").primaryKey().defaultRandom(),
  orgId: uuid("org_id").notNull(),
  referralId: uuid("referral_id").notNull(),
  kind: text("kind").$type<"result_published" | "result_not_sent">().notNull(),
  summary: jsonb("summary").$type<Record<string, unknown>>().notNull(),
  reason: text("reason"),
  createdAt: ts("created_at").notNull().defaultNow(),
});

// ---------- P8: reporting & hardening ----------
const bytea = customType<{ data: Buffer; driverData: Buffer }>({ dataType: () => "bytea" });

export const notifications = pgTable("notifications", {
  id: uuid("id").primaryKey().defaultRandom(),
  orgId: uuid("org_id").notNull(),
  userId: uuid("user_id").notNull(),
  kind: text("kind").notNull(),
  title: text("title").notNull(),
  link: text("link"),
  securityCritical: boolean("security_critical").notNull().default(false),
  sourceId: uuid("source_id"),
  createdAt: ts("created_at").notNull().defaultNow(),
  readAt: ts("read_at"),
});

export const notificationPrefs = pgTable("notification_prefs", {
  orgId: uuid("org_id").notNull(),
  userId: uuid("user_id").notNull(),
  kind: text("kind").notNull(),
  email: boolean("email").notNull().default(true),
  inApp: boolean("in_app").notNull().default(true),
}, (t) => [primaryKey({ columns: [t.orgId, t.userId, t.kind] })]);

export const reports = pgTable("reports", {
  id: uuid("id").primaryKey().defaultRandom(),
  orgId: uuid("org_id").notNull(),
  createdBy: uuid("created_by").notNull(),
  format: text("format").$type<"csv" | "pdf">().notNull(),
  clientGroupId: uuid("client_group_id"),
  params: jsonb("params").$type<Record<string, unknown>>().notNull().default({}),
  sha256: text("sha256").notNull(),
  sizeBytes: integer("size_bytes").notNull(),
  content: bytea("content").notNull(),
  createdAt: ts("created_at").notNull().defaultNow(),
});

export type TokenScope = "findings:read" | "assets:read" | "reports:generate";
export const apiTokens = pgTable("api_tokens", {
  id: uuid("id").primaryKey().defaultRandom(),
  orgId: uuid("org_id").notNull(),
  userId: uuid("user_id").notNull(),
  name: text("name").notNull(),
  prefix: text("prefix").notNull(),
  tokenHash: text("token_hash").notNull(),
  scopes: text("scopes").array().$type<TokenScope[]>().notNull(),
  expiresAt: ts("expires_at").notNull(),
  createdAt: ts("created_at").notNull().defaultNow(),
  revokedAt: ts("revoked_at"),
  lastUsedAt: ts("last_used_at"),
});

export const webmonitorWatchedHosts = pgTable("webmonitor_watched_hosts", {
  orgId: uuid("org_id").notNull(),
  host: text("host").notNull(),
  tokenId: uuid("token_id"),
  firstSeenAt: ts("first_seen_at").notNull().defaultNow(),
  lastSeenAt: ts("last_seen_at").notNull().defaultNow(),
}, (t) => [primaryKey({ columns: [t.orgId, t.host] })]);

export const breakGlassSessions = pgTable("break_glass_sessions", {
  id: uuid("id").primaryKey().defaultRandom(),
  orgId: uuid("org_id").notNull(),
  operatorUserId: uuid("operator_user_id").notNull(),
  reason: text("reason").notNull(),
  startedAt: ts("started_at").notNull().defaultNow(),
  expiresAt: ts("expires_at").notNull(),
  endedAt: ts("ended_at"),
});

export const auditChainAnchors = pgTable("audit_chain_anchors", {
  id: bigserial("id", { mode: "number" }).primaryKey(),
  orgId: uuid("org_id").notNull(),
  seq: bigint("seq", { mode: "number" }).notNull(),
  hash: text("hash").notNull(),
  purgedCount: bigint("purged_count", { mode: "number" }).notNull(),
  createdAt: ts("created_at").notNull().defaultNow(),
});

export const ctCache = pgTable("ct_cache", {
  domain: text("domain").primaryKey(),
  source: text("source").notNull(),
  fetchedAt: ts("fetched_at").notNull(),
  truncated: boolean("truncated").notNull().default(false),
  entries: jsonb("entries").notNull(),
});

export type SuggestionStatus = "suggested" | "added" | "dismissed";
export const assetSuggestions = pgTable("asset_suggestions", {
  id: uuid("id").primaryKey().defaultRandom(),
  orgId: uuid("org_id").notNull(),
  sourceAssetId: uuid("source_asset_id"),
  host: text("host").notNull(),
  source: text("source").notNull().default("ct"),
  status: text("status").$type<SuggestionStatus>().notNull().default("suggested"),
  firstSeen: ts("first_seen").notNull().defaultNow(),
  lastSeen: ts("last_seen").notNull().defaultNow(),
  decidedBy: uuid("decided_by"),
  decidedAt: ts("decided_at"),
});

// ---------- 0022 attack-origin monitoring ----------
export type AttackSourceKind = "cloudflare" | "log_agent";
export type AttackSourceStatus = "pending" | "active" | "error" | "disabled";
export const attackSources = pgTable("attack_sources", {
  id: uuid("id").primaryKey().defaultRandom(),
  orgId: uuid("org_id").notNull(),
  assetId: uuid("asset_id").notNull(),
  kind: text("kind").$type<AttackSourceKind>().notNull(),
  name: text("name").notNull(),
  cfZoneId: text("cf_zone_id"),
  cfTokenEnc: text("cf_token_enc"),
  ingestTokenHash: text("ingest_token_hash"),
  ingestPrefix: text("ingest_prefix"),
  status: text("status").$type<AttackSourceStatus>().notNull().default("pending"),
  cursorAt: ts("cursor_at"),
  nextPollAt: ts("next_poll_at"),
  lastPolledAt: ts("last_polled_at"),
  lastEventAt: ts("last_event_at"),
  lastError: text("last_error"),
  createdBy: uuid("created_by").notNull(),
  createdAt: ts("created_at").notNull().defaultNow(),
});

export const attackEvents = pgTable("attack_events", {
  id: bigserial("id", { mode: "number" }).primaryKey(),
  orgId: uuid("org_id").notNull(),
  assetId: uuid("asset_id").notNull(),
  sourceId: uuid("source_id").notNull(),
  occurredAt: ts("occurred_at").notNull(),
  ip: text("ip").notNull(),
  country: text("country"),
  asn: integer("asn"),
  asOrg: text("as_org"),
  action: text("action").notNull(),
  attackType: text("attack_type").notNull(),
  ruleId: text("rule_id"),
  method: text("method"),
  path: text("path"),
  statusCode: integer("status_code"),
  userAgent: text("user_agent"),
  dedupeKey: text("dedupe_key").notNull(),
  createdAt: ts("created_at").notNull().defaultNow(),
});
