// Single source of truth for RuyaShield v2.0 specification content.
const C = 'Confirmed from existing PRD', R = 'Recommended addition', Q = 'Open question';
const L = { C, R, Q };

const meta = {
  product: 'RuyaShield', parent: 'RuyaLab', version: '2.0', date: '2026-10-29',
  status: 'Implementation-ready specification (proposed) — no application code written yet',
  owner: 'Product & Engineering',
  history: [
    ['1.0', 'Not supplied', 'Original PRD (not available for this review)', 'Product & Engineering'],
    ['1.1', 'Not dated in source', 'Updated scope; WebMonitor limited to integration/acquisition channel', 'Product & Engineering'],
    ['2.0', '2026-10-29', 'Audit of v1.1; roles & permission matrix; 16 epics with stories; state machines; AI, FixProof and WebMonitor specs; architecture, data model, API/event contracts (proposed); QA & security test plan; phased implementation plan; traceability; decision log', 'Product & Engineering (draft prepared with AI assistance — requires human review and approval)'],
  ],
};

// ---------- PRD audit ----------
const audit = [
  // id, area, observation, impact, resolution in v2.0, severity
  ['AUD-01','Roles','v1.1 requires RBAC (FR-003) but defines no roles or permissions.','RBAC cannot be built or tested; approval separation of duties is undefined.','Defined 7 roles and a permission matrix (§4). Approver ≠ requester by default.','High'],
  ['AUD-02','FixProof states','v1.1 uses verified / partially verified / failed / unverified; the master prompt asks for pass / fail / inconclusive / not-run.','Two vocabularies would cause inconsistent UI, API and reporting.','Two levels: VerificationRun result = passed | failed | inconclusive | error | not_run; FixProof overall status = verified | partially_verified | failed | unverified, with a deterministic mapping (§9).','High'],
  ['AUD-03','Authorization','Domain ownership verification and "documented authorization" are required but methods, expiry and agency-on-behalf-of-client cases are unspecified.','Highest-risk control (unauthorized scanning) has no implementable definition.','DNS TXT, HTTP well-known file and HTML meta tag methods; signed authorization attestation; expiry and periodic re-verification; check action classes (§7, EPIC SCOPE).','Critical'],
  ['AUD-04','Check classes','Passive vs active checks are not distinguished; v1.1 blocks "active scanning" until verification but does not define active.','Teams may run active probes on unverified assets, or block harmless passive checks.','Action classes: P (passive, third-party data only), A1 (active-safe, non-mutating HTTP/TLS/DNS), A2 (active-extended, needs approval), X (prohibited). Verification required for A1/A2.','Critical'],
  ['AUD-05','Scanner','First scanner is an open decision ("select an established engine after technical and licensing evaluation").','Assessment epic cannot finalize check catalogue.','Kept as decision D-01. Provisional adapter interface defined; candidates listed for evaluation only — no selection claimed.','Medium'],
  ['AUD-06','Repository integration','"Authorized repository integrations" named but no provider chosen; required permissions undefined.','PR workflow cannot be designed or threat-modelled.','Decision D-06 (provisional: GitHub App first). Integration requests only contents:read + pull_requests:write; never merge/admin.','Medium'],
  ['AUD-07','"Apply" semantics','v1.1 requires approval "before merge or production deployment" but does not say whether RuyaShield merges or deploys.','Ambiguity about whether the product ever holds deploy privileges.','MVP: RuyaShield never merges or deploys. It opens a PR after approval; humans merge/deploy outside RuyaShield; RuyaShield observes merge and runs verification.','High'],
  ['AUD-08','Sandbox','"Isolated environments" required but runtime, egress, lifetime and artifact handling unspecified.','RCE risk from executing customer code and AI patches.','Sandbox spec (§11.6): ephemeral container/microVM, no prod credentials, deny-by-default egress with package-registry allowlist, CPU/mem/disk/time caps, artifacts out only.','High'],
  ['AUD-09','Priorities','Agency persona is primary, yet agency workspaces (FR-007) are P1 while agency branding appears in MVP scope.','MVP may not satisfy the primary buyer.','Client groups inside one organization promoted to P0 (FR-008-style split: FR-007 client groups P0, branding P1). See decision D-09.','Medium'],
  ['AUD-10','Priorities','Finding deduplication (FR-015) is P1, but MVP scope lists "duplicate handling", and verification needs to match a finding across runs.','Verification and FixProof cannot reliably identify "the same finding".','Fingerprint-based dedup promoted to P0; cross-tool correlation stays P1.','High'],
  ['AUD-11','Priorities','Regression monitoring (FR-036) and result linkage (FR-043) are P1 while MVP scope mentions recurrence checks and result linkage.','Scope disagreement.','Kept P1 as in the FR table; MVP scope wording reinterpreted as "where supported, post-MVP". Flagged as decision D-10.','Low'],
  ['AUD-12','Billing','FR-041 requires consent to charges (P0) but billing appears only in Phase 5.','Consent to charges with no billing system.','MVP records explicit consent and enforces plan quotas; payment collection is manual (invoice) during invite-only pilot. No billing implementation in MVP.','Medium'],
  ['AUD-13','Incident journey','Journey 10.3 depends on gathering application/infrastructure evidence (logs) — no log ingestion exists in MVP scope; SIEM is out of scope.','Journey is unimplementable in MVP.','Journey 10.3 marked Phase-later (P2). MVP supports only manual evidence notes and the four-way classification on findings.','Medium'],
  ['AUD-14','Severity / confidence','Separate severity and confidence required but scales undefined; "model confidence is not calibrated".','Inconsistent prioritization and misleading confidence.','Severity: critical/high/medium/low/info (+ source severity, optional CVSS vector). Confidence: confirmed/likely/suspected/unknown, derived from evidence type, never from model self-report alone.','High'],
  ['AUD-15','Tamper evidence','Change history auditable (FR-037) but no integrity mechanism.','FixProof records could be altered without detection.','Recommended: append-only audit table + SHA-256 hash chain + FixProof content hash. Described as tamper-evident, not immutable. Optional WORM storage is decision D-11.','Medium'],
  ['AUD-16','Metrics','Pilot target "Fix verification recorded: 100% of fixes marked verified" is ambiguous (reads as 100% of fixes must be verified).','Wrong incentive: pressure to mark fixes verified.','Restated: 100% of fixes with status "verified" have linked passing verification evidence.','Low'],
  ['AUD-17','AI provenance','Structured outputs required but no versioning of prompts/models, no cost controls, no fallback when AI is unavailable.','Unreproducible AI output; outages block workflow.','AI spec (§8): prompt/model/version registry, input hash, token budget, schema validation, deterministic fallback; core workflow never depends on AI.','High'],
  ['AUD-18','WebMonitor contract','WebMonitor integration required but no API, payload, auth or event contract is provided.','Risk of inventing endpoints.','Provisional adapter interface only (§10); real contract is dependency DEP-WM-01.','Medium'],
  ['AUD-19','Kill switch','No emergency stop for scanning or AI.','Cannot contain an abuse incident quickly.','FR-060 global / per-org / per-asset kill switch (P0).','High'],
  ['AUD-20','Data retention','8.1 requires retention/deletion rules but none are defined.','Privacy and storage cost risk.','Provisional retention table (§12) labelled assumptions; FR-056.','Medium'],
  ['AUD-21','MFA','No MFA requirement although approvers can trigger PRs to customer repositories.','Account takeover leads to malicious approved changes.','FR-008: MFA required for org admin, security lead, approver; step-up for approvals.','High'],
  ['AUD-22','Service identities','No machine identities defined for workers/integrations.','Over-privileged workers.','Service identity role with per-worker scoped credentials (§4).','Medium'],
  ['AUD-23','Release gates','Release blockers listed but not mapped to tests.','Gates cannot be evaluated objectively.','RB-01..RB-06 mapped to test cases and phase gates G0–G7 (§16, traceability).','Medium'],
  ['AUD-24','Roadmap','6 phases with calendar durations; master prompt requires 8 phases with relative sizing.','—','8 phases with T-shirt sizes; v1.1 durations retained only as historical reference.','Low'],
  ['AUD-25','Requirement IDs','FR numbering has gaps (008–009, 018–019, 028–029, 038–039).','None — but new requirements must not collide.','v1.1 IDs preserved unchanged; new requirements use gap numbers and FR-046+, FR-050+; each marked "Recommended addition".','Low'],
  ['AUD-26','Pricing','Prices are hypotheses (stated in v1.1).','Risk of publishing unvalidated pricing.','Kept as hypotheses; no pricing logic in MVP beyond plan quotas.','Low'],
];

// ---------- Requirements ----------
// [id, title, statement/acceptance, priority, label, epic, phase]
const requirements = [
  ['FR-001','User authentication','Users sign in securely and access only authorized workspaces.','P0',C,'IAM','P1'],
  ['FR-002','Organization management','Users can create and manage an organization.','P0',C,'IAM','P1'],
  ['FR-003','Role-based access','Permissions are enforced server-side, per the v2.0 permission matrix.','P0',C,'IAM','P1'],
  ['FR-004','Asset ownership verification','Active scanning is blocked until required authorization checks pass.','P0',C,'ASSET','P1'],
  ['FR-005','Scan authorization','Scope, scan type, authorization, and limits are recorded.','P0',C,'SCOPE','P2'],
  ['FR-006','Audit logging','Sensitive actions record actor, timestamp, and outcome.','P0',C,'AUDIT','P1'],
  ['FR-007','Agency workspaces (client groups)','Users can manage client workspaces without cross-client data leakage. v2.0: client groups with group-scoped membership are P0; white-label branding stays P1.','P0',C+' (priority raised P1→P0, see AUD-09)','IAM','P1'],
  ['FR-008','MFA for privileged roles','Org admin, security lead and approver roles require MFA; approval decisions require authentication within the last 15 minutes (step-up).','P0',R,'IAM','P1'],
  ['FR-009','Invitations and session management','Invitations expire (7 days, assumption), sessions are revocable, membership removal revokes access within 60 s.','P0',R,'IAM','P1'],
  ['FR-010','Asset registration','A user can add and verify an authorized domain.','P0',C,'ASSET','P1'],
  ['FR-011','Scan orchestration','Approved scan jobs are queued, executed, and tracked.','P0',C,'ASSESS','P2'],
  ['FR-012','Rate/resource limits','Concurrency, duration, and request limits are enforced.','P0',C,'ASSESS','P2'],
  ['FR-013','Evidence capture','Every finding has a source, timestamp, and relevant evidence.','P0',C,'FIND','P2'],
  ['FR-014','Severity and confidence','Severity and confidence are represented separately using the v2.0 scales.','P0',C,'FIND','P2'],
  ['FR-015','Finding deduplication','Repeated detections can be linked to existing findings. v2.0: fingerprint dedup P0; cross-tool correlation P1.','P0',C+' (priority raised P1→P0 for fingerprint dedup, see AUD-10)','FIND','P2'],
  ['FR-016','Scan cancellation','Authorized users can cancel queued and eligible running scans.','P0',C,'ASSESS','P2'],
  ['FR-017','Failure handling','Failed or incomplete scans are never shown as clean scans.','P0',C,'ASSESS','P2'],
  ['FR-018','Assessment scope definition','Scope lists hostnames, base URLs, excluded paths, allowed check classes, time window, request budget; scope is versioned and immutable once used by an assessment.','P0',R,'SCOPE','P2'],
  ['FR-019','Check catalogue and action classes','Every check declares action class (P/A1/A2/X), version, timeout, request budget and whether it supports verification. Class X checks cannot be enabled.','P0',R,'SCOPE','P2'],
  ['FR-020','Evidence summarization','AI summaries do not invent missing details.','P0',C,'AI','P4'],
  ['FR-021','Root-cause hypotheses','Unconfirmed causes are explicitly labelled as hypotheses.','P0',C,'AI','P4'],
  ['FR-022','Remediation guidance','Recommendations identify affected components and next steps.','P0',C,'AI','P4'],
  ['FR-023','Evidence references','Material claims link to findings or tool results.','P0',C,'AI','P4'],
  ['FR-024','Uncertainty reporting','Insufficient evidence produces an inconclusive status.','P0',C,'AI','P4'],
  ['FR-025','Diagnostic plan','AI can recommend safe, authorized follow-up checks (recommendation only; launching requires a user and normal authorization).','P1',C,'AI','P4'],
  ['FR-026','Customer context','Approved architecture and history inform recommendations.','P1',C,'AI','P4'],
  ['FR-027','AI evaluation','Recommendations are tested against a versioned evaluation set before each model or prompt release.','P0',C,'AI','P4'],
  ['FR-028','AI output schema and provenance','All AI output is schema-validated; each output stores model id, prompt version, input hash, token usage and evidence references; claims are typed observation | inference | recommendation.','P0',R,'AI','P4'],
  ['FR-029','AI-optional degraded mode','If AI is disabled, over budget or unavailable, findings, remediation (manual), approvals, verification and FixProof still work.','P0',R,'AI','P4'],
  ['FR-030','Proposed remediation','Users review a fix before implementation.','P0',C,'REMED','P5'],
  ['FR-031','Isolated testing','Proposed code runs without production credentials or unrestricted egress.','P0',C,'REMED','P5'],
  ['FR-032','Human approval','AI cannot alone trigger production changes. Approval is bound to the exact patch hash; approver ≠ requester by default.','P0',C,'APPR','P5'],
  ['FR-033','Verification checks','Relevant authorized checks rerun after a fix.','P0',C,'FIXP','P6'],
  ['FR-034','Verification status','Fixes are labelled verified, failed, partially verified, or unverified (FixProof status) derived from run results passed/failed/inconclusive/error/not_run.','P0',C,'FIXP','P6'],
  ['FR-035','FixProof','Reports state exactly what was tested and the supporting evidence, including what was not tested.','P0',C,'FIXP','P6'],
  ['FR-036','Regression monitoring','Supported findings can be rechecked on a schedule.','P1',C,'FIXP','P7'],
  ['FR-037','Change history','Proposals, approvals, and outcomes are auditable.','P0',C,'AUDIT','P5'],
  ['FR-038','False-positive and accepted-risk workflows','Marking false positive requires justification; accepted risk requires security lead, justification and expiry (max 365 days, assumption). Both are audited and reversible.','P0',C+' (MVP scope §4.1; ID added)','RISK','P3'],
  ['FR-039','FixProof export','FixProof exports as JSON and PDF with a SHA-256 content hash that can be re-verified.','P0',C+' (MVP scope "exportable record"; ID added)','FIXP','P6'],
  ['FR-040','Contextual referral','A relevant WebMonitor finding opens the appropriate workflow.','P0',C,'WMON','P7'],
  ['FR-041','Consent before assessment','User explicitly authorizes assessment and associated charges.','P0',C,'WMON','P7'],
  ['FR-042','Context handoff','Only necessary authorized event details are transferred.','P0',C,'WMON','P7'],
  ['FR-043','Result linkage','Results can be associated with the originating monitoring event.','P1',C,'WMON','P7'],
  ['FR-044','Referral attribution','Conversions and referrals can be measured.','P1',C,'WMON','P7'],
  ['FR-045','Partner referrals','Approved third-party services can be offered with transparent disclosures.','P2',C,'WMON','Later'],
  ['FR-046','WebMonitor provisional adapter','Inbound referrals are accepted only via a signed, replay-protected handoff matching the provisional adapter interface; no WebMonitor endpoint is assumed.','P0',R,'WMON','P7'],
  ['FR-050','Security dashboard','Dashboard shows open findings by severity, assessment health (including failed/incomplete), remediation pipeline and verification state.','P0',C+' (MVP scope §4.1; ID added)','DASH','P8'],
  ['FR-051','Notifications','Configurable email/in-app notifications for assignment, approval requests, verification results, failed assessments, expiring authorizations.','P0',C+' (MVP scope; ID added)','DASH','P8'],
  ['FR-052','Downloadable reports','Assessment and finding reports downloadable as PDF/CSV, stating coverage limits; agency branding P1.','P0',C+' (MVP scope; ID added)','DASH','P8'],
  ['FR-053','Comments and assignment','Findings and remediation plans support owner assignment, due dates and comments with mentions.','P1',R,'COLLAB','P3'],
  ['FR-054','Audit log viewer and export','Org admins and security leads can search and export audit events.','P0',C+' (MVP "audit trail"; ID added)','AUDIT','P8'],
  ['FR-055','Tamper-evident history','Audit events and FixProof records are hash-chained; a verification job detects breaks and alerts.','P0',R,'AUDIT','P6'],
  ['FR-056','Retention and deletion','Evidence and reports follow configurable retention; org deletion purges tenant data within 30 days (assumption).','P1',C+' (§8.1 control; ID added)','PLAT','P8'],
  ['FR-057','Plan quotas and usage metering','Per-org limits on assets, assessments/month, AI tokens and sandbox minutes are enforced; usage metered idempotently. No payment processing in MVP.','P0',R,'ADMIN','P2'],
  ['FR-058','Platform operator console','RuyaLab operators can view tenant health and act via audited, time-boxed, customer-visible break-glass access.','P1',R,'ADMIN','P8'],
  ['FR-059','Scoped API tokens','Org-scoped API tokens for CI/service use with least-privilege scopes and expiry.','P1',R,'IAM','P8'],
  ['FR-060','Kill switch','Global, per-org and per-asset switches immediately stop new scans, AI calls and sandbox runs; running jobs abort within 60 s.','P0',R,'PLAT','P2'],
  ['FR-061','Repository integration','Connect a repository with least-privilege scopes (read contents, open PRs; never merge or admin); credentials stored in secrets manager.','P0',C+' (MVP "authorized repository integrations"; ID added)','REMED','P5'],
];

// Security requirements (v1.1 §8.1/8.2 + additions)
const secReqs = [
  ['SEC-01','Authentication and server-side authorization on every route and job.',C],
  ['SEC-02','Tenant isolation at API and database layers (org_id on all tenant rows + PostgreSQL row-level security).',C],
  ['SEC-03','Domain ownership or documented authorization before active scanning.',C],
  ['SEC-04','SSRF prevention: block cloud metadata, private/link-local/loopback ranges, non-scope destinations; DNS re-resolution pinning.',C],
  ['SEC-05','Scan budgets, timeouts, concurrency and request limits.',C],
  ['SEC-06','Isolation of scanners and test environments.',C],
  ['SEC-07','Least-privilege IAM and short-lived credentials.',C],
  ['SEC-08','Encryption in transit (TLS 1.2+) and at rest (KMS).',C],
  ['SEC-09','Protection of sessions, API keys and integration credentials (secrets manager, never in DB plaintext, never sent to AI).',C],
  ['SEC-10','Auditable records of sensitive operations.',C],
  ['SEC-11','Dependency scanning and secret detection in CI.',C],
  ['SEC-12','Tested backups and recovery.',C],
  ['SEC-13','Vulnerability disclosure and incident response procedures.',C],
  ['SEC-14','Retention and deletion rules for customer evidence.',C],
  ['SEC-15','No arbitrary command execution from model output.',C],
  ['SEC-16','Never execute customer uploads on the application server.',C],
  ['SEC-17','No production credentials in sandboxes.',C],
  ['SEC-18','Restricted outbound network from workers (egress guard).',C],
  ['SEC-19','Disposable environments with CPU, memory, disk and time limits.',C],
  ['SEC-20','Explicit target scope for every active assessment.',C],
  ['SEC-21','Approval before changes leave the sandbox.',C],
  ['SEC-22','Untrusted content (websites, repos, logs, WebMonitor payloads, AI output) is data, never instructions; tool policy enforced outside the model.',C],
  ['SEC-23','Secrets and personal data redacted before AI calls.',R],
  ['SEC-24','Webhook/handoff signatures (HMAC-SHA256), timestamp tolerance 5 min, nonce replay protection.',R],
  ['SEC-25','Rate limiting on auth and API (per IP and per token).',R],
  ['SEC-26','Security headers and CSP on the RuyaShield app itself.',R],
];

const releaseBlockers = [
  ['RB-01','Known unresolved critical security defect.',C],
  ['RB-02','Material cross-tenant data exposure.',C],
  ['RB-03','Ability to scan unauthorized targets through normal product workflows.',C],
  ['RB-04','AI can deploy production changes without required approval.',C],
  ['RB-05','Failed scans can be misrepresented as clean scans.',C],
  ['RB-06','FixProof can claim verification without test evidence.',C],
  ['RB-07','Inconclusive, error or not-run verification displayed or exported as passed/verified.',R],
  ['RB-08','AI output accepted without schema validation or able to invoke tools directly.',R],
];

// ---------- Roles & permissions ----------
const roles = [
  ['org_admin','Org admin','Manages organization, members, billing contact, integrations, policies. Cannot bypass approval separation unless explicit single-approver policy is set (audited).','MFA required'],
  ['security_lead','Security lead','Owns security programme: approves asset authorizations and A2 checks, accepts risk, approves remediation, manages AI settings.','MFA required'],
  ['analyst','Analyst','Runs assessments within approved scope, triages findings, requests AI analysis, prepares remediation plans, requests verification.','MFA recommended'],
  ['developer','Developer / remediation owner','Works assigned findings, writes/edits remediation plans and patches, runs sandbox tests, requests approval, marks guided fixes applied.','MFA recommended'],
  ['approver','Approver','Approves or rejects remediation plans and patches bound to an exact hash. Typically a tech lead or client representative.','MFA + step-up required'],
  ['viewer','Read-only stakeholder','Views dashboards, findings, FixProof and reports for permitted client groups. No evidence raw download by default.','—'],
  ['service','Service identity','Non-human: workers, integrations, API tokens. Scoped to one function and one org (or platform worker with job-signed scope). Cannot approve.','Short-lived credentials'],
];
// permission matrix: resource/action rows; columns order of roles
// values: Y = allowed, S = allowed within assigned client groups/own items, A = allowed but requires approval/second person, N = denied, Sys = system/service only
const permCols = ['org_admin','security_lead','analyst','developer','approver','viewer','service'];
const permissions = [
  ['Organization','Edit settings, policies, delete org','Y','N','N','N','N','N','N'],
  ['Members','Invite / change roles / remove','Y','N','N','N','N','N','N'],
  ['Assets','Create / edit asset','Y','Y','S','N','N','N','N'],
  ['Assets','Start ownership verification','Y','Y','S','N','N','N','Sys'],
  ['Assets','Record authorization attestation','Y','Y','N','N','N','N','N'],
  ['Assets','View','Y','Y','S','S','S','S','Sys'],
  ['Assessment config','Create / edit scope (P, A1 checks)','Y','Y','S','N','N','N','N'],
  ['Assessment config','Enable A2 (active-extended) checks','A','A','N','N','N','N','N'],
  ['Assessment config','Launch / cancel assessment','Y','Y','S','N','N','N','Sys (schedules)'],
  ['Findings','View findings & redacted evidence','Y','Y','S','S','S','S','Sys'],
  ['Findings','Triage / confirm / change severity','Y','Y','S','N','N','N','N'],
  ['Findings','Mark false positive','Y','Y','S','N','N','N','N'],
  ['Findings','Accept risk','Y','Y','N','N','N','N','N'],
  ['Findings','Assign owner / comment','Y','Y','S','S (comment)','S (comment)','N','N'],
  ['Evidence','Download raw evidence','Y','Y','S','S','N','N','Sys'],
  ['AI','Request analysis on finding','Y','Y','S','S','N','N','N'],
  ['AI','Configure AI (enable/disable, budget, provider)','Y','Y','N','N','N','N','N'],
  ['Remediation','Create / edit plan or patch','Y','Y','S','S','N','N','Sys (AI draft)'],
  ['Remediation','Run sandbox test','Y','Y','S','S','N','N','Sys'],
  ['Remediation','Request approval','Y','Y','S','S','N','N','N'],
  ['Approvals','Approve / reject (not own request)','A*','Y','N','N','Y','N','N'],
  ['Approvals','Set single-approver policy','Y','N','N','N','N','N','N'],
  ['Remediation','Open PR (after approval)','N','N','N','N','N','N','Sys'],
  ['Remediation','Mark guided fix as applied','Y','Y','S','S','N','N','N'],
  ['Verification','Request verification run','Y','Y','S','S','N','N','Sys (schedules)'],
  ['Verification','Set verification result','N','N','N','N','N','N','Sys'],
  ['FixProof','View / export','Y','Y','S','S','S','S','N'],
  ['Reports','Generate / download','Y','Y','S','N','S','S','N'],
  ['Integrations','Connect / revoke repository, WebMonitor','Y','Y','N','N','N','N','N'],
  ['Audit','View / export audit log','Y','Y','N','N','N','N','N'],
  ['Kill switch','Org-level stop scanning / AI','Y','Y','N','N','N','N','N'],
];
const permLegend = 'Y = allowed; S = allowed only for assets/client groups the member is assigned to (or own items); A = allowed but needs a second person (A2 enablement needs both security lead and org admin, or two security leads); A* = org admin may approve only if also not the requester; Sys = system/service identity only; N = denied. Viewer access to raw evidence is denied by default. Platform operators have no tenant access except audited break-glass (FR-058).';

// ---------- Epics ----------
// id, name, objective, problem, scope, nonGoals, deps, priority, outcome, risks, phase
const epics = [
  ['IAM','Identity, organizations & access','Secure sign-in, organizations, client groups, RBAC and MFA.','Without enforced roles and tenancy every other control is meaningless.','Auth via established provider (OIDC), orgs, memberships, invitations, client groups, roles, MFA/step-up, sessions.','Building a custom identity provider; SSO/SAML (P2); SCIM.','None','P0','0 cross-tenant/BOLA failures in security test suite; 100% routes behind policy layer.','Misconfigured provider; BOLA on nested resources.','P1'],
  ['ASSET','Asset registration & ownership verification','Register websites/APIs and prove control or documented authorization.','Scanning unverified targets is illegal/harmful and a release blocker.','Asset CRUD, hostname normalization, DNS TXT/HTTP file/meta verification, attestation, expiry & re-verification.','Network ranges/CIDR scanning; internal hosts; mobile apps.','IAM','P0','0 active checks against unverified assets; verification success ≥90% first attempt (assumption).','DNS propagation delays; subdomain takeover of verified hosts; shared hosting.','P1'],
  ['SCOPE','Assessment scope & authorization','Explicit, versioned scope and check catalogue with action classes.','"Authorized" must be machine-enforceable per request, not a checkbox.','Scope objects, check catalogue, action classes, A2 approvals, scope versioning, time windows, budgets.','Arbitrary custom payloads; authenticated scanning with customer credentials (P2).','ASSET','P0','100% of worker requests pass the scope check; 0 out-of-scope requests in egress logs.','Redirects to out-of-scope hosts; DNS rebinding.','P2'],
  ['ASSESS','Assessment orchestration & execution','Queue, run, track, cancel and fail assessments safely and transparently.','Scans that silently fail are reported as clean (release blocker).','Assessment lifecycle, workers, scanner adapter, egress guard, limits, retries, cancellation, kill switch.','Proprietary scanner; destructive/exploit checks; distributed scanning.','SCOPE, PLAT','P0','Acknowledgement <5 s P95; 0 failed/partial runs displayed as clean.','Scanner licensing; target overload; cost.','P2'],
  ['FIND','Findings & evidence','Normalized, deduplicated, evidence-backed findings with separate severity/confidence.','Raw scanner output is noisy, duplicated and hard to trust.','Normalization, fingerprinting, occurrences, evidence store with hashes, severity/confidence scales, lifecycle.','Cross-tool ML correlation (P1+); automatic severity overrides by AI.','ASSESS','P0','100% findings have source+timestamp+evidence; duplicate rate <5% on test corpus (assumption).','Fingerprint instability across scanner versions.','P3'],
  ['AI','AI investigation assistant','Evidence-bound explanations, hypotheses and remediation guidance with provenance.','Users need understanding, but ungrounded AI is dangerous.','AI gateway, redaction, prompt registry, schemas, claim typing, evaluation harness, budgets, fallback.','Chatbot UI; autonomous tool use; AI-triggered scans or changes.','FIND','P0','≥95% evidence-backed recommendations on eval set; 0 unsupported compromise claims.','Hallucination; prompt injection; provider cost.','P4'],
  ['RISK','Triage, false positive & accepted risk','Prioritize findings and record justified decisions not to fix.','Teams need a defensible way to close non-actionable findings.','Triage, priority scoring, FP workflow, accepted risk with expiry, re-detection behavior.','Automated risk scoring by AI alone.','FIND','P0','100% FP/accepted-risk decisions have actor + justification; expired acceptances re-open automatically.','Abuse of accepted risk to hide issues.','P3'],
  ['REMED','Remediation planning & sandbox testing','Reviewable plans and patches tested in isolation; PRs opened only after approval.','Fixes are slow and AI patches are risky.','Guided plans, patch proposals, repo integration, sandbox runner, PR creation, merge observation.','Merging or deploying; non-git delivery; arbitrary stack support.','FIND, AI, APPR, PLAT','P0','0 changes leave sandbox without approval; sandbox escape tests pass.','Sandbox escape; supply-chain via package installs.','P5'],
  ['APPR','Approvals & separation of duties','Hash-bound, auditable human approval for changes and elevated checks.','"AI cannot alone trigger production changes" needs a concrete control.','Approval requests, eligibility, step-up, hash binding, expiry, invalidation, revocation, policies.','Multi-stage CAB workflows (P2).','IAM','P0','100% submitted changes trace to a valid approval of the identical patch hash.','Approver fatigue; social engineering.','P5'],
  ['FIXP','Verification & FixProof','Independently verify fixes and produce honest, exportable, tamper-evident proof.','Customers need evidence a specific issue was addressed.','Verification runs, result mapping, FixProof assembly, hashing, export, reopening, regression schedule (P1).','Claims of overall site security; third-party attestations.','ASSESS, FIND, REMED','P0','0 FixProof "verified" without passing evidence; 100% failed verifications reopen findings.','Checks that cannot verify a fix type.','P6'],
  ['WMON','WebMonitor integration','Convert relevant WebMonitor signals into consented, authorized RuyaShield workflows.','Acquisition channel without consent/authorization controls creates abuse risk.','Provisional adapter, signed handoff, referral landing, consent, minimal context, linkage (P1), attribution (P1).','Building WebMonitor features; inventing its API.','IAM, ASSET, SCOPE','P0','100% referral-initiated assessments have consent + authorization records.','Contract unknown (DEP-WM-01).','P7'],
  ['DASH','Dashboard, notifications & reporting','Honest overview, alerts and downloadable reports.','Non-specialists and clients need understandable outputs.','Dashboard, notification preferences, PDF/CSV reports, coverage statements, branding (P1).','BI tool; custom report builder.','FIND, FIXP','P0','Dashboard P95 <500 ms; every report includes coverage/limitations section.','Over-claiming in client-facing reports.','P8'],
  ['COLLAB','Collaboration & assignment','Owners, due dates, comments and mentions on findings/plans.','Work stalls without ownership.','Assignment, due dates, comments, mentions, activity feed.','Generic project management, chat, ticket tracker (integration P2).','FIND','P1','Median time-to-assign reduced (baseline in pilot).','Scope creep into PM tooling.','P3'],
  ['AUDIT','Audit trail & tamper evidence','Complete, searchable, tamper-evident record of sensitive actions.','Trust requires reconstructing who did what.','Audit event schema, append-only store, hash chain, viewer, export, integrity check.','SIEM; legal hold workflows (P2).','PLAT','P0','100% sensitive actions in catalogue emit audit events (contract test).','Log volume; PII in logs.','P1'],
  ['PLAT','Platform, security & operations','Infrastructure, isolation, observability, kill switch, backups, CI security.','Controls must exist below the application layer.','Environments, IaC, queues, egress guard infra, secrets, logging/metrics/tracing, backups, CI scans, kill switch, retention jobs.','Kubernetes; multi-region active-active.','—','P0','Backup restore tested; CI blocks critical vulns/secrets.','Misconfiguration; cost overrun.','P1'],
  ['ADMIN','Plans, quotas & platform administration','Enforce plan limits and support operations without billing implementation.','Costs (scanner, AI, sandbox) must be bounded during pilot.','Plans config, quota enforcement, idempotent usage metering, operator console (P1), break-glass.','Payment processing, invoicing, tax (post-MVP).','IAM, PLAT','P0','0 duplicate usage records under retry tests; quota enforced before job enqueue.','Under-metering AI cost.','P2'],
];

// ---------- Decisions ----------
// id, decision, recommendation, status/label, owner, needed by, impact
const decisions = [
  ['D-01','First scanner engine','Evaluate established engines (e.g. OWASP ZAP baseline/passive mode, ProjectDiscovery Nuclei with curated non-intrusive templates, testssl.sh) for licensing, coverage of MVP checks, determinism for verification, and safe modes. Select one primary engine plus native TLS/header/DNS checks.',Q,'Tech lead + security engineer','Gate G0','Blocks ASSESS check catalogue'],
  ['D-02','Database access layer','Prisma or Drizzle — choose based on RLS/session-variable support and migration tooling. Provisional: Drizzle (simpler SQL control for RLS).',Q,'Tech lead','Gate G0','FOUNDATION schema'],
  ['D-03','Queue technology','AWS SQS + DLQ (as v1.1) with transactional outbox. Confirm.',C,'Tech lead','Gate G0','ASSESS, REMED'],
  ['D-04','Identity provider','Established provider supporting OIDC, MFA, step-up (e.g. managed auth service). Evaluate cost and data residency.',Q,'Tech lead','Gate G0','IAM'],
  ['D-05','Worker runtime','Containers on AWS Fargate/ECS tasks for scan & verification workers; sandbox runtime needs stronger isolation (Firecracker-based microVM or gVisor). Evaluate.',Q,'DevOps + security','Gate G1','PLAT, REMED'],
  ['D-06','First repository provider','GitHub App first (fine-grained permissions); GitLab later.',Q,'Product owner','Gate G4','REMED'],
  ['D-07','AI provider(s)','Provider-agnostic adapter (v1.1). Select first provider by eval-set score, data handling terms (no training on customer data), cost.',Q,'AI engineer','Gate G3','AI'],
  ['D-08','Single-approver policy','Default requires a different approver; allow org-admin opt-in "single-approver" for small agencies, flagged in audit and FixProof.',R,'Product owner + security','Gate G4','APPR'],
  ['D-09','Agency model','Client groups within one org (P0) vs separate orgs per client. Recommend client groups; cross-org agency hierarchy P2.',R,'Product owner','Gate G0','IAM'],
  ['D-10','MVP recurrence monitoring','Keep FR-036/FR-043 P1 (post-MVP) unless pilot partners require it.',Q,'Product owner','Gate G5','FIXP, WMON'],
  ['D-11','WORM storage for FixProof exports','Optional S3 Object Lock (compliance mode) for exported FixProof; adds cost/irreversibility. Until decided, describe as tamper-evident only.',Q,'Security + product','Gate G5','FIXP'],
  ['D-12','Data residency','Single AWS region for pilot (provisional: ap-south-1 given INR pricing). Confirm with pilot customers.',Q,'Product owner','Gate G0','PLAT'],
  ['D-13','Pilot payments','Manual invoicing during invite-only pilot; billing system post-MVP.',R,'Product owner','Gate G0','ADMIN'],
  ['D-14','WebMonitor contract','Obtain actual API/event contract from WebMonitor team; until then build to provisional adapter.',Q,'Product owner','Gate G6','WMON'],
  ['D-15','Evidence redaction policy','Default redaction of cookies, auth headers, tokens, emails, phone numbers in stored evidence views and AI inputs.',R,'Security','Gate G2','FIND, AI'],
  ['D-16','A2 checks in MVP','Recommend shipping MVP with P and A1 only; A2 framework built but no A2 checks enabled until security review.',R,'Security','Gate G2','SCOPE'],
];

// ---------- NFRs ----------
// id, category, target, measurement, label
const nfrs = [
  ['NFR-01','Availability','99.5% monthly for web app & API (excluding announced maintenance ≤4 h/month).','Synthetic probe every 1 min from 2 locations.',C+' (target); exclusions = '+R],
  ['NFR-02','Dashboard performance','P95 < 500 ms server time for dashboard reads at pilot workload (≤50 orgs, ≤2,000 assets, ≤200k findings — assumption).','APM traces; k6 load test at G7.',C+' (target); workload = '+R],
  ['NFR-03','Scan acknowledgement','Accepted assessment returns 202 with id within 5 s P99; queued→running median < 60 s (assumption).','API metrics; queue age metric.',C],
  ['NFR-04','Scan reliability','Each check has timeout (default 120 s, max 600 s) and assessment budget (default 30 min). 100% of failed/partial runs labelled as such.','Contract tests + chaos tests killing workers.',C],
  ['NFR-05','Pilot scale','Validate ≥100 assets before scaling review; design headroom 10× pilot.','Load test report.',C],
  ['NFR-06','Idempotency','All POST mutations accept Idempotency-Key (24 h retention); queue consumers idempotent; no duplicate jobs, findings, usage records.','Retry/duplicate-delivery tests.',C],
  ['NFR-07','Security release gate','No open critical/high security defect at release; pen test of app before commercial launch.','Defect tracker; pen test report.',C+' (critical); high = '+R],
  ['NFR-08','Auditability','100% of actions in the audit catalogue emit events within 5 s; audit retention 1 year minimum (assumption).','Audit contract tests.',C],
  ['NFR-09','Privacy','Collect only email, name, role for users; evidence redacted by default; no customer data used for model training.','Data inventory review at G0/G7.',C],
  ['NFR-10','Recovery','RPO ≤ 1 h, RTO ≤ 4 h (assumption); restore tested before commercial launch and quarterly.','Restore drill record.',C+' (tested recovery); RPO/RTO = '+R],
  ['NFR-11','Accessibility','WCAG 2.2 AA for core workflows (onboarding, findings, approvals, FixProof).','axe automated + manual keyboard/screen-reader review.',C],
  ['NFR-12','Maintainability','Typed APIs (OpenAPI 3.1 generated), ≥80% line coverage on policy/state-machine modules (assumption), ADRs for significant decisions.','CI coverage report.',C],
  ['NFR-13','Portability','AI, scanner, repository, identity and WebMonitor behind adapters with contract tests.','Adapter contract test suites.',C],
  ['NFR-14','AI latency & cost','AI analysis P95 < 60 s async; per-org monthly AI token budget enforced; per-analysis cap (assumption 30k input tokens).','AI gateway metrics.',R],
  ['NFR-15','Kill switch latency','New work blocked immediately; running jobs aborted ≤ 60 s.','Game-day test.',R],
  ['NFR-16','Target safety','Default ≤ 5 requests/s and ≤ 2 concurrent connections per target host (assumption); honour 429/503 back-off.','Egress guard metrics.',R],
  ['NFR-17','Observability','Structured JSON logs with trace id, org id (no secrets); RED metrics per route & queue; alerting on DLQ depth, error rate, egress denials.','Dashboards exist before G7.',C+' (v1.1 stack); specifics = '+R],
];

// ---------- Risks (v1.1 + additions) ----------
const risks = [
  ['RK-01','Crowded market','High','Focus on a defined buyer and verified remediation workflow.',C],
  ['RK-02','False positives','High','Evidence-backed findings, evaluation, and human review.',C],
  ['RK-03','Missed vulnerabilities','High','Define coverage limits and use independent validation; reports state coverage.',C],
  ['RK-04','Unsafe AI patch','High','Isolated testing, review, approval, and rollback procedures.',C],
  ['RK-05','Prompt injection','High','Treat external content as untrusted and enforce tool policies.',C],
  ['RK-06','SSRF/scanner abuse','Critical','Ownership verification, destination validation, egress controls, isolation.',C],
  ['RK-07','Data leakage','Critical','Tenant isolation, encryption, least privilege, minimal retention.',C],
  ['RK-08','High scanning costs','Medium','Quotas, caching where appropriate, and cost monitoring.',C],
  ['RK-09','Low willingness to pay','High','Run paid pilots before extensive development.',C],
  ['RK-10','Third-party dependency','Medium','Replaceable adapters and provider evaluation.',C],
  ['RK-11','Misleading security claims','High','State coverage limitations and use evidence-based reporting.',C],
  ['RK-12','Excessive scope','High','Keep MVP focused on investigation, remediation, and verification.',C],
  ['RK-13','Agency authorizes scans of client sites it does not control','Critical','Attestation with signatory details + technical verification; abuse reporting channel; kill switch.',R],
  ['RK-14','Sandbox escape / supply-chain during dependency install','High','MicroVM/gVisor isolation, registry allowlist, no secrets, ephemeral, egress logged.',R],
  ['RK-15','Approver account takeover','High','MFA + step-up, hash-bound approvals, notifications to org admins on approval.',R],
  ['RK-16','WebMonitor contract changes / unavailability','Medium','Provisional adapter, versioned contract, feature flag.',R],
];

// ---------- Phases & gates ----------
// id, name, size, objective, deliverables, epics, exit gate id, gate criteria
const phases = [
  ['P0','Discovery','M','Validate problem, buyer and technical approach.','15–20 agency interviews; scanner evaluation (D-01); AI provider eval (D-07); threat model; data inventory; ADRs 1–8 signed; pilot partner LOIs.','—','G0','Decisions D-01, D-02, D-04, D-09, D-12, D-13 closed; threat model reviewed; ≥3 design partners committed.'],
  ['P1','Foundation','L','Secure multi-tenant base.','IAM, orgs, client groups, RBAC policy layer, MFA, assets + verification, audit log + hash chain, outbox/queue, CI security, IaC, observability baseline.','IAM, ASSET, AUDIT, PLAT','G1','All P0 IAM/ASSET/AUDIT tests pass; BOLA/cross-tenant suite green; independent security review of policy layer; RB-02 cleared.'],
  ['P2','Core assessment','L','Authorized, safe, transparent assessments.','Scope & check catalogue, egress guard, scan workers, scanner adapter, limits, cancellation, failure handling, kill switch, quotas.','SCOPE, ASSESS, ADMIN, PLAT','G2','SSRF/egress suite green; 0 out-of-scope requests in controlled tests; failed/partial never shown clean (RB-03, RB-05 cleared).'],
  ['P3','Findings & triage','M','Trustworthy, deduplicated findings and decisions.','Normalization, fingerprinting, evidence store, severity/confidence, triage, FP/accepted risk, assignment/comments.','FIND, RISK, COLLAB','G3a','Reproducible findings on a fixed test target corpus; dedup tests green.'],
  ['P4','AI investigation','M','Evidence-bound AI assistance.','AI gateway, redaction, prompt registry, schemas, claim typing, evaluation harness, fallback mode.','AI','G3','Eval set: ≥95% evidence-backed, 0 unsupported compromise claims, 0 successful injection-induced policy violations (RB-08 cleared).'],
  ['P5','Remediation & approvals','L','Safe, approved change proposals.','Remediation plans, repo integration, sandbox runner, approvals with hash binding, PR creation, merge observation, change history.','REMED, APPR','G4','Sandbox isolation tests green; 100% PRs trace to approvals (RB-04 cleared); independent security review.'],
  ['P6','Verification & FixProof','M','Honest verification and proof.','Verification runs, result mapping, reopening, FixProof assembly, hashing, export, integrity check.','FIXP, AUDIT','G5','RB-06, RB-07 cleared; FixProof export re-verification passes.'],
  ['P7','WebMonitor integration','S–M','Consented referral funnel.','Provisional adapter, signed handoff, referral landing, consent, minimal context; linkage/attribution (P1).','WMON','G6','Signature/replay suite green; 100% referral assessments have consent + authorization; contract (D-14) confirmed or adapter behind flag.'],
  ['P8','Reporting & hardening','L','Production readiness for invite-only paid pilot.','Dashboard, notifications, reports, audit viewer/export, retention jobs, load/perf tests, restore drill, external pen test, runbooks, docs.','DASH, AUDIT, PLAT, ADMIN','G7','All release blockers RB-01..RB-08 cleared; NFR-02/03/10 met; pen test criticals fixed; production readiness review approved.'],
];
const mvpDefinition = [
  'Smallest coherent MVP = phases P1–P6 plus the P0 parts of P8 (dashboard, notifications, reports, audit viewer) — i.e. gates G1–G5 and G7. WebMonitor (P7) is the first post-MVP increment unless a pilot partner arrives via WebMonitor; FR-040–042/046 are P0 for the WebMonitor launch, not for the first private pilot.',
  'MVP user journey: create org → invite team → register asset → verify ownership → define scope (P/A1 checks only) → run assessment → review evidence-backed findings → AI explanation (optional) → plan fix → sandbox test (patch) or guided steps → approval → PR opened → customer merges → verification → FixProof export.',
  'Explicitly not in MVP: A2 checks enabled (framework only), regression schedules (FR-036), WebMonitor linkage/attribution (FR-043/044), partner referrals (FR-045), branding, SSO, billing, log ingestion/incident journey 10.3.',
];
const phaseDeps = [['P0','P1'],['P1','P2'],['P2','P3'],['P3','P4'],['P3','P5'],['P4','P5'],['P5','P6'],['P2','P7'],['P1','P7'],['P6','P8'],['P7','P8']];

const glossary = [
  ['Action class','Classification of a check by its effect on the target: P passive, A1 active-safe, A2 active-extended (needs approval), X prohibited.'],
  ['Assessment','One execution of a set of checks against an asset within a fixed scope version.'],
  ['Asset','A registered website or API base URL (hostname + scheme) owned by an organization.'],
  ['Attestation','A signed statement by an authorized person that the organization may test an asset, including signatory, relationship and expiry.'],
  ['BOLA','Broken object-level authorization — accessing another tenant\'s object by ID.'],
  ['Check','A versioned, deterministic test (e.g. TLS expiry, HSTS header) implemented natively or via a scanner adapter.'],
  ['Client group','A subset of an organization\'s assets and members representing one agency client.'],
  ['Confidence','How sure RuyaShield is that a finding is real: confirmed, likely, suspected, unknown. Independent of severity.'],
  ['Egress guard','Proxy all worker traffic must pass through; enforces scope, blocks private/metadata IPs, rate-limits.'],
  ['Evidence item','Stored raw or derived artifact (request/response excerpt, certificate, DNS record, tool output) with SHA-256 hash.'],
  ['Finding','A deduplicated security issue on an asset identified by a stable fingerprint; has one or more occurrences.'],
  ['Fingerprint','Hash of check id + normalized location + issue key used to match occurrences across runs.'],
  ['FixProof','Exportable, hash-protected record of a finding\'s remediation and verification, stating what was and was not tested.'],
  ['Inconclusive','A result where the evidence is insufficient to decide pass or fail. Never displayed as passed.'],
  ['Kill switch','Control that stops new scans/AI/sandbox work and aborts running jobs at global, org or asset level.'],
  ['Observation / Inference / Recommendation','AI claim types: observation = restates evidence; inference = hypothesis derived from evidence; recommendation = suggested action.'],
  ['Outbox','Transactional table from which events are reliably published to the queue.'],
  ['Sandbox','Ephemeral isolated environment for running customer code and proposed patches with no production credentials.'],
  ['Scope (version)','Immutable snapshot of what may be tested: hosts, paths, exclusions, check classes, window, budget.'],
  ['Severity','Potential impact of a finding: critical, high, medium, low, info.'],
  ['Step-up authentication','Fresh re-authentication (incl. MFA) required immediately before a sensitive action.'],
  ['Tamper-evident','Modification can be detected (hash chain mismatch); not the same as immutable.'],
  ['Verification run','Re-execution of the same check (same id and version) to determine whether a fix worked.'],
];

const factsVsAssumptions = {
  facts: [
    'v1.1 defines RuyaShield scope, 37 functional requirements (FR-001..FR-045 with gaps), AI guardrails, stack proposal, NFR targets, risks, roadmap and open decisions.',
    'v1.1 names WebMonitor as a related RuyaLab product used as an integration and acquisition channel.',
    'v1.1 states pricing, pilot targets and timelines are hypotheses/estimates, not commitments.',
    'No application code, scanner selection, customer validation, certification or WebMonitor API contract exists in the supplied material.',
  ],
  assumptions: [
    'Agencies managing 10–200 client sites will pay for verified remediation workflow (v1.1 hypothesis BO-01; unvalidated).',
    'GitHub is the most common repository host among target agencies (unvalidated; D-06).',
    'MVP checks (TLS, headers, DNS, passive exposure, dependency manifests) are sufficient to deliver value in pilot (unvalidated).',
    'Pilot workload: ≤50 orgs, ≤2,000 assets (assumption for NFR sizing).',
    'Customers accept that RuyaShield opens PRs but never merges/deploys (to validate in discovery).',
    'INR pricing implies India-first pilot; data residency to be confirmed (D-12).',
  ],
};

module.exports = { L, meta, audit, requirements, secReqs, releaseBlockers, roles, permCols, permissions, permLegend, epics, decisions, nfrs, risks, phases, mvpDefinition, phaseDeps, glossary, factsVsAssumptions };
