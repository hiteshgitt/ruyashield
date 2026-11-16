// Technical-spec data for RuyaShield PRD v2.0. Labels: C = Confirmed from existing PRD, R = Recommended addition, Q = Open question.
const { L } = require('./data_core.js');
const C = L.C, R = L.R, Q = L.Q;

// ---------- 1. Strategy ----------
const vision = {
  vision: 'RuyaShield is an AI-assisted cybersecurity platform that helps organizations identify security weaknesses, understand their impact, investigate relevant evidence, prepare safe fixes, and verify remediation. Its primary value is the end-to-end remediation workflow, not simply producing a list of scanner findings.',
  visionLabel: C + ' (v1.1 §1.1, verbatim)',
  positioning: 'For web development agencies that maintain many client websites, RuyaShield is the authorized, evidence-first remediation workflow — find → explain → fix safely → prove the fix (FixProof). It is not a generic vulnerability scanner, not a chatbot, not an autonomous penetration-testing agent and not an IT management suite.',
  positioningLabel: R,
  problems: [
    'Security alerts are spread across monitoring, scanning, cloud, and application tools. (' + C + ')',
    'Developers spend time distinguishing urgent issues from low-priority or duplicate findings. (' + C + ')',
    'Agencies struggle to show clients evidence that issues were actually fixed — scanner exports do not prove remediation. (' + R + ', to be validated in discovery)',
  ],
  principles: [
    'Evidence before claims.', 'Authorization before scanning.', 'Read-only by default.', 'Human approval before production changes.',
    'Independent verification before marking a fix verified.', 'Least privilege and tenant isolation throughout.',
    'Transparent limitations and no blanket security guarantees.', 'Measure verified outcomes, not scan volume.',
  ],
};

const personas = [
  ['Primary', 'Web development agency owner', 'Manages a portfolio of client sites; needs evidence of ongoing maintenance value and client-ready reports.', 'org_admin / approver', C],
  ['Secondary', 'Technical lead or senior developer', 'Triages findings, prepares and reviews fixes, wants low noise and reproducible evidence.', 'security_lead / developer', C],
  ['Secondary', 'SMB owner or IT manager', 'Has limited access to security specialists; needs plain-language explanations and safe defaults.', 'org_admin / viewer', C],
  ['Future', 'Managed service provider', 'Operates many tenants; needs delegated administration and scale — post-MVP.', '—', C + ' (future segment)'],
];

const scopeIn = [
  ['Organization and asset management', 'Orgs, members, roles, client groups, asset registration, ownership verification, authorization attestation, scan limits, audit history.', C],
  ['Security assessment', 'Passive and active-safe checks (TLS certificate/expiry, security headers, DNS/email posture, exposure checks) through one established scanner engine (D-01) plus native checks.', C],
  ['Findings and risk management', 'Normalized findings, evidence, severity + confidence, dedup, false-positive and accepted-risk workflows.', C],
  ['AI-assisted investigation', 'Evidence-bound explanations, hypotheses, prioritized remediation recommendations — optional, never required for the core workflow.', C],
  ['Controlled remediation', 'Proposed code or configuration changes, tested in isolated sandboxes, approval-gated pull requests. RuyaShield never merges or deploys.', C + ' (PR-only clarified by AUD-07)'],
  ['FixProof', 'Original finding and evidence, change reference, approval, verification evidence, status, integrity hash, export.', C],
  ['WebMonitor integration', 'Minimal context handoff and result linkage through a provisional adapter (DEP-WM-01). Post-MVP phase P7.', C + ' (phase per §17)'],
  ['Reporting and notifications', 'Dashboard, notifications, downloadable report with coverage state, audit trail for sensitive actions.', C],
];
const scopeOut = [
  ['Autonomous exploitation of customer systems.', C],
  ['Autonomous production changes or deployments; RuyaShield merging PRs.', C],
  ['Automated destructive penetration testing; A2 checks are flag-off in MVP (D-16); X checks are never available.', C],
  ['Building a proprietary scanner from scratch.', C],
  ['Testing any asset that is not verified or attested and in an approved scope.', R],
  ['Generic AI chatbot, free-form agent with tools, SIEM/log ingestion, general IT management, social-media/marketing products.', R],
  ['Billing/payment integration (manual invoicing during invite-only pilot).', R + ' (AUD-12)'],
  ['Compliance certification claims of any kind.', R],
];

const objectives = [
  ['BO-01', 'Validate a paying segment', 'At least 3 paid pilot organizations.', C],
  ['BO-02', 'Reduce investigation effort', 'At least 30% investigation-time reduction vs a measured customer baseline.', C],
  ['BO-03', 'Improve remediation completion', 'Help customers implement and verify fixes; measured as verified remediations per active org.', C],
  ['BO-04', 'Create recurring revenue', 'Establish a sustainable subscription model (pricing hypotheses only; no billing in MVP).', C],
  ['BO-05', 'Enable WebMonitor cross-sell', 'Referral click-through and conversion measurable after P7.', C],
  ['BO-06', 'Build durable product value', 'FixProof history and verified outcomes as the retained asset.', C],
  ['BO-07', 'Establish trust', 'Zero unauthorized scans; zero unauthorized production changes; honest status everywhere.', C],
];

const metrics = [
  ['Design-partner organizations', 'Recruit 5 agencies with active client-site portfolios', 'Pilot CRM', C],
  ['Paid pilot organizations', '≥ 3', 'Signed pilot agreements', C],
  ['Traceable findings', '100%', 'Every delivered finding has a source check version, timestamp and evidence reference (automated query).', C],
  ['Evidence-backed AI recommendations', '≥ 95%', 'Manually reviewed eval set (TC-AIEVAL-001).', C],
  ['Critical findings reviewed before delivery', '100%', 'Critical findings require analyst triage before inclusion in client reports.', C],
  ['Unauthorized production changes by AI', '0', 'Enforced by architecture: no merge/deploy capability exists (RB-03).', C],
  ['Fix verification integrity', '100% of fixes with status "verified" have linked passing verification evidence', 'Automated integrity query on fixproof_records (restated, AUD-16).', C + ' (restated)'],
  ['Investigation time reduction', '≥ 30%', 'Time-to-diagnosis vs customer baseline measured in discovery.', C],
  ['Material false-positive rate', '< 10% (initial)', 'Analyst adjudication of a sampled set.', C],
  ['Unauthorized scans', '0', 'Egress-guard and authorization audit (RB-01).', C],
  ['North-star', 'Verified remediations per active paying organization', 'Monthly, with security-quality guardrails; raw scan volume is not a success metric.', C],
];

const kpis = [
  ['Acquisition', 'Signup conversion, WebMonitor-to-RuyaShield click-through, assessment-start rate, paid conversion.', C],
  ['Engagement', 'Weekly active organizations, verified assets, scans per organization, findings reviewed and assigned.', C],
  ['Security quality', 'Evidence completeness, adjudicated false-positive/negative rates, unsafe recommendations, authorization failures, product security incidents.', C],
  ['Remediation', 'Time to diagnosis, time to verified fix, independently verified fix rate, regression rate, patch acceptance, developer time saved.', C],
  ['Business', 'MRR, CAC, gross margin, churn, retention when sample size permits, support cost per customer, pilot-to-paid conversion.', C],
];

// ---------- 6. Workflows: transition tables ----------
// action type: RO = read-only (no effect on customer systems), RT = read-only target contact (non-mutating requests to an authorized asset),
// TM = target-modifying, AR = approval-required.
const actionTypes = [
  ['RO', 'Read-only', 'Changes RuyaShield state only; no traffic to or change on customer systems.'],
  ['RT', 'Read-only (target contact)', 'Sends non-mutating requests (P/A1 checks) to an authorized, in-scope asset through the egress guard.'],
  ['AR', 'Approval-required', 'Cannot happen without a valid, unexpired, content-bound approval by an eligible approver.'],
  ['TM', 'Target-modifying', 'Changes something the customer owns (e.g. opens a PR in their repository). Always also AR in RuyaShield.'],
];

const transitions = {
  assessment: [
    ['draft', 'queued', 'Launch: authz, scope, verification, quota and kill-switch checks pass', 'analyst / security_lead', 'RO'],
    ['draft', 'rejected', 'Any pre-check fails (403/409/423/429 returned to caller)', 'system', 'RO'],
    ['queued', 'running', 'Worker obtains lease', 'service', 'RT'],
    ['queued', 'cancelled', 'User cancels before start', 'analyst / security_lead', 'RO'],
    ['running', 'completed', 'All checks finished without error', 'service', 'RO'],
    ['running', 'completed_with_errors', 'Some checks errored/timed out; coverage % shown, never presented as clean', 'service', 'RO'],
    ['running', 'failed', 'No check completed, or authorization expired mid-run', 'service', 'RO'],
    ['running', 'cancelling → cancelled', 'User cancel or kill switch (reason kill_switch); target traffic stops ≤ 60 s', 'user / org_admin / platform operator', 'RO'],
    ['running', 'timed_out', 'Assessment budget exceeded', 'service', 'RO'],
    ['running', 'queued', 'Lease expired (worker lost); retry ≤ 2 then failed', 'system', 'RO'],
  ],
  finding: [
    ['new', 'triaged', 'Analyst triage', 'analyst / security_lead', 'RO'],
    ['new | triaged', 'false_positive', 'Justification required; audited', 'analyst / security_lead', 'RO'],
    ['triaged', 'confirmed', 'Deterministic check evidence or analyst validation', 'analyst / security_lead', 'RO'],
    ['triaged | confirmed', 'accepted_risk', 'Reason + expiry ≤ 365 days; analyst cannot (403)', 'security_lead / org_admin', 'RO'],
    ['confirmed | reopened', 'in_remediation', 'Remediation plan created or owner assigned', 'analyst / developer / security_lead', 'RO'],
    ['in_remediation', 'fix_pending_verification', 'Merge observed or guided fix marked applied', 'system / developer', 'RO'],
    ['fix_pending_verification', 'resolved_verified', 'Verification passed (system-only; no user path, 422 otherwise)', 'system', 'RT'],
    ['fix_pending_verification', 'reopened', 'Verification failed', 'system', 'RT'],
    ['fix_pending_verification', '(unchanged)', 'Verification inconclusive / error / not_run — never mapped to passed', 'system', 'RT'],
    ['resolved_verified', 'reopened', 'Regression detected on later run', 'system', 'RT'],
    ['accepted_risk', 'triaged', 'Expiry reached', 'system', 'RO'],
    ['false_positive', 'triaged', 'Re-detected with new evidence hash', 'system', 'RO'],
    ['new ↔ stale', '', 'Not observed in N completed runs / observed again', 'system', 'RO'],
  ],
  remediation: [
    ['draft', 'proposed', 'Plan generated (AI optional) or written', 'developer / analyst', 'RO'],
    ['proposed', 'sandbox_testing', 'Patch-type plan submitted for test', 'developer', 'RO'],
    ['sandbox_testing', 'test_passed | test_failed', 'Sandbox result; test_failed reasons: apply_failed, tests_failed, timeout (20 min)', 'service', 'RO'],
    ['test_failed', 'proposed', 'Revise patch', 'developer', 'RO'],
    ['proposed (guided) | test_passed', 'awaiting_approval', 'Approval requested; subject hash computed', 'developer / analyst', 'RO'],
    ['awaiting_approval', 'approved | rejected', 'Eligible approver with step-up MFA', 'approver / security_lead / org_admin', 'AR'],
    ['awaiting_approval', 'proposed', 'Plan edited → approval invalidated', 'developer', 'RO'],
    ['approved', 'change_submitted', 'Pull request opened in customer repository; approval consumed', 'service', 'TM + AR'],
    ['approved', 'applied_by_customer', 'Guided plan: owner marks change applied outside RuyaShield', 'developer / org_admin', 'RO'],
    ['change_submitted', 'merged_observed | closed_unmerged', 'Repository webhook/poll; humans merge outside RuyaShield', 'system', 'RO'],
    ['merged_observed | applied_by_customer', 'verifying', 'Verification scheduled', 'system', 'RT'],
    ['verifying', 'completed | remediation_failed', 'FixProof verified / verification failed', 'system', 'RT'],
    ['remediation_failed', 'proposed', 'Revise', 'developer', 'RO'],
  ],
  approval: [
    ['pending', 'approved', 'Eligible approver ≠ requester (unless single-approver policy D-08), step-up auth_time ≤ 15 min, subject hash matches', 'approver', 'AR'],
    ['pending', 'rejected', 'Eligible approver + reason', 'approver', 'AR'],
    ['pending', 'expired', 'TTL reached (default 7 days)', 'system', 'RO'],
    ['pending', 'invalidated', 'Plan/patch content hash changed', 'system', 'RO'],
    ['approved', 'revoked', 'Revoked before change submitted', 'approver / org_admin', 'RO'],
    ['approved', 'consumed', 'Change submitted (single use)', 'system', 'TM'],
  ],
  verification: [
    ['scheduled', 'running', 'Worker lease; same check_definition version as original detection', 'service', 'RT'],
    ['scheduled', 'not_run', 'Cancelled, authorization expired or check unsupported', 'system', 'RO'],
    ['running', 'passed', 'Check passes with captured evidence', 'service', 'RT'],
    ['running', 'failed', 'Issue still observed', 'service', 'RT'],
    ['running', 'inconclusive', 'Target unreachable, partial or ambiguous result', 'service', 'RT'],
    ['running', 'error', 'Tool / infrastructure error', 'service', 'RT'],
  ],
  asset: [
    ['unverified', 'verified', 'DNS TXT / HTTP well-known file / meta tag proof found, or attestation recorded (attestation allows P only unless policy allows A1)', 'org_admin / security_lead', 'RT'],
    ['verified', 'lapsed', 'Re-verification fails twice over 72 h; active checks blocked', 'system', 'RT'],
    ['lapsed', 'verified', 'Proof restored', 'system', 'RT'],
  ],
};

const journeys = [
  ['J-01', 'New agency onboarding', 'Create organization and user access → verify a domain and define authorized scope → select permitted assessment types → run configured checks → review prioritized findings and evidence → assign to a developer → prepare and test a fix → rerun relevant checks and generate FixProof.', 'IAM, ASSET, SCOPE, ASSESS, FIND, COLLAB, REMED, APPR, FIXP', 'MVP', C],
  ['J-02', 'WebMonitor-to-RuyaShield conversion', 'WebMonitor detects a signal → customer sees what is known and unknown → chooses to investigate → RuyaShield verifies authorization and confirms scope → user consents to any paid assessment → findings or explicit inconclusive result → remediation options → after a fix the check is rerun; recurrence monitoring resumes where supported.', 'WMON, SCOPE, ASSESS, FIXP', 'P7 (post-MVP; depends on DEP-WM-01)', C],
  ['J-03', 'Suspected incident investigation', 'Alert/suspicious submission → gather permitted evidence → AI provisional timeline with evidence gaps → propose safe authorized follow-up checks → qualified operator review → evidence-based assessment and escalation guidance. Must distinguish suspicious activity / attempted exploitation / confirmed compromise / insufficient evidence.', 'AI, FIND', 'Later (no log ingestion in MVP; AUD-13). MVP: manual evidence notes + four-way classification field.', C + ' (phase moved, AUD-13)'],
];

// ---------- 8. AI spec ----------
const aiUseCases = [
  ['AI-UC-01', 'Explain a finding (technical + plain language)', 'Optional', 'Finding, evidence items (redacted), check definition', 'ai.analysis v1 (explanation)', 'Deterministic template text from check definition', 'RS-AI-002'],
  ['AI-UC-02', 'Root-cause hypotheses', 'Optional', 'Finding, evidence, approved customer context', 'ai.analysis v1 (claims typed inference)', 'No hypothesis shown; "AI unavailable" banner', 'RS-AI-003'],
  ['AI-UC-03', 'Remediation guidance / proposed patch', 'Optional', 'Finding, evidence, repo file excerpts (redacted) if connected', 'ai.analysis v1 (recommendation) / patch diff', 'Check-definition remediation guidance; human-written patch', 'RS-AI-004'],
  ['AI-UC-04', 'Diagnostic plan (suggest follow-up checks)', 'Optional', 'Finding, scope, check catalogue (P/A1 only)', 'List of check_definition IDs — never commands', 'User picks checks manually', 'RS-AI-007'],
  ['AI-UC-05', 'Report narrative drafting', 'Optional', 'Assessment summary, verified FixProof records', 'Draft text; human edits before export', 'Template report', 'RS-DASH-003'],
  ['AI-UC-06', 'Prompt-injection screening of untrusted content', 'Required (when AI is used)', 'Untrusted spans', 'Classifier label; deterministic delimiting regardless', 'Treat all as untrusted (default)', 'RS-AI-005'],
  ['AI-UC-07', 'Deciding a finding is resolved / verified', 'Prohibited', '—', '—', 'Only deterministic verification runs can set resolved_verified', 'RS-FIXP-002'],
  ['AI-UC-08', 'Selecting targets, expanding scope, launching scans', 'Prohibited', '—', '—', 'Human launch within approved scope only', 'RS-SCOPE-001'],
  ['AI-UC-09', 'Approving, merging, deploying or executing commands', 'Prohibited', '—', '—', 'Human approver; PR-only; sandbox runs only fixed test commands', 'RS-APPR-002'],
  ['AI-UC-10', 'Creating or editing findings / scan results', 'Prohibited', '—', '—', 'Findings come only from check runs', 'RS-FIND-001'],
  ['AI-UC-11', 'Claiming compromise or guaranteeing security', 'Prohibited', '—', '—', 'Four-way classification set by a human', 'RS-AI-003'],
];

const aiClaimTypes = [
  ['observation', 'A fact directly present in a cited evidence item (e.g. header absent in response evidence EV-…).', 'Must cite ≥ 1 evidence_item_id that contains the fact; validator checks the ID belongs to the finding.'],
  ['inference', 'A reasoned conclusion from observations (e.g. likely cause is CDN config).', 'Must cite the observations it relies on; displayed as "Hypothesis"; confidence label ≤ likely.'],
  ['recommendation', 'A suggested action (e.g. add HSTS header).', 'Must reference the finding and include a verification check ID; requires human acceptance; never executed by AI.'],
];

const aiControls = [
  ['Inputs & provenance', 'Only data from the tenant\'s own findings, evidence and approved context; each input recorded as {source_type, id, sha256}. input_hash = SHA-256 of canonical input bundle.', R],
  ['Output schema', 'JSON schema ai.analysis v1 validated server-side; invalid → one retry with repair prompt → else stored as failed, fallback shown.', C + ' (structured outputs) + ' + R],
  ['Typing', 'Every claim typed observation / inference / recommendation; untyped or uncited claims are dropped and counted.', R],
  ['Untrusted content', 'Website content, repository content, logs and uploads are wrapped in delimited, labelled data blocks; system policy never in the same channel; model has no tools; output never executed.', C],
  ['Redaction', 'Secrets (API keys, tokens, passwords, private keys), cookies, Authorization headers, emails and IPs of end users redacted before sending; redaction patterns versioned (D-15).', C + ' (minimize) + ' + R],
  ['Fallback', 'Core workflow (scan → finding → remediation → verification → FixProof) works with AI disabled per org or globally.', R],
  ['Cost', 'Per-request token cap, per-org monthly AI budget from plan, circuit breaker on provider errors; usage metered idempotently.', R],
  ['Versioning', 'prompt_template_id@version, model provider/model ID, schema version, redaction version stored on every ai_analyses row; changes go through eval gate.', R],
  ['Evaluation', 'Golden set per use case: factual accuracy, evidence traceability, unsafe-action attempts, injection resistance, leakage, regressions; gate before each model/prompt release (TC-AIEVAL-*).', C],
  ['Human review', 'AI output labelled "AI-generated — review before use"; recommendations need explicit acceptance; critical findings need analyst triage regardless.', C],
  ['Provider', 'Provider-agnostic gateway; provider choice D-07; no customer data used for provider training (contractual requirement to confirm).', C + ' / ' + Q],
];

// ---------- 9. FixProof ----------
const fixproofStatus = [
  ['all runs passed', 'verified', 'resolved_verified', 'Only path to "verified".'],
  ['≥1 passed, none failed, some inconclusive/error/not_run', 'partially_verified', 'fix_pending_verification (unchanged)', 'Shown amber; never displayed as verified.'],
  ['any run failed', 'failed', 'reopened', 'Remediation → remediation_failed; owner notified.'],
  ['none passed and none failed', 'unverified', 'fix_pending_verification (unchanged)', 'Retry allowed; reason shown.'],
];
const fixproofContents = [
  ['Original finding', 'finding_id, fingerprint, title, severity, confidence, first_seen, check_definition id@version'],
  ['Original evidence', 'evidence_item ids + sha256 (content stored in private S3, redacted)'],
  ['Remediation', 'remediation_plan id, type (guided/patch), code_change id, PR URL, merge commit SHA (if observed)'],
  ['Approval', 'approval id, approver user id, decided_at, subject_sha256, policy (two-person / single-approver)'],
  ['Verification', 'verification_run ids, result per run, same check version flag, evidence ids + sha256, started/finished timestamps'],
  ['Status & limits', 'overall status (verified / partially_verified / failed / unverified), coverage note, limitations text ("verifies only the listed checks at the stated time")'],
  ['Integrity', 'content_sha256 over RFC 8785 canonical JSON; prev_record_hash (hash chain per org); export signature (HMAC/KMS-sign, D-11 for WORM)'],
];
const fixproofRules = [
  'A FixProof record is created only from a completed verification evaluation; it is never edited — a new record supersedes it (supersedes_id) on re-verification or regression.',
  'Failed, inconclusive, error and not_run results are never represented as passed in UI, API, export or report.',
  'Records are tamper-evident (hash chain + content hash, verifiable offline from the JSON export). No immutability or WORM claim is made unless D-11 (S3 Object Lock) is implemented.',
  'Regression on a resolved_verified finding reopens it and marks the latest FixProof superseded (regression); the original record is retained unchanged.',
  'Export: JSON (canonical, with hashes) and PDF (human-readable, with verification instructions). Exports are audited (fixproof.exported).',
  'Retention: kept for the life of the organization plus the retention period in §12.3 (assumption: 3 years after finding closure); deletion only via org deletion workflow, audited.',
];

// ---------- 10. WebMonitor ----------
const wmAdapter = [
  ['Dependency', 'DEP-WM-01: WebMonitor API, payload, authentication and event contract — not yet provided. Everything below is a provisional RuyaShield-side adapter interface, not a WebMonitor endpoint.', Q],
  ['Direction', 'Inbound referral handoff (WebMonitor → RuyaShield) and outbound result linkage (RuyaShield → WebMonitor) behind a WebMonitorAdapter interface with a stub implementation for tests.', R],
  ['Authentication', 'Provisional: signed handoff token (asymmetric signature, ≤ 10 min TTL, single-use nonce) — to be replaced by the agreed mechanism.', R + ' / ' + Q],
  ['Minimal context', 'Only: referral id, signal type, affected URL/host, observed_at, short description. No WebMonitor credentials, page content or end-user data.', C + ' (FR-042)'],
  ['Consent', 'User must sign in, select org, confirm asset verification/attestation and explicitly consent to the assessment (and to any charge). No scan starts from a handoff alone.', C + ' (FR-041)'],
  ['Result linkage', 'Outbound status only: referral id, assessment status, counts by severity, FixProof status. P1.', C + ' (FR-043)'],
  ['Attribution', 'referral_events table for click-through / conversion metrics. P1.', C + ' (FR-044)'],
];
const wmInterface = `interface WebMonitorAdapter {
  // PROVISIONAL — shape owned by RuyaShield; real transport defined by DEP-WM-01
  verifyHandoff(token: string): Promise<VerifiedReferral>;      // rejects expired, replayed, bad signature
  publishResult(link: ReferralResultLink): Promise<void>;        // idempotent on (referral_id, status_version)
}
type VerifiedReferral = { referralId: string; signalType: string; host: string; observedAt: string; summary: string };
type ReferralResultLink = { referralId: string; assessmentId: string; status: string;
  severityCounts: Record<'critical'|'high'|'medium'|'low'|'info', number>; fixproofStatus?: string; statusVersion: number };`;

// ---------- 11. Architecture ----------
const modules = [
  ['iam', 'Users, orgs, memberships, client groups, roles, sessions, MFA/step-up checks', 'Web/API', 'IAM'],
  ['policy', 'Single authorization decision point (RBAC + tenancy + action class + kill switch)', 'Web/API, workers', 'IAM, SCOPE'],
  ['assets', 'Assets, verification proofs, attestations, re-verification scheduler', 'Web/API, verifier worker', 'ASSET'],
  ['scope', 'Versioned scopes, check catalogue, action classes', 'Web/API', 'SCOPE'],
  ['assessments', 'Launch, orchestration, leases, status, quotas', 'Web/API, orchestrator', 'ASSESS, ADMIN'],
  ['scanning', 'Scanner adapter + native checks; runs only in scan workers behind egress guard', 'Scan worker', 'ASSESS'],
  ['findings', 'Normalization, fingerprint dedup, evidence, lifecycle, triage, risk acceptance', 'Web/API, workers', 'FIND, RISK, COLLAB'],
  ['ai', 'AI gateway: redaction, prompt registry, schema validation, budget, provenance; no tools', 'AI worker', 'AI'],
  ['remediation', 'Plans, code changes, sandbox orchestration, repo integration (PR-only)', 'Web/API, sandbox runner', 'REMED'],
  ['approvals', 'Content-bound approvals, step-up, expiry, invalidation', 'Web/API', 'APPR'],
  ['verification', 'Verification runs, FixProof assembly, export, hash chain', 'Workers', 'FIXP, AUDIT'],
  ['integrations', 'WebMonitor adapter (provisional), repo provider, notifications', 'Web/API, workers', 'WMON, DASH'],
  ['audit', 'Append-only audit events, hash chain, viewer/export', 'All', 'AUDIT'],
  ['platform', 'Outbox, queue consumers, idempotency, observability, retention jobs', 'All', 'PLAT'],
];

const trustBoundaries = [
  ['TB-1', 'Internet ↔ Web/API', 'Untrusted users and browsers', 'OIDC sessions, CSRF, CSP, rate limits, input validation, WAF'],
  ['TB-2', 'Web/API ↔ Postgres', 'Tenant data', 'RLS keyed on org_id set per transaction, least-privilege DB roles, no superuser at runtime'],
  ['TB-3', 'Web/API ↔ Queue ↔ Workers', 'Job messages', 'Outbox, signed job envelopes carrying org_id + scope version, per-worker IAM roles'],
  ['TB-4', 'Scan workers ↔ Customer targets', 'Untrusted target responses', 'Egress guard: resolve-and-pin, deny private/metadata ranges, scope allowlist, rate/time budgets'],
  ['TB-5', 'Sandbox ↔ everything', 'Untrusted customer code + AI patches', 'Ephemeral isolated runtime, no prod credentials, deny-by-default egress (registry allowlist), artifacts out only'],
  ['TB-6', 'AI worker ↔ Model provider', 'Redacted tenant data; untrusted model output', 'Redaction, no tools, schema validation, output never executed, budget caps'],
  ['TB-7', 'Integrations ↔ Repo provider / WebMonitor', 'Third-party APIs and webhooks', 'Least-privilege app installation, webhook signature check, short-lived tokens in Secrets Manager'],
  ['TB-8', 'Operators ↔ Production', 'Platform staff', 'Break-glass with reason + time limit + audit, no standing access to tenant evidence'],
];

const adrs = [
  ['ADR-001', 'Modular monolith with isolated workers', 'One Next.js/TypeScript codebase with enforced module boundaries; scanning, sandbox and AI run as separate worker processes with their own IAM roles.', 'Small team, simpler ops; isolation where it matters (v1.1 §7.3).', 'Extract services only for isolation, scale or ownership reasons.', 'Accepted (proposed)', C],
  ['ADR-002', 'PostgreSQL with row-level security for tenancy', 'Every tenant table has org_id; RLS policies + app-layer policy checks (defence in depth).', 'Cross-tenant leakage is a release blocker.', 'ORM choice D-02 must support SET LOCAL per transaction.', 'Proposed', R],
  ['ADR-003', 'SQS + transactional outbox, idempotent consumers', 'State change and outbox row in one transaction; relay publishes; consumers dedupe on idempotency key.', 'No duplicate jobs, findings or usage (NFR idempotency).', 'At-least-once semantics everywhere.', 'Proposed', C + ' (SQS) + ' + R],
  ['ADR-004', 'Egress guard for all target traffic', 'All scanner/verifier HTTP/DNS/TLS goes through a guard that resolves, pins and checks IPs against scope and deny lists.', 'SSRF and out-of-scope scanning prevention (SEC).', 'Adds latency; scanner engine must support proxying (D-01 criterion).', 'Proposed', R],
  ['ADR-005', 'Ephemeral sandbox for patch tests', 'Container or microVM per run (D-05), 20 min cap, no credentials, registry-only egress.', 'RCE containment (v1.1 §8.2).', 'Some test suites will not run; result test_failed(reason) not passed.', 'Proposed', C + ' + ' + R],
  ['ADR-006', 'AI gateway without tools', 'Model receives redacted data and returns schema-validated JSON; it cannot call tools, network or shell.', 'Prompt injection cannot cause actions.', 'Less "agentic"; acceptable by design.', 'Proposed', C + ' (tool policy outside model) + ' + R],
  ['ADR-007', 'Hash-chained audit and FixProof records', 'SHA-256 chain per org over canonical JSON; periodic anchor digest stored separately.', 'Tamper evidence for client-facing proof.', 'Tamper-evident only; WORM is D-11.', 'Proposed', R],
  ['ADR-008', 'PR-only remediation', 'RuyaShield opens PRs after approval; never merges, deploys, or holds admin scopes.', 'Removes production-change risk (RB-03).', 'Customer must merge; verification waits for merge observation.', 'Proposed', C + ' (approval before merge) + ' + R],
  ['ADR-009', 'Content-bound approvals', 'Approval binds to subject_sha256 of RFC 8785 canonical JSON of plan + diff; any change invalidates.', 'Prevents approve-then-swap.', 'Edits require re-approval.', 'Proposed', R],
];

const sandbox = [
  ['Runtime', 'Ephemeral container with gVisor or Firecracker microVM (D-05); fresh per run; destroyed after.', R],
  ['Limits', '2 vCPU, 4 GB RAM, 10 GB disk, 20 min wall clock (assumptions; tune in P5).', R],
  ['Network', 'Deny by default; allowlist package registries via caching proxy; no customer production hosts; no metadata endpoints.', C + ' + ' + R],
  ['Credentials', 'None. Repository checkout via short-lived read token used outside the sandbox; code copied in.', C],
  ['Commands', 'Fixed, customer-configured install/test commands from repo config reviewed in RuyaShield; never from model output.', C],
  ['Artifacts', 'Only test report, logs (redacted, size-capped) and diff hash leave the sandbox.', R],
  ['Failure', 'Any limit breach → test_failed with reason; never test_passed.', R],
];

const egress = [
  'Resolve hostname once, pin the IP for the request, and re-check on redirect (max 5 redirects, each re-validated).',
  'Deny RFC 1918, loopback, link-local, CGNAT, multicast, IPv6 ULA/link-local, cloud metadata (169.254.169.254, fd00:ec2::254) and RuyaShield own ranges.',
  'Allow only hosts in the assessment scope snapshot (exact host or verified subdomain per policy).',
  'Enforce per-assessment request budget, concurrency, rate (default 5 req/s — assumption) and per-check timeouts.',
  'Check kill switch state before each batch; refuse when engaged.',
  'Log every denied request as egress.denied with reason; denials never silently retried to another IP.',
];

// ---------- 12. Data ----------
const tables = [
  ['organizations', 'Tenant root', 'id, name, plan, kill_switch, single_approver_policy, created_at', 'root', 'Org life + 30 days'],
  ['users', 'Identity (IdP subject)', 'id, idp_sub, email, mfa_enrolled, disabled_at', 'global', 'Account life'],
  ['memberships', 'User ↔ org role', 'org_id, user_id, role, client_group_ids[], invited_by, status', 'org_id RLS', 'Org life'],
  ['client_groups', 'Agency client separation', 'org_id, id, name', 'org_id RLS', 'Org life'],
  ['assets', 'Authorized targets', 'org_id, id, client_group_id, kind (domain/url/api), host, verification_status', 'org_id RLS', 'Org life'],
  ['asset_verifications', 'Ownership proofs', 'org_id, asset_id, method, token_hash, verified_at, last_checked_at, failures', 'org_id RLS', 'Org life'],
  ['asset_authorizations', 'Documented attestation', 'org_id, asset_id, attested_by, text_version, document_ref, expires_at', 'org_id RLS', 'Org life + 3 y'],
  ['check_definitions', 'Versioned check catalogue', 'id, version, action_class (P/A1/A2/X), engine, params_schema', 'global', 'Permanent'],
  ['assessment_scopes', 'Versioned scope', 'org_id, id, asset_id, version, check_ids[], limits, approved_by', 'org_id RLS', 'Org life'],
  ['assessments', 'Runs', 'org_id, id, scope_id, scope_version, state, reason, coverage_pct, idempotency_key', 'org_id RLS', '3 y'],
  ['check_runs', 'Per-check execution', 'org_id, assessment_id, check_definition_id@version, state, started_at, finished_at', 'org_id RLS', '3 y'],
  ['evidence_items', 'Evidence metadata (content in S3)', 'org_id, id, kind, s3_key, sha256, redaction_version, size', 'org_id RLS', '1 y raw / hash kept 3 y'],
  ['findings', 'Deduplicated issues', 'org_id, id, asset_id, fingerprint, state, severity, confidence, owner_id, due_at', 'org_id RLS', '3 y after closure'],
  ['finding_occurrences', 'Detections', 'org_id, finding_id, check_run_id, observed_at', 'org_id RLS', '3 y'],
  ['finding_status_history', 'Transitions', 'org_id, finding_id, from, to, actor, reason, at', 'org_id RLS', '3 y'],
  ['risk_acceptances', 'Accepted risk', 'org_id, finding_id, accepted_by, reason, expires_at', 'org_id RLS', '3 y'],
  ['ai_analyses', 'AI outputs + provenance', 'org_id, id, finding_id, use_case, prompt_id@ver, model, input_hash, status, tokens, cost', 'org_id RLS', '1 y'],
  ['ai_claims', 'Typed claims', 'org_id, analysis_id, type, text, evidence_ids[], confidence_label', 'org_id RLS', '1 y'],
  ['remediation_plans', 'Plans', 'org_id, id, finding_id, type, state, content_sha256', 'org_id RLS', '3 y'],
  ['code_changes', 'Proposed diffs', 'org_id, id, plan_id, diff_s3_key, diff_sha256, pr_url, merge_sha', 'org_id RLS', '3 y'],
  ['sandbox_runs', 'Patch tests', 'org_id, id, code_change_id, result, reason, limits, report_s3_key', 'org_id RLS', '1 y'],
  ['approvals', 'Content-bound approvals', 'org_id, id, subject_type, subject_id, subject_sha256, requester_id, approver_id, state, auth_time, expires_at', 'org_id RLS', '3 y'],
  ['verification_runs', 'Verification', 'org_id, id, finding_id, check_definition_id@version, result, reason', 'org_id RLS', '3 y'],
  ['fixproof_records', 'FixProof', 'org_id, id, finding_id, status, content_json, content_sha256, prev_hash, supersedes_id', 'org_id RLS', 'Org life + 3 y'],
  ['integrations', 'Repo / WebMonitor connections', 'org_id, id, provider, scopes, secret_ref (Secrets Manager ARN)', 'org_id RLS', 'Until disconnected'],
  ['webmonitor_referrals', 'Provisional handoffs', 'org_id, id, external_ref, signal_type, host, nonce, consumed_at', 'org_id RLS', '1 y'],
  ['consents', 'Assessment/charge consent', 'org_id, id, user_id, subject, text_version, at', 'org_id RLS', '3 y'],
  ['usage_records', 'Quota metering', 'org_id, id, metric, quantity, idempotency_key, period', 'org_id RLS', '3 y'],
  ['outbox', 'Event outbox', 'id, org_id, event_type, payload, published_at', 'org_id RLS', '7 days after publish'],
  ['audit_events', 'Append-only audit', 'org_id, seq, id, actor, action, subject, outcome, at, prev_hash, hash', 'org_id RLS; INSERT only', '3 y (assumption)'],
];

const retention = [
  ['Raw evidence content (S3)', '1 year after capture', 'Hash and metadata kept with finding', R + ' — assumption'],
  ['Findings, history, FixProof', '3 years after finding closure; FixProof for org life + 3 y', 'Client-proof value', R + ' — assumption'],
  ['AI inputs/outputs', '1 year; inputs stored only as hashes + references', 'Minimization', R + ' — assumption'],
  ['Sandbox logs and reports', '1 year', '', R + ' — assumption'],
  ['Audit events', '3 years', 'Investigations', R + ' — assumption'],
  ['Org deletion', 'Soft delete 30 days, then purge (except legally required records)', 'Customer request', R + ' — ' + Q + ' (legal review)'],
  ['Backups', '35 days point-in-time', 'Recovery', R + ' — assumption'],
];

const auditCatalogue = [
  ['auth.login / auth.login_failed / auth.logout', 'IAM'], ['auth.step_up', 'IAM'], ['authz.denied', 'IAM'],
  ['org.created / org.updated / org.kill_switch_changed', 'IAM, ASSESS'], ['member.invited / member.role_changed / member.removed', 'IAM'],
  ['asset.created / asset.verified / asset.lapsed / asset.attested', 'ASSET'], ['scope.created / scope.version_approved', 'SCOPE'],
  ['assessment.launched / assessment.rejected / assessment.cancelled / assessment.completed', 'ASSESS'], ['egress.denied', 'ASSESS'],
  ['finding.created / finding.transitioned / finding.assigned', 'FIND, COLLAB'], ['finding.false_positive / risk.accepted / risk.expired', 'RISK'],
  ['evidence.accessed / evidence.exported', 'FIND'], ['ai.analysis_requested / ai.analysis_failed / ai.injection_detected', 'AI'],
  ['remediation.created / sandbox.run_completed', 'REMED'], ['approval.requested / approval.decided / approval.invalidated / approval.revoked', 'APPR'],
  ['change.pr_opened / change.merge_observed', 'REMED'], ['verification.completed / fixproof.created / fixproof.exported', 'FIXP'],
  ['integration.connected / integration.disconnected', 'REMED, WMON'], ['webmonitor.handoff_received / webmonitor.handoff_rejected', 'WMON'],
  ['operator.break_glass / operator.action', 'ADMIN'], ['audit.exported / audit.chain_verified', 'AUDIT'], ['retention.purged', 'PLAT'],
];

// ---------- 13. API & events ----------
const apiConventions = [
  'Base path /v1; JSON; org scoping via path /v1/orgs/{orgId}/… — server re-checks membership (path value never trusted alone).',
  'Mutations require Idempotency-Key header (24 h retention); replay returns the original response.',
  'Errors: RFC 9457 problem+json with stable "code" (e.g. transition_not_allowed, approval_required, kill_switch_engaged, quota_exceeded, scope_violation).',
  'Status codes: 400 validation, 401 unauthenticated, 403 forbidden, 404 not found (also for other tenants\' IDs), 409 conflict/state, 410 expired, 422 transition_not_allowed / prohibited, 423 kill switch, 429 rate/quota.',
  'Cursor pagination (?cursor=&limit≤100); ISO-8601 UTC timestamps; IDs are prefixed ULIDs (asm_, fnd_, …).',
  'All endpoints below are proposed contracts for implementation, not an existing API.',
];
const api = [
  ['POST', '/v1/orgs', 'Create organization', 'any signed-in user', 'RS-IAM-002'],
  ['POST', '/v1/orgs/{orgId}/invites', 'Invite member with role', 'org_admin', 'RS-IAM-003'],
  ['POST', '/v1/orgs/{orgId}/assets', 'Register asset', 'org_admin, security_lead', 'RS-ASSET-001'],
  ['POST', '/v1/orgs/{orgId}/assets/{assetId}/verifications', 'Start / check ownership verification', 'org_admin, security_lead', 'RS-ASSET-002'],
  ['POST', '/v1/orgs/{orgId}/assets/{assetId}/authorizations', 'Record attestation', 'org_admin', 'RS-ASSET-003'],
  ['POST', '/v1/orgs/{orgId}/scopes', 'Create scope version', 'security_lead', 'RS-SCOPE-001'],
  ['POST', '/v1/orgs/{orgId}/assessments', 'Launch assessment', 'analyst, security_lead', 'RS-ASSESS-001'],
  ['POST', '/v1/orgs/{orgId}/assessments/{id}:cancel', 'Cancel assessment', 'analyst, security_lead', 'RS-ASSESS-004'],
  ['PUT', '/v1/orgs/{orgId}/kill-switch', 'Engage / release org kill switch (step-up)', 'org_admin', 'RS-ASSESS-007'],
  ['GET', '/v1/orgs/{orgId}/findings', 'List findings with filters', 'all roles (viewer read)', 'RS-FIND-005'],
  ['POST', '/v1/orgs/{orgId}/findings/{id}/transitions', 'Request state transition', 'per transition table', 'RS-FIND-004'],
  ['POST', '/v1/orgs/{orgId}/findings/{id}/risk-acceptances', 'Accept risk with expiry', 'security_lead, org_admin', 'RS-RISK-002'],
  ['POST', '/v1/orgs/{orgId}/findings/{id}/ai-analyses', 'Request AI analysis (async)', 'analyst, developer, security_lead', 'RS-AI-002'],
  ['POST', '/v1/orgs/{orgId}/remediation-plans', 'Create remediation plan', 'developer, analyst', 'RS-REMED-001'],
  ['POST', '/v1/orgs/{orgId}/code-changes/{id}/sandbox-runs', 'Run patch in sandbox', 'developer', 'RS-REMED-003'],
  ['POST', '/v1/orgs/{orgId}/approvals', 'Request approval (returns subject_sha256)', 'developer, analyst', 'RS-APPR-001'],
  ['POST', '/v1/orgs/{orgId}/approvals/{id}/decision', 'Approve / reject (step-up)', 'approver, security_lead, org_admin', 'RS-APPR-002'],
  ['POST', '/v1/orgs/{orgId}/findings/{id}/verification-runs', 'Schedule verification', 'system / analyst', 'RS-FIXP-001'],
  ['GET', '/v1/orgs/{orgId}/fixproofs/{id}/export?format=json|pdf', 'Export FixProof', 'all except service', 'RS-FIXP-004'],
  ['GET', '/v1/orgs/{orgId}/audit-events', 'Audit viewer / export', 'org_admin, security_lead', 'RS-AUDIT-003'],
  ['POST', '/v1/integrations/webmonitor/handoffs', 'PROVISIONAL inbound handoff (adapter; contract per DEP-WM-01)', 'signed token', 'RS-WMON-001'],
];

const jsonExamples = [
  ['Launch assessment — request', `POST /v1/orgs/org_01J.../assessments
Idempotency-Key: 6f1c2b9e-...
{
  "scope_id": "scp_01J8Z...",
  "scope_version": 3,
  "requested_check_ids": ["tls.cert_expiry@2", "http.security_headers@1", "dns.email_posture@1"]
}`],
  ['Launch assessment — 202 response', `{
  "id": "asm_01J9A...",
  "state": "queued",
  "scope_version": 3,
  "checks": [{"id": "tls.cert_expiry@2", "action_class": "A1"}, {"id": "http.security_headers@1", "action_class": "A1"},
             {"id": "dns.email_posture@1", "action_class": "P"}],
  "created_at": "2026-10-29T09:12:44Z"
}`],
  ['Launch blocked — 423 kill switch', `{
  "type": "https://docs.ruyashield.example/errors/kill_switch_engaged",
  "title": "Assessments are paused",
  "status": 423,
  "code": "kill_switch_engaged",
  "detail": "The organization kill switch is engaged. No target traffic will be sent."
}`],
  ['ai.analysis v1 (stored output)', `{
  "schema": "ai.analysis/v1",
  "analysis_id": "aia_01J9C...",
  "finding_id": "fnd_01J9B...",
  "use_case": "explain_finding",
  "provenance": {"prompt": "explain_finding@4", "model": "<provider>/<model-id>", "redaction": "r3",
                 "input_hash": "sha256:9c1e...", "inputs": [{"type": "evidence_item", "id": "evi_01J9B...", "sha256": "sha256:51aa..."}]},
  "claims": [
    {"type": "observation", "text": "The response does not include a Strict-Transport-Security header.", "evidence_ids": ["evi_01J9B..."]},
    {"type": "inference", "text": "HSTS is likely not configured at the CDN layer.", "relies_on": [0], "confidence_label": "likely"},
    {"type": "recommendation", "text": "Add Strict-Transport-Security: max-age=31536000; includeSubDomains.", "verification_check_id": "http.security_headers@1", "requires_human_acceptance": true}
  ],
  "unknowns": ["Whether all subdomains serve HTTPS has not been checked."],
  "label": "AI-generated — review before use"
}`],
  ['Approval decision — request', `POST /v1/orgs/org_01J.../approvals/apr_01J9D.../decision
Idempotency-Key: 0b7d...
{ "decision": "approved", "subject_sha256": "sha256:4be2...", "comment": "Header change only; tests pass." }
// server rejects with 409 subject_mismatch if hash differs, 401 step_up_required if auth_time > 15 min,
// 403 self_approval_forbidden if approver == requester and single-approver policy is off`],
  ['Verification run — completed', `{
  "id": "vrf_01J9F...",
  "finding_id": "fnd_01J9B...",
  "check": "http.security_headers@1",
  "same_version_as_detection": true,
  "result": "passed",
  "evidence_ids": ["evi_01J9F..."],
  "started_at": "2026-10-29T11:02:10Z",
  "finished_at": "2026-10-29T11:02:14Z"
}`],
  ['FixProof export (JSON, abridged)', `{
  "schema": "fixproof/v1",
  "id": "fxp_01J9G...",
  "status": "verified",
  "finding": {"id": "fnd_01J9B...", "fingerprint": "sha256:aa10...", "severity": "medium", "check": "http.security_headers@1"},
  "remediation": {"plan_id": "rem_01J9D...", "type": "patch", "pr_url": "https://<repo-host>/<org>/<repo>/pull/42", "merge_sha": "3f9c..."},
  "approval": {"id": "apr_01J9D...", "approver": "usr_01H...", "subject_sha256": "sha256:4be2...", "policy": "two_person"},
  "verification": [{"id": "vrf_01J9F...", "result": "passed"}],
  "limitations": "Verifies only the listed checks against the listed asset at the stated time.",
  "integrity": {"content_sha256": "sha256:7d02...", "prev_record_hash": "sha256:c8e1...", "canonicalization": "RFC8785"}
}`],
  ['WebMonitor handoff (PROVISIONAL)', `// Provisional adapter payload — not a WebMonitor API. Replace per DEP-WM-01.
{
  "referral_id": "wm-ref-…",
  "signal_type": "tls_certificate_expiring",
  "host": "client-site.example",
  "observed_at": "2026-10-28T22:00:00Z",
  "summary": "Certificate expires in 9 days",
  "nonce": "…", "exp": 1793270000
}`],
];

const events = [
  ['assessment.requested', 'assessments', 'orchestrator', 'assessment_id, org_id, scope_version, idempotency_key'],
  ['check_run.dispatched', 'orchestrator', 'scan worker', 'check_run_id, check_definition@version, scope_snapshot_hash, budget'],
  ['check_run.completed', 'scan worker', 'findings, assessments', 'check_run_id, state, evidence_ids[], raw_result_ref'],
  ['finding.created / finding.transitioned', 'findings', 'notifications, ai (optional), dashboard', 'finding_id, from, to, actor'],
  ['ai.analysis.requested / completed', 'ai', 'findings UI', 'analysis_id, status, schema_version'],
  ['sandbox.run.requested / completed', 'remediation', 'sandbox runner / remediation', 'sandbox_run_id, diff_sha256, result, reason'],
  ['approval.decided', 'approvals', 'remediation', 'approval_id, decision, subject_sha256'],
  ['change.merge_observed', 'integrations', 'remediation, verification', 'code_change_id, merge_sha'],
  ['verification.completed', 'verification', 'findings, fixproof, notifications', 'verification_run_id, result'],
  ['fixproof.created', 'verification', 'notifications, integrations (WebMonitor link)', 'fixproof_id, status, content_sha256'],
  ['org.kill_switch_changed', 'iam', 'orchestrator, workers', 'org_id, engaged, actor'],
];
const eventEnvelope = `{
  "event_id": "evt_01J9...", "type": "verification.completed", "version": 1,
  "org_id": "org_01J...", "occurred_at": "2026-10-29T11:02:14Z",
  "idempotency_key": "vrf_01J9F...:completed", "trace_id": "4bf92f35...",
  "data": { "verification_run_id": "vrf_01J9F...", "finding_id": "fnd_01J9B...", "result": "passed" }
}`;

// ---------- 14. UX ----------
const screens = [
  ['UX-01', 'Sign-in & org switcher', 'all', 'IdP redirect, org list, MFA prompt', 'Disabled account, no orgs'],
  ['UX-02', 'Onboarding checklist', 'org_admin', 'Create org → add asset → verify → scope → first assessment', 'Step blocked with reason'],
  ['UX-03', 'Assets list & detail', 'org_admin, security_lead', 'Verification badge (unverified/verified/lapsed), method instructions, attestation, client group', 'Lapsed banner blocks active checks'],
  ['UX-04', 'Scope editor', 'security_lead', 'Check catalogue with action-class chips (P/A1; A2 disabled "not available in MVP"; X hidden), limits, version diff', 'Validation errors inline'],
  ['UX-05', 'Assessment launch & progress', 'analyst, security_lead', 'Pre-flight summary of scope, quota, kill-switch state; live check progress; coverage %', 'completed_with_errors shown amber with failed checks listed; never "clean"'],
  ['UX-06', 'Findings list', 'all', 'Filters (state, severity, confidence, asset, client group, owner), bulk assign, saved views', 'Empty state explains no findings ≠ secure'],
  ['UX-07', 'Finding detail', 'all', 'Evidence panel, timeline, state actions per role, AI panel (labelled, typed claims with evidence links), comments', 'AI unavailable → template guidance'],
  ['UX-08', 'Remediation plan & diff review', 'developer, approver', 'Plan, diff viewer, sandbox result with reason, request approval', 'test_failed reason visible'],
  ['UX-09', 'Approval inbox & decision', 'approver', 'Exact content hash shown, step-up prompt, approve/reject with reason, expiry countdown', 'Invalidated/expired states'],
  ['UX-10', 'Verification & FixProof', 'all', 'Status chip (verified / partially_verified / failed / unverified), per-run results, integrity hash, export JSON/PDF', 'Inconclusive explained; no green unless verified'],
  ['UX-11', 'Dashboard', 'all', 'Open by severity, overdue, verified remediations this month, assets needing re-verification', 'Coverage caveats'],
  ['UX-12', 'Audit log', 'org_admin, security_lead', 'Filter, export, chain verification result', ''],
  ['UX-13', 'Org settings', 'org_admin', 'Members & roles, client groups, MFA policy, single-approver policy, kill switch, integrations, AI on/off', 'Kill switch requires step-up + confirmation'],
  ['UX-14', 'WebMonitor referral landing (P7)', 'org_admin, analyst', 'What is known / unknown, authorization check, consent, start assessment', 'Expired/replayed handoff'],
];
const uxRules = [
  'Status honesty: colour and copy never imply success for failed, inconclusive, error, not_run, partially_verified or completed_with_errors.',
  'Every AI block shows "AI-generated — review before use", claim type, and evidence links; uncited claims are not rendered.',
  'Destructive or privileged actions (kill switch, approve, accept risk, remove member) require confirmation, reason, and step-up where listed.',
  'WCAG 2.2 AA for core workflows; status never conveyed by colour alone; keyboard-operable diff and approval flows.',
  'Plain-language mode for SMB personas; technical detail expandable.',
];

// ---------- 15. QA strategy ----------
const qaStrategy = [
  ['Unit', 'Policy engine, state machines, status mapping, canonical hashing, redaction, egress rules', 'CI on every PR', 'Vitest/Jest (assumption)'],
  ['Integration', 'API + Postgres RLS + outbox + workers with stub scanner/AI/repo adapters', 'CI', 'Ephemeral Postgres, LocalStack SQS/S3'],
  ['Contract', 'Scanner adapter, AI schema, repo provider, provisional WebMonitor adapter', 'CI', 'Recorded fixtures; stubs'],
  ['End-to-end', 'Journey J-01 on lab targets owned by RuyaShield', 'Nightly + pre-release', 'Playwright; lab targets in isolated VPC'],
  ['Security', 'Authz matrix sweep, cross-tenant IDOR, SSRF corpus, sandbox escape attempts, injection corpus, dependency/secret scanning, DAST of RuyaShield itself', 'CI + per gate + independent review before pilot', 'Own lab only — never customer targets'],
  ['AI eval', 'Golden sets per use case; injection and leakage suites', 'Before each prompt/model release (gate G3)', 'Eval harness RS-AI-006'],
  ['Performance', 'Dashboard P95, launch ack, pilot scale 100 assets', 'Per gate G2/G7', 'k6 (assumption)'],
  ['Accessibility', 'WCAG 2.2 AA core flows', 'G7', 'axe + manual screen-reader pass'],
  ['Recovery', 'Backup restore drill, RTO/RPO', 'G7', 'Runbook'],
];
const environments = [
  ['local', 'Developers; stub adapters; seeded synthetic data'],
  ['ci', 'Ephemeral; no external network except package registries'],
  ['staging', 'Production-like; lab targets only; synthetic tenants; real IdP test tenant'],
  ['production', 'Invite-only pilot; feature flags (A2 off, WebMonitor off until P7)'],
];

// ---------- 18. Ops & commercial ----------
const team = [
  ['Product owner', 'Customer problem, scope, priorities, commercial outcomes.', C],
  ['Technical lead', 'Architecture, engineering standards, technical decisions.', C],
  ['Full-stack engineer', 'Next.js application, APIs, database, and integrations.', C],
  ['Security engineer/consultant', 'Threat modelling, scanner validation, security review.', C],
  ['AI engineer or experienced integrator', 'AI orchestration, evaluation, and output controls.', C],
  ['QA engineer', 'Functional, regression, authorization, and workflow testing.', C],
  ['DevOps/cloud engineer', 'AWS deployment, monitoring, isolation, recovery.', C],
  ['Pilot customer/design partner', 'Workflow feedback and willingness-to-pay validation.', C],
];
const pricing = [
  ['Free / Trial', 'Free with strict limits', 'Basic checks and limited findings.'],
  ['Starter', '₹1,499/month', 'Limited assets and scheduled checks.'],
  ['Agency', '₹5,999/month', 'Multiple client sites, reporting, remediation workflows.'],
  ['Agency Pro', '₹14,999/month', 'Higher limits, team workflows, integrations, enhanced reporting.'],
  ['Managed Remediation', 'Custom', 'Qualified expert assistance under an agreed scope.'],
];
const ops = [
  ['Pilot model', 'Invite-only paid pilot; manual invoicing; consent recorded in-product; quotas enforced (no payment integration in MVP).', C + ' + ' + R],
  ['Support', 'Named support channel for pilots; target first response 1 business day (assumption); security issues escalated to security engineer.', R],
  ['On-call', 'Business-hours on-call during pilot; paging for kill-switch events, egress anomalies, cross-tenant alerts.', R],
  ['Runbooks', 'Kill switch, credential rotation, scanner outage, AI provider outage (fallback), restore from backup, abuse report on scanning.', R],
  ['Abuse handling', 'Public abuse contact; any third-party complaint → per-asset kill switch within 1 h and investigation.', R],
  ['Vulnerability disclosure', 'security.txt and disclosure policy before pilot (RS-PLAT-007).', C],
  ['Legal', 'Terms covering authorization warranty, automated-vs-human testing distinction, liability limits, referral disclosure — legal review required.', C + ' / ' + Q],
  ['Additional revenue (later)', 'Paid assessments, developer-assisted remediation, managed maintenance, disclosed partner referrals, premium white-label reporting.', C],
];

// ---------- 21. Consistency audit ----------
const consistency = [
  ['CA-01', 'Phase count', 'The prompt asks for 8 phases; the plan has P0 Discovery + 8 delivery phases (P1–P8). P0 is a pre-build validation step with no code. If a strict 8 is required, merge P3 (Findings & triage) and P4 (AI) — not recommended, because AI must not block the core findings workflow.', 'Resolved: noted'],
  ['CA-02', 'FixProof vocabulary', 'Run-level results (passed/failed/inconclusive/error/not_run) and record-level status (verified/partially_verified/failed/unverified) are used consistently in §6.5, §9, stories RS-FIXP-*, tests TC-FIXP-*, API examples.', 'Consistent'],
  ['CA-03', 'Role keys', 'Seven role keys (org_admin, security_lead, analyst, developer, approver, viewer, service) used across matrix, stories, tests and API table. Test wording normalized this revision.', 'Consistent'],
  ['CA-04', 'State names', 'Finding/assessment/remediation/approval/verification/asset states in diagrams, transition tables, stories and tests aligned (e.g. fix_pending_verification, completed_with_errors, accepted_risk).', 'Consistent'],
  ['CA-05', 'Error codes', 'Illegal transitions return 422 transition_not_allowed; kill switch 423; quota 429; self-approval 403.', 'Consistent'],
  ['CA-06', 'WebMonitor', 'Only a provisional adapter and payload exist; no WebMonitor endpoint is specified anywhere. Phase P7 (post-MVP).', 'Consistent'],
  ['CA-07', 'Claims', 'No certification, compliance, customer validation or completed implementation is claimed. OWASP/NIST/AWS are engineering references only.', 'Consistent'],
  ['CA-08', 'MVP vs v1.1 scope', 'v1.1 lists WebMonitor in MVP scope; v2.0 sequences it to P7 because its contract is unknown (DEP-WM-01). Decision recorded in log.', 'Open — product owner to confirm'],
  ['CA-09', 'Requirement preservation', 'All 37 v1.1 FR IDs retained (Appendix C); none removed. Priority changes recorded (FR-007, FR-015).', 'Consistent'],
  ['CA-10', 'Numbers', 'All NFR, retention, sandbox and rate numbers not in v1.1 are labelled assumptions.', 'Consistent'],
  ['CA-11', 'Test coverage', 'Some P2/P3 / Later stories have no test cases yet (listed in Traceability → Coverage gaps); acceptable because they are outside MVP.', 'Known gap'],
];

// ---------- Appendix C: v1.1 preservation map ----------
const preservation = [
  ['1 Executive summary', '§1.2 Vision & positioning, §1.3 Problem', 'Preserved (vision verbatim)'],
  ['2 Business objectives & pilot targets', '§1.6 Objectives & success metrics', 'Preserved; one metric restated (AUD-16)'],
  ['3 Target customers & personas', '§1.4 Personas', 'Preserved'],
  ['4 Product scope & exclusions', '§1.5 Scope / non-goals', 'Preserved; WebMonitor sequenced P7, billing excluded from MVP'],
  ['5 Functional requirements FR-001…FR-045', '§3.1 Functional requirements', 'All IDs preserved; FR-007, FR-015 priority raised; new IDs added in gaps / FR-046+'],
  ['6 AI system design and guardrails', '§8 AI specification', 'Preserved and extended'],
  ['7 Technical architecture', '§11 Architecture, §12 Data model', 'Preserved stack; entities mapped to tables'],
  ['8 Security and privacy requirements', '§3.2 SEC-01…SEC-26, §11.6, §11.7', 'Preserved and made testable'],
  ['9 Non-functional requirements', '§16.3 NFRs', 'Preserved targets; measurements added'],
  ['10 User journeys', '§6.6 End-to-end journeys', 'Preserved; J-03 moved to Later (AUD-13)'],
  ['11 Monetization and packaging', '§18 Operations & commercial', 'Preserved as hypotheses'],
  ['12 Product analytics and KPIs', '§1.6 Success metrics, §18', 'Preserved'],
  ['13 Delivery roadmap', '§17 Implementation plan', 'Re-planned to P0–P8 with T-shirt sizes (AUD-24)'],
  ['14 Team and responsibilities', '§18 Operations & commercial', 'Preserved'],
  ['15 Testing and release gates', '§15 QA plan, §16 Release gates', 'Preserved; RBs mapped to tests'],
  ['16 Risks and mitigations', '§19 Risks', 'Preserved and extended'],
  ['17 Open decisions', '§22 Decision log', 'Preserved; v1.1 recommendations kept as defaults'],
  ['18 Definition of done', '§15.4 Definition of done', 'Preserved verbatim plus additions'],
  ['19 Immediate next actions', '§17 (Phase P0 deliverables)', 'Preserved'],
  ['Appendix A Product principles', '§1.2 Principles', 'Preserved verbatim'],
  ['Appendix B Reference frameworks', '§11 / Appendix A glossary', 'Preserved; explicitly no compliance claim'],
];

const v11Decisions = [
  ['Initial customer segment', 'Web agencies managing multiple websites.'], ['Initial scope', 'Authorized website and API security assessments.'],
  ['First scanner', 'Select an established engine after technical and licensing evaluation. (→ D-01)'], ['AI execution', 'Tool-mediated AI with constrained permissions. (v2.0: no tools in MVP, ADR-006)'],
  ['Remediation mode', 'Reviewable patch and human approval.'], ['Cloud', 'AWS.'], ['Database', 'PostgreSQL.'], ['Integration priority', 'WebMonitor.'],
  ['Commercial model', 'SaaS with optional remediation.'], ['Launch model', 'Invite-only paid pilot.'], ['Autonomous production remediation', 'Excluded from MVP.'],
];

const dodV11 = ['Acceptance criteria pass.', 'Authentication and authorization are tested.', 'Failure states are handled.', 'Required audit events are recorded.',
  'Automated tests cover relevant logic.', 'Security implications are reviewed.', 'Documentation is updated.', 'Monitoring and operational ownership are defined.',
  'AI-generated claims are traceable to evidence where applicable.', 'Deployment follows the approved release process.'];
const dodAdd = ['Negative and cross-tenant tests for every new endpoint.', 'State-machine transitions covered, including illegal ones (422).', 'No status path can present failed/inconclusive/not_run as passed.',
  'Threat-model delta reviewed by someone other than the author where feasible.', 'Feature flags default safe (off) in production.'];

module.exports = { vision, personas, scopeIn, scopeOut, objectives, metrics, kpis, actionTypes, transitions, journeys,
  aiUseCases, aiClaimTypes, aiControls, fixproofStatus, fixproofContents, fixproofRules, wmAdapter, wmInterface,
  modules, trustBoundaries, adrs, sandbox, egress, tables, retention, auditCatalogue, apiConventions, api, jsonExamples,
  events, eventEnvelope, screens, uxRules, qaStrategy, environments, team, pricing, ops, consistency, preservation,
  v11Decisions, dodV11, dodAdd };
