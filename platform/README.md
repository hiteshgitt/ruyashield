# RuyaShield platform (P1 foundation + P2 core assessment + P3 findings & triage + P4 AI investigation + P5 remediation & approvals + P6 verification & FixProof + P7 WebMonitor referrals & regression re-tests + P8 reporting & hardening)

Multi-tenant foundation for RuyaShield: sign-in, organizations and roles, asset ownership
verification / authorization, kill switches, and a tamper-evident audit log (P1), plus
scope-bound assessments of eligible assets with a small passive / safe-active check set and
deduplicated findings (P2), and finding triage with hashed evidence, prioritization, assignment,
comments and time-boxed risk acceptance (P3), and verification re-tests with tamper-evident FixProof
records (P6), evidence-bound AI explanations and remediation suggestions behind a gateway (P4), and
remediation plans with sandboxed patch tests and two-person approvals (P5), and consented WebMonitor
referrals plus scheduled regression re-tests (P7), and reports, API tokens, notifications, support access, legal
hold, org deletion and data retention (P8).

## Findings & triage (P3)

- `/findings` lists findings by priority (severity × confidence × asset criticality, version `prio/1`,
  inputs shown); filters for asset, severity, confidence, status and owner.
- `/findings/[id]` shows status history, occurrences, evidence (redacted, with integrity status),
  comments with @mentions, assignment and the allowed status changes for your role.
- API: `GET /v1/evidence/{id}`, `GET /v1/evidence/{id}/raw` (audited), `POST /v1/findings/{id}/transitions`.
- Lifecycle: `new → triaged → confirmed → in_remediation → fix_pending_verification`, plus
  `false_positive`, `accepted_risk`, and system-only `reopened`, `stale`, `resolved_verified`.
- Evidence is stored in Postgres (`evidence_items`). Object storage (S3 / SSE-KMS) is not implemented.

### Implemented checks (P2)

| Check | Class | What it does |
|---|---|---|
| `dns.caa@1` | P | Looks up CAA records for the host |
| `dns.email_posture@1` | P | Looks up SPF and DMARC records |
| `tls.cert_expiry@1` | A1 | One TLS handshake; reports expired / soon-expiring / unreadable certificates |
| `http.security_headers@1` | A1 | Up to 4 GET requests to in-scope paths; reports missing security headers |
| `x.exploit_payloads@1` | X | Catalogue placeholder only — prohibited, never executed |

Certificate-transparency and dependency checks from the PRD are not implemented.

## Run locally

```bash
docker compose up -d          # Postgres 17 on 127.0.0.1:5450, Mailpit on :1035 (UI http://localhost:8035)
npm install
npm run migrate               # applies db/migrations/*.sql as the owner role
npm run dev                   # http://localhost:3200
npm run worker                # outbox worker (invite emails, re-verification, assessment runs) — separate terminal
```

Configuration lives in `.env.local`. `AUTH_PROVIDER=dev` gives a local sign-in form with
simulated MFA; it is refused when `NODE_ENV=production`. Real deployments set
`AUTH_PROVIDER=oidc` and `OIDC_ISSUER` / `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET`.

## Checks

```bash
npm run typecheck
npm run lint
npm test                      # unit tests; DB tests are skipped without DATABASE_URL
npm run test:db               # RLS isolation, audit chain and assessment lifecycle tests (stop the worker first)
npm run build
```

CI (`../.github/workflows/ci.yml`) runs all of the above against a Postgres service.

## AI investigation (P4)

- Off by default. An org admin or security lead turns it on in **Settings → Safety** with a reason and a monthly token
  budget (0 = no tokens). The `ai` kill switch blocks every request (423).
- Provider (`RUYA_AI_PROVIDER`): `disabled` (default, 503), `fixture`, or `openai`. **`fixture` is not a language model**:
  it is a deterministic offline stand-in that restates the finding and its first evidence item, and every
  summary says so. It exists for development, tests and the eval harness.
- `openai` uses any OpenAI-compatible endpoint (`OPENAI_BASE_URL`, `OPENAI_API_KEY`, `OPENAI_MODEL`). It sends the
  redacted bundle to that service and costs money. It is never chosen implicitly, and it has **not been evaluated or
  released in this build**. To enable it: `npm run ai:eval -- --provider openai --promote` (sends only the synthetic
  golden cases), then set `RUYA_AI_PROVIDER=openai`.
- Gateway: evidence is redacted (secrets, credentials, personal data) before it leaves; untrusted evidence is fenced
  inside a per-request random boundary and treated as data, not instructions; no tools or functions are offered to the model;
  calls have a 30 s timeout, one retry and a circuit breaker; usage counts against the budget; requests are idempotent.
- Output is validated before it is stored. Claims that cite no real evidence label, reference an unknown check or URL, or
  assert compromise or resolution are dropped. Inferences are capped at "likely". Every recommendation requires approval,
  and an analysis with no evidence is `inconclusive`. Invalid replies get one repair attempt, then the analysis is `rejected`.
- AI never changes a finding's status. Results are labelled "AI-generated — review before use" and record their provenance
  (provider/model, prompt id@version, template SHA-256, input SHA-256, redaction version). Analyses and claims are append-only.
- Release gate: a prompt version can be used with a provider/model only after a passing eval run
  (`npm run ai:eval -- --provider fixture --promote`). Thresholds: schema validity 100 %, ≥ 95 % evidence-backed claims, and zero
  unsupported compromise claims, injection-induced resolution claims, secret leaks and confirmed inferences.
- API: `POST/GET /v1/findings/{id}/ai-analyses`.
- Not in P4: turning a recommendation into a draft remediation plan (RS-AI-004 handoff, moved to P5), the AI diagnostic plan
  for follow-up checks (RS-AI-007 / FR-025), and approved customer context (RS-AI-008 / FR-026).

## Remediation & approvals (P5)

- A finding gets remediation **plans**: `guided` (steps the customer applies themselves) or `patch` (a unified diff
  against a connected repository at a pinned base commit). Plans can start from a reviewed AI recommendation; the
  plan records that link. States: draft → proposed → (patch) test_passed / test_failed → awaiting_approval →
  approved → applied_by_customer → verifying → completed | remediation_failed.
- **Approvals** are bound to the SHA-256 of the exact plan content. Any edit invalidates open or granted approvals
  and sends the plan back to proposed; deciding against an older hash is refused (409 `stale_review`).
  Policy is two-person by default (the requester cannot decide, 403 `self_approval`); an org that turns this off
  still never lets an org admin approve their own request. Rejection needs a reason; approvals expire.
- A patch plan must pass its **sandbox test** before approval (an untested override needs a ≥ 10-character reason
  and is recorded). Tests run the integration's snapshot of test commands under bubblewrap (no network, cleared
  env, read-only system, prlimit caps, timeout). Only all-zero exits pass; timeouts and sandbox errors are never passes.
- Approving a patch plan only opens a `ruyashield/…` branch in the repository. **RuyaShield never merges or pushes
  to the default branch** (a static test enforces no merge/rebase/force-push calls). A guided plan is marked
  applied by a person with a note, which consumes the approval.
- A plan is `completed` only when a verification re-test comes back `verified`; a failed re-test marks it
  `remediation_failed`. FixProof now records the remediation (plan, content hash, approval, approver, branch/merge
  observed, whether it came from AI) or states that the fix was made outside RuyaShield.
- UI: the Remediation panel on each finding, `/approvals`, `/settings/integrations` (Repositories).
- API: `GET/POST /v1/findings/{id}/remediation-plans`, `GET/PATCH /v1/remediation-plans/{id}`,
  `POST …/{id}/submit`, `POST …/{id}/sandbox-runs`, `POST …/{id}/approval-requests`, `POST …/{id}/applied`,
  `GET /v1/approvals`, `POST /v1/approvals/{id}/decision` (step-up), `POST /v1/approvals/{id}/revoke`,
  `GET/POST /v1/integrations/repository`, `DELETE /v1/integrations/repository/{id}`, `POST /webhooks/repository`
  (HMAC per integration, ±5 min timestamp; a delivery only prompts a re-read of the repository, never trusted as fact).
- Env: `RUYA_LOCAL_REPO_ROOT` (directory holding allowed local repositories), `RUYA_WEBHOOK_SECRET` (≥ 32 chars).
- **Limits, stated plainly:** the only repository adapter is a provisional local-git one; GitHub/GitLab are not
  integrated. The sandbox is process isolation on the worker host, not a microVM, and has no process-count cap
  (needs cgroups). Production needs VM-level isolation.

## Verification & FixProof (P6)

- On a finding in `fix_pending_verification`, **Re-test now** queues a verification run that re-runs only the
  checks that produced the finding, against the same asset, under the same eligibility, scope guard, rate limits
  and kill switch as an assessment. One active re-test per finding; requests are idempotent.
- Outcomes: `verified` (every re-run check looked at the same location and no longer saw the issue),
  `partially_verified`, `failed` (re-detected), `unverified` (errors, redirects to another location, nothing
  conclusive). Kill switch, lapsed authorization or max duration give `not_run` with no traffic sent.
- Only `verified` moves the finding to `resolved_verified`; only `failed` reopens it (and notifies the owner).
  Everything else leaves it in `fix_pending_verification`. Inconclusive is never shown as passed.
- Every completed run writes a FixProof record: canonical-JSON content, SHA-256, per-org sequence and
  `prev_sha256` chain, append-only (only "superseded" may be set, once; reasons `newer_verification`, `regression`).
- API: `POST/GET /v1/findings/{id}/verification-runs`, `GET /v1/fixproofs/{id}`,
  `GET /v1/fixproofs/{id}/export?format=json|pdf` (audited). A record whose hash or chain link fails is withheld (409).
- Offline check of a JSON export: `npm run verify-fixproof -- fixproof.json [previous.json]` (exit 0 match, 1 mismatch, 2 usage).
- FixProof records remediation from P5 (RS-FIXP-005). Not yet: FixProof inside reports (TC-FIXP-015); P8 reports do not include FixProof records.

## WebMonitor referrals & regression re-tests (P7)

P7 is post-MVP (D-10). The WebMonitor adapter is **provisional** (D-14 / DEP-WM-01): no WebMonitor API
contract exists, so none is assumed. Outbound `publishResult` returns `not_sent: no_contract`.

- Inbound handoffs: `POST /v1/integrations/webmonitor/handoffs`, HMAC-SHA256 over `timestamp.body`
  (`WEBMONITOR_HANDOFF_SECRET`, ≥ 32 chars), ±5 min tolerance, nonce single-use. Without the secret the
  endpoint answers 503 `handoffs_disabled`. Unknown fields are dropped; a handoff never starts a scan.
- Consent page `/referrals/{token}`: single-use token, consent text versioned (`CONSENT_TEXT_VERSION`; a changed
  text gives 409). Accept records three consent subjects (assessment, result sharing, charges); billing consent is
  recorded only, nothing is charged. Decline and delete are supported; a deleted referral is never published.
- An assessment may cite a referral only if it is consented, claimed by the same org and for the same host.
  Unclaimed referrals are invisible to other orgs (RLS). Ownership verification / authorization still applies.
- Link-back summary has exactly 5 fields (externalRef, assessment status, severity counts, FixProof status, link);
  no hosts, titles, evidence or user ids. Funnel counts only: `npm run referral:funnel`.
- Not built: FR-045 (WebMonitor-side monitoring hooks), pending a contract.
- Regression re-tests: org admins set an interval (1–90 days, Settings → Safety; off by default). The worker
  re-tests `resolved_verified` findings with trigger `scheduled_regression`, at most once per finding per day.
  Re-detected → finding reopened and owner notified. Lapsed authorization or kill switch → `not_run`, notified,
  finding unchanged. `not_run` and inconclusive are never shown as passes.

## Reporting & hardening (P8)

- Reports: `POST/GET /v1/reports`, `GET /v1/reports/{id}` (CSV or PDF, optionally one client group). The file is
  stored once with its SHA-256 (returned as `X-Report-SHA256`); `ruya_app` may only INSERT/SELECT reports. Every
  report states it is not a certification and lists its limitations. CSV cells starting with `= + - @`, tab or CR are neutralized.
  Restricted members see only reports they generated. Downloads are audited.
- API tokens (FR-058): `POST/GET /v1/tokens`, `DELETE /v1/tokens/{id}`. `Authorization: Bearer rs_...` acts as the
  creator, narrowed to the chosen scopes (403 `insufficient_scope`), 1–366 days, shown once, stored as a SHA-256 hash.
  A token never passes step-up, so it cannot approve, delete, administer or create tokens. `GET /v1/findings` for scripts.
- Notifications (FR-056): in-app list and per-kind preferences. Security-critical kinds (failed verification,
  regression, regression not run, risk expired, kill switch, support access, org deletion) cannot be turned off.
- Support access (RS-PLAT-007): operators listed in `RUYA_OPERATOR_EMAILS` (empty = none) with fresh MFA and a
  reason get read-only access to one org for 5–240 minutes. It is written to that org's audit chain and its admins
  are notified.
- Legal hold and org deletion: an admin requests deletion by typing the org slug; it can be cancelled for 30 days,
  then the org is closed and access ends. A legal hold blocks deletion and retention. Hard erasure of a closed org is
  a manual step: `docs/runbooks/org-erasure.md`.
- Retention (daily, in the worker): evidence, AI analyses, notifications and reports after 1 year; evidence on closed
  findings and audit events after 3 years. Findings rows and status history are kept (FixProof points at them), only
  their captured evidence is scrubbed. Purged audit ranges leave an anchor (last purged hash) so `verify_audit_chain` still passes.
- Runbooks: `docs/runbooks/backup-restore.md`, `docs/runbooks/org-erasure.md` — written, **not yet exercised**
  (no restore drill or penetration test has been performed). `docs/security.txt.template` needs real contacts
  before it is published.

## Security invariants

- The app connects as `ruya_app` (no superuser, no BYPASSRLS); every tenant table has RLS keyed on `app.org_id`.
- `audit_events` is append-only and hash-chained; UPDATE/DELETE are rejected by trigger.
- Outbound verification requests go through the egress guard (no private/metadata addresses, pinned DNS, size/time limits).
- A verification check that cannot be completed is reported as an error (inconclusive), never as passed.
- Assessments launch only for eligible assets (verified ownership or a live attestation) and only with check classes that eligibility allows; class X is never run.
- Each run is bound to an immutable scope version; the job carries an HMAC token (`JOB_TOKEN_SECRET`) over the scope hash, and the worker refuses a job whose token or scope does not match.
- Every outbound request of a check passes the per-assessment scope guard (host/path in scope, total and per-check budgets, ≤ 2 req/s per host) and the egress guard; cross-host redirects are refused.
- Kill switch, authorization lapse, window end and max duration are re-checked before every check; a stopped run's remaining checks are recorded as skipped.
- Only a run where every planned check succeeded is `completed`. Partial runs are `completed_with_errors`, runs with no successful check are `failed`; neither is ever shown as clean.
- A dead worker's run is re-queued (with a freshly signed token) up to 3 attempts, then `timed_out` (`sweep_assessments()`, migrations 0002/0003).
- No person can set `resolved_verified`; only a verification re-test with outcome `verified` may (P6). "Mark fix applied" leaves a finding open in `fix_pending_verification`, and seeing it again reopens it.
- Evidence items are SHA-256 hashed and append-only (UPDATE/DELETE rejected by trigger). An item whose hash no longer matches is withheld and the failure audited; secrets and personal data are redacted on display, and raw download requires `evidence.download_raw` and is audited.
- A failed or skipped check never counts as a miss; a `new` finding goes `stale` only after 2 consecutive successful runs that did not see it.
- False positives need a ≥ 20-character justification; different evidence later sends them back to triage.
- Risk acceptance (org admin / security lead only) needs a justification, compensating controls and an expiry ≤ 365 days; the worker returns expired acceptances to `triaged`.
- Findings can be assigned only to members who can see the asset (client-group restrictions apply); mentions resolve only to such members.
- WebMonitor handoffs are signature-checked, replay-protected and never trigger traffic; referral data is shared back only with recorded consent and only as the minimal summary.

## Migrations

`db/migrations/*.sql` are applied in filename order, each in one transaction, and recorded in
`schema_migrations`. Never edit an applied file; add a new one.

- `0001` — P1 foundation (tenancy, RLS, audit chain, outbox)
- `0002` — assessments, scope versions, check runs, findings, usage
- `0003` — `sweep_assessments()` no longer copies the outbox payload on lease expiry; the app re-enqueues the retry with a new token
- `0004` — findings triage: evidence items, status history, risk acceptances, comments, asset criticality, `due_risk_expiries()`
- `0005` — verification runs, append-only hash-chained FixProof records, `stuck_verification_runs()`
- `0006` — AI settings, analyses and claims (append-only), usage, eval runs and prompt releases
- `0007` — remediation plans, approvals, sandbox runs, repository integrations, code changes, webhook deliveries
- `0008` — `stuck_sandbox_runs()` for the sandbox lease sweep
- `0009` — WebMonitor referrals, consents, referral events, org regression interval
- `0010` — reports, API tokens, notifications, break-glass, legal hold / org deletion, retention, audit anchors
