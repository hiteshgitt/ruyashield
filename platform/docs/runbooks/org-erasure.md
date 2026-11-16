# Runbook: hard erasure of a deleted organization

> **Status: written, not yet exercised.** This procedure has not been run against real data.
> Test it on a restored copy (see `backup-restore.md`) before using it in production.

## Background
- An org admin requests deletion in **Settings → Organization** (step-up MFA, typed slug, reason).
  Admins are notified and can cancel during a 30-day grace period. A legal hold blocks the request.
- After 30 days the worker's retention job (`runRetention`, daily) calls `finalize_org_deletions()`, which sets
  `orgs.deleted_at` and writes an `org.deleted` audit event. From then on members can no longer use the org.
- **Rows are not erased automatically.** Many tables are append-only by trigger (audit events, evidence,
  AI analyses, approvals, FixProof records, reports), and erasing them is deliberately a manual,
  two-person step. That is this runbook.

## Preconditions (check all)
1. `SELECT id, slug, deleted_at, legal_hold FROM orgs WHERE slug = '<slug>';` shows `deleted_at` set and
   `legal_hold = false`. Stop if a legal hold is set or the org is not deleted.
2. A second person has reviewed the request (ticket reference recorded below).
3. A fresh backup exists, and the retention period for backups that still contain this org is understood
   (backups expire on their own schedule; note the date the last copy expires).
4. If the customer asked for an export, it was delivered before this step.

## Procedure
Run as a superuser in a single transaction. `session_replication_role = replica` disables the append-only
triggers for this transaction only.
```sql
BEGIN;
SET LOCAL session_replication_role = replica;
-- Every table with an org_id column; review the list before deleting.
SELECT table_name FROM information_schema.columns
 WHERE table_schema = 'public' AND column_name = 'org_id' ORDER BY table_name;
-- For each table above (children before parents), then the org itself:
DELETE FROM <table> WHERE org_id = '<org-id>';
DELETE FROM memberships WHERE org_id = '<org-id>';
DELETE FROM orgs WHERE id = '<org-id>';
-- Confirm nothing is left:
-- SELECT '<table>', count(*) FROM <table> WHERE org_id = '<org-id>';  (repeat per table; all must be 0)
COMMIT;
```
- Users who belonged only to this org keep their `users` row (they may belong to other orgs).
  Remove users with no remaining membership only if the customer asked for it.
- Record the erasure in the operator log (outside the tenant, since the tenant's audit chain is gone).

## Record
| Date | Org slug | Org id | Ticket | Performed by | Reviewed by | Last backup copy expires |
|------|----------|--------|--------|--------------|-------------|--------------------------|
| _none yet_ | | | | | | |
