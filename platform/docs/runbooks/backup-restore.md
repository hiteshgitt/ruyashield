# Runbook: database backup and restore

> **Status: written, not yet exercised.** No restore drill has been performed against this procedure.
> Run a drill (step 4) before relying on it, and record the date and result at the bottom of this file.

## What must be backed up
- The Postgres database (all application data, evidence, audit chain, reports).
- Secrets held outside the database: `DATABASE_URL`, `DATABASE_OWNER_URL`, `OIDC_CLIENT_SECRET`,
  `JOB_TOKEN_SECRET`, `RUYA_WEBHOOK_SECRET`, SMTP credentials. Keep these in the secret store, never in the dump.

## 1. Take a backup
Run as the owner role (`ruya_owner`), which owns every table, so the dump is complete:
```sh
pg_dump --format=custom --no-owner --file=ruyashield-$(date -u +%Y%m%dT%H%MZ).dump "$DATABASE_OWNER_URL"
sha256sum ruyashield-*.dump > ruyashield.dump.sha256
```
- Encrypt the dump at rest (it contains evidence and audit data) and store it off-host.
- Target: daily, keep 35 days. This is a proposed policy, not a configured job; no scheduler is set up in this repo.

## 2. Restore into an empty database
```sh
createdb ruyashield_restore
psql -d ruyashield_restore -c "CREATE ROLE ruya_app LOGIN" # only if the role does not exist yet
pg_restore --no-owner --role=ruya_owner -d ruyashield_restore ruyashield-<stamp>.dump
```
Then apply any migrations newer than the dump: `npm run migrate` with `DATABASE_OWNER_URL` pointing at the restore.

## 3. Check the restore
1. Row counts of `orgs`, `findings`, `audit_events` match what the source reported at dump time.
2. The audit chain of every org verifies (`verify_audit_chain()` checks the org named by `app.org_id`,
   starting from its latest retention anchor; run it once per org):
   ```sql
   SELECT set_config('app.org_id', '<org-id>', false);
   SELECT * FROM verify_audit_chain();   -- first_broken_seq must be NULL
   ```
   Any break must be investigated before the restore is used. Do not mark the restore good otherwise.
3. Report files still match their stored hashes (`reports.sha256`).
4. Sign in to the app against the restore and open a finding, its evidence and the audit page.

## 4. Restore drill (to be done)
Restore the latest backup into a scratch database, run step 3, and record the result here:

| Date | Backup used | Duration | Audit chains OK | Result | By |
|------|-------------|----------|-----------------|--------|----|
| _not yet performed_ | | | | | |
