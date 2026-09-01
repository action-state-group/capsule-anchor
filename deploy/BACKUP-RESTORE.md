# Backup / restore drill for the witness log store

The witness log (`anchor_log_entries` and related tables) lives in Cloud SQL
Postgres (`capsule-anchor-pg`). "We have backups configured" is not the same
claim as "a restore actually works" — this runbook is the second claim, and
it must be re-run (not just re-read) before any date where the witness is
depended on publicly.

## 1. Confirm backups + PITR are enabled

```bash
gcloud sql instances describe capsule-anchor-pg --project=PROJECT_ID \
  --format="yaml(settings.backupConfiguration)"
```

Expect `enabled: true`, `pointInTimeRecoveryEnabled: true`. If `enabled: false`,
fix that first — nothing below has anything to restore from:

```bash
gcloud sql instances patch capsule-anchor-pg --project=PROJECT_ID \
  --backup-start-time=05:00 \
  --enable-point-in-time-recovery \
  --retained-transaction-log-days=7 \
  --retained-backups-count=7
```

## 2. Take (or wait for) a backup

```bash
gcloud sql backups create --instance=capsule-anchor-pg --project=PROJECT_ID \
  --description="restore-drill baseline"
gcloud sql backups list --instance=capsule-anchor-pg --project=PROJECT_ID
```

## 3. Capture the expected floor from the LIVE instance

Record the live tree size and root before restoring, so step 5 has something
to compare against:

```bash
curl -s https://witness.agentactioncapsule.org/health | python3 -m json.tool
# note tree_size and latest_root_hash
```

## 4. Clone to a SCRATCH instance — never restore onto prod in place

`gcloud sql instances clone` creates a brand-new instance from the source's
current state (or a `--point-in-time`); it never touches the source. This is
the safe drill shape — prod is never the restore target.

```bash
gcloud sql instances clone capsule-anchor-pg capsule-anchor-pg-restore-drill \
  --project=PROJECT_ID
```

This can take several minutes. Poll with:

```bash
gcloud sql operations list --instance=capsule-anchor-pg-restore-drill --project=PROJECT_ID
```

## 5. Verify the restored data, not just that the clone exists

Connect via the Cloud SQL Auth Proxy (IAM-authenticated, no public IP needed
on the scratch instance) and run the integrity check directly against it —
this checks the append-only hash chain, not just "the app started":

```bash
cloud-sql-proxy PROJECT_ID:us-central1:capsule-anchor-pg-restore-drill --port 6543 &

DB_PASS=$(gcloud secrets versions access latest --secret=capsule-anchor-database-url \
  --project=PROJECT_ID | grep -oE 'capsule_anchor:[^@]+@' | sed 's/capsule_anchor://;s/@//')
python3 deploy/verify_restore.py "postgresql://capsule_anchor:${DB_PASS}@127.0.0.1:6543/capsule_anchor"
```

Expect `PASS: N entries, contiguous log_index, unbroken hash chain.` with
`N` matching (or exceeding, if writes happened between backup and drill) the
`tree_size` captured in step 3. The table is `log_entries` (`PostgresLogStore`,
`packages/capsule_anchor/anchoring/store.py`) — NOT `anchor_log_entries`
(that name belongs to `SqlLogStore` in `sql_store.py`, a different, unused-
in-production store implementation; don't confuse the two schemas).

## 6. Tear down the scratch instance

The drill is done once step 5 passes. Don't leave a second billed Cloud SQL
instance running:

```bash
gcloud sql instances delete capsule-anchor-pg-restore-drill --project=PROJECT_ID --quiet
```

## Result log

Record each drill here (date, backup ID used, verify_restore.py result, who
ran it) so "last restore-tested" has an answer if asked:

| Date | Backup ID | Result | Notes |
|---|---|---|---|
| 2026-09-01 | `1788224520371` (on-demand) | PASS — 534 entries, contiguous, unbroken hash chain, matches live `tree_size` | First drill ever run for this instance; automated backups + PITR were OFF before this task and were enabled as a prerequisite. See [witness-ops-readiness]. |
