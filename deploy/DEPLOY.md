# Deploying capsule-anchor (Cloud Run)

## Runtime configuration

| Variable | Source in prod | Purpose |
|---|---|---|
| `CAPSULE_ANCHOR_SIGNING_KEY` | Secret Manager | Hex-encoded Ed25519 seed. **Required** — startup fails without it (see [Key Management](KEY-MANAGEMENT.md)). |
| `CAPSULE_ANCHOR_SIGNING_KEY_FILE` | Mounted secret file | Alt: path to PEM/seed file. |
| `CAPSULE_ANCHOR_DATABASE_URL` | Secret Manager | Postgres connection URL. **Required** — startup fails without it. |
| `CAPSULE_ANCHOR_HOST` / `CAPSULE_ANCHOR_PORT` | env | Bind address (default `0.0.0.0:8000`). |
| `CAPSULE_ANCHOR_TSA_ENABLED` | env | Set to `1` to enable RFC 3161 TSA timestamps (opt-in). |
| `CAPSULE_ANCHOR_TSA_URL` | env | Override TSA endpoint (default: FreeTSA). |
| `CAPSULE_ANCHOR_INSECURE_EPHEMERAL_KEY` | env | **Dev only.** Set `1` to allow startup without a configured signing key. Never set in production. |
| `CAPSULE_ANCHOR_INSECURE_IN_MEMORY` | env | **Dev only.** Set `1` to allow startup without `CAPSULE_ANCHOR_DATABASE_URL`. Never set in production. |

**Fail-closed defaults:** the service refuses to start without both `CAPSULE_ANCHOR_SIGNING_KEY` and
`CAPSULE_ANCHOR_DATABASE_URL`. Silent in-memory storage would lose the CT log on restart (prior receipts
become unverifiable); an ephemeral signing key would change the authority identity on every restart.

## Cloud SQL setup

```bash
# 1. Create the Cloud SQL Postgres instance (if not already provisioned)
gcloud sql instances create capsule-anchor-pg \
  --database-version=POSTGRES_15 \
  --tier=db-f1-micro \
  --region=us-central1 \
  --project=PROJECT_ID

# 2. Create the database
gcloud sql databases create capsule_anchor \
  --instance=capsule-anchor-pg \
  --project=PROJECT_ID

# 3. Create a DB user
gcloud sql users create anchor \
  --instance=capsule-anchor-pg \
  --password=STRONG_PASSWORD \
  --project=PROJECT_ID

# 4. Store the connection URL in Secret Manager
# Cloud Run unix-socket form (no TCP, no VPC connector needed):
echo -n "postgresql://anchor:STRONG_PASSWORD@/capsule_anchor?host=/cloudsql/PROJECT_ID:us-central1:capsule-anchor-pg" | \
  gcloud secrets create capsule-anchor-database-url --data-file=- --project=PROJECT_ID
```

## Quick deploy (production — Postgres-backed, stable key)

```bash
# 1. Generate and store the signing key
python3 -c "import os; print(os.urandom(32).hex())" | \
  gcloud secrets create capsule-anchor-signing-key --data-file=- --project=PROJECT_ID

# 2. Deploy with Cloud SQL + secrets
gcloud run deploy capsule-anchor \
  --source . \
  --project=PROJECT_ID \
  --region=us-central1 \
  --port=8000 \
  --allow-unauthenticated \
  --add-cloudsql-instances=PROJECT_ID:us-central1:capsule-anchor-pg \
  --set-secrets=\
CAPSULE_ANCHOR_SIGNING_KEY=capsule-anchor-signing-key:latest,\
CAPSULE_ANCHOR_DATABASE_URL=capsule-anchor-database-url:latest
```

No `--max-instances` cap is needed when using Postgres: all instances share the same append-only log,
and the rate limiter is per-instance (see HA notes below). Remove `--max-instances=1` from any
prior deploy commands — it was only safe with in-memory storage.

## High-availability (HA)

With Postgres as the backing store, multiple Cloud Run instances are safe:

- **Log integrity**: all instances write to the same Postgres database; `log_index` is a BIGINT
  primary key, so concurrent appends serialize correctly.
- **Dedup**: the `submitted_statements` table uses `ON CONFLICT (entry_hash) DO NOTHING`, so
  duplicate submissions from concurrent instances are idempotent.
- **Rate limiter**: `_SlidingWindowLimiter` is per-process. For cluster-wide rate limiting, add
  Cloud Armor (`--security-policy`) in front of the Cloud Run service.
- **Recommended minimum HA config**:
  ```bash
  gcloud run services update capsule-anchor \
    --region=us-central1 \
    --min-instances=1 \
    --max-instances=10 \
    --project=PROJECT_ID
  ```
  `--min-instances=1` avoids cold-start latency for the first request on a new instance.

## Key management and rotation

See [deploy/KEY-MANAGEMENT.md](KEY-MANAGEMENT.md) for the full key rotation story,
GCP KMS path, and historical-receipt verification.

## cloudbuild.yaml deploy

```bash
gcloud builds submit --config deploy/cloudbuild.yaml \
  --substitutions \
    _REGION=us-central1,\
    _REGISTRY=us-central1-docker.pkg.dev/PROJECT_ID/anchor,\
    _SIGNING_KEY_SECRET=capsule-anchor-signing-key \
  --project=PROJECT_ID
```
