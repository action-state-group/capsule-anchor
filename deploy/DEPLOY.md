# Deploying capsule-witness (Cloud Run) — built from the capsule-anchor repo

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
gcloud run deploy capsule-witness \
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

## One service, two domains: witness.aac (primary) + anchor.aac (legacy alias)

**Finalized 2026-08-28 (Steven): ONE Cloud Run service, TWO domain mappings, and "witness"
is the service vocabulary.** This repo's code deploys as the Cloud Run service
**`capsule-witness`** — it runs the full Transparency Service (`WITNESS_ONLY` was removed in
#30). Both hostnames point at that one service:

- **`witness.agentactioncapsule.org`** — primary. The CLL/checkpoint surface: `POST /checkpoints`
  (default; COSE checkpoint wire; verify-before-countersign; a non-checkpoint body gets one named
  400) + `POST /register` (opt-in per-record receipt) + `/health`.
- **`anchor.agentactioncapsule.org`** — legacy alias of the *same* service, still answering its
  legacy routes (`/v1/digest`, `/transparency/register-statement`, `/anchor/*`) for existing
  callers. "anchor" survives only as this deprecated alias and never appears as service vocabulary
  in new docs; its eventual removal is a later decision.

Note the naming split: the **repo/codebase** is still `capsule-anchor` and the secret/instance
names (`capsule-anchor-signing-key`, `capsule-anchor-pg`, `CAPSULE_ANCHOR_*`) are unchanged — they
are codebase/infra identifiers, not the service name. Only the Cloud Run **service** is
`capsule-witness`.

**These are Steven's clicks — nothing below goes live without running it.**

```bash
# Deploy the service from this repo checkout (current main):
gcloud run deploy capsule-witness \
  --source . --project=PROJECT_ID --region=us-central1 --port=8000 --allow-unauthenticated \
  --add-cloudsql-instances=PROJECT_ID:us-central1:capsule-anchor-pg \
  --set-secrets=CAPSULE_ANCHOR_SIGNING_KEY=capsule-anchor-signing-key:latest,CAPSULE_ANCHOR_DATABASE_URL=capsule-anchor-database-url:latest

# Map BOTH hostnames onto the one capsule-witness service:
gcloud beta run domain-mappings create --service=capsule-witness \
  --domain=witness.agentactioncapsule.org --region=us-central1 --project=PROJECT_ID
gcloud beta run domain-mappings create --service=capsule-witness \
  --domain=anchor.agentactioncapsule.org --region=us-central1 --project=PROJECT_ID
```

Each `domain-mappings create` prints the DNS record to add — normally a single
`CNAME  <name>  ghs.googlehosted.com.`. TLS provisions automatically once DNS resolves (minutes
to ~an hour); a remap of an existing hostname triggers a fresh managed-cert provision, so expect a
short propagation window. Both hostnames answer with the same `key_id`.

Verify both domains serve from the one service:

```bash
curl -s https://witness.agentactioncapsule.org/health | python3 -m json.tool
curl -s https://anchor.agentactioncapsule.org/health   | python3 -m json.tool   # same key_id

curl -s -o /dev/null -w '%{http_code}
' -X POST https://witness.agentactioncapsule.org/checkpoints \
  -H 'content-type: application/cll-checkpoint+cbor' --data-binary 'nope'        # 400 (named refusal)
curl -s -o /dev/null -w '%{http_code}
' -X POST https://witness.agentactioncapsule.org/register \
  -H 'content-type: application/json' -d '{"capsule_id":"'"$(printf 'e%.0s' $(seq 64))"'"}'  # 2xx
curl -s -o /dev/null -w '%{http_code}
' -X POST https://anchor.agentactioncapsule.org/v1/digest -d '{}'  # 422 (legacy route live)
```

**A third hostname, `ts.agentactioncapsule.org` ("ts" = Transparency Service), must also be
remapped — it is NOT optional.** It is the hardcoded default in the shipped `agent-action-capsule`
library (`anchor.py`: `_DEFAULT_TS_URL = "https://ts.agentactioncapsule.org"`), so deleting the old
service while `ts.aac` still points at it breaks every existing install's default anchor path. Remap
it like the others, then retire the old service only after all THREE hostnames are green on
`capsule-witness`:

```bash
# remap the Transparency-Service alias (library default) onto capsule-witness:
gcloud beta run domain-mappings delete --domain=ts.agentactioncapsule.org --region=us-central1 --project=PROJECT_ID
gcloud beta run domain-mappings create --service=capsule-witness --domain=ts.agentactioncapsule.org --region=us-central1 --project=PROJECT_ID
curl -s https://ts.agentactioncapsule.org/health   # 200, same key_id

# confirm NOTHING still targets capsule-anchor, then delete it:
gcloud beta run domain-mappings list --region=us-central1 --project=PROJECT_ID
gcloud run services delete capsule-anchor --region=us-central1 --project=PROJECT_ID
```

(`ts.aac` and `anchor.aac` both survive as legacy aliases of `capsule-witness`; new library code
should default to `witness.aac`, with the old names honored via DNS mapping, not code branches.)


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
  gcloud run services update capsule-witness \
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

## Uptime monitoring

`deploy/monitoring.sh` creates BOTH the read-path and checkpoint-submit-path
checks as code (not manual Cloud Console clicks), wired to an existing
notification channel:

```bash
PROJECT_ID=PROJECT_ID \
NOTIFICATION_CHANNEL=projects/PROJECT_ID/notificationChannels/CHANNEL_ID \
  deploy/monitoring.sh
```

- **Read path**: `GET /health` on `witness.agentactioncapsule.org`, pings every
  1 min from global PoPs, alerts on any non-200.
- **Submit path**: `POST /checkpoints` with a deliberately-invalid body,
  expecting the documented named-refusal `400`. This proves the write path is
  alive and enforcing its input contract without needing a real allowlisted
  submitter identity (see [witness-external-submitter]) — a 200, a 5xx, or a
  timeout all fail the check.

Both checks page the same channel as the legacy `anchor.aac /health` check
(kept, unchanged) within ~2 minutes of a failure.

**Public status answer, if asked:** witness.agentactioncapsule.org is monitored
24/7 on both its read and checkpoint-submit paths from Google's global uptime
network, with alerting to on-call within two minutes of any failure.

Smoke-test the write path after each deploy (substitute a real 64-hex capsule_id):

```bash
# anchor a synthetic test capsule — no real customer data
curl -s -X POST https://anchor.agentactioncapsule.org/v1/digest \
  -H "Content-Type: application/json" \
  -d '{"capsule_id":"0000000000000000000000000000000000000000000000000000000000000001"}' \
  | python3 -m json.tool

# verify /health reports ok=true and tree_size > 0
curl -s https://anchor.agentactioncapsule.org/health | python3 -m json.tool

# verify /anchor/sth returns a signed tree head
curl -s https://anchor.agentactioncapsule.org/anchor/sth | python3 -m json.tool
```

## Load sanity (burst testing)

`deploy/burst_test.py` fires concurrent requests at `POST /checkpoints` and
the read routes at a configurable rate, reporting a status-code histogram and
latency percentiles per simulated submitter — including a distinguished
"demo identity" so a run can confirm noisy background submitters don't starve
the one identity actually demoing live.

**Do not run this against production before [witness-external-submitter]
lands** — before that, `/checkpoints` has only a single global rate limit, so
a burst test proves the global limiter works, not that per-submitter limits
protect the demo identity from other traffic:

```bash
python3 deploy/burst_test.py \
  --host https://witness.agentactioncapsule.org \
  --demo-key-hex "$DEMO_IDENTITY_ED25519_SEED_HEX" \
  --demo-log-id demo-webinar-2026-09-09 \
  --noisy-submitters 5 --rate 20 --duration 30
```

## Revision verification

`deploy/check_revision.sh` mechanically checks the deployed Cloud Run revision
against `origin/main`, per the 2026-08-27 stale-deploy rule (fetch, fast-
forward, THEN deploy) — no eyeballing timestamps:

```bash
PROJECT_ID=PROJECT_ID deploy/check_revision.sh
```

Exact match requires deploying with `cloudbuild.yaml`'s `_TAG=$(git rev-parse
--short HEAD)` (see that file); a `--source .` deploy is checked by timestamp
inference instead and says so explicitly.

## Backup / restore

See [deploy/BACKUP-RESTORE.md](BACKUP-RESTORE.md) — a restore drill runbook
plus `deploy/verify_restore.py`, an integrity check for the log store's
append-only hash chain. Automated backups + point-in-time recovery must be
enabled on `capsule-anchor-pg` (`gcloud sql instances describe
capsule-anchor-pg --format="yaml(settings.backupConfiguration)"` — expect
`enabled: true`); a restore drill should be re-run, not just re-read, before
any date the witness is depended on publicly.
