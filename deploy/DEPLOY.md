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

## Domain mapping: witness.aac (primary) + anchor.aac (legacy alias)

**Ruling (2026-08-27, Steven): ONE witness endpoint, ONE Cloud Run service, TWO domain
mappings.** This supersedes the earlier "separate `capsule-witness` deployment +
`WITNESS_ONLY` env flag" plan — that mode is removed from the code (see CHANGELOG). There
is no server-side role flag and no second deployment: `witness.agentactioncapsule.org`
becomes the CLL/checkpoint-primary name (`POST /checkpoints` default, `POST /register`
opt-in) and `anchor.agentactioncapsule.org` retires to a plain alias of the exact same
service, still answering its legacy routes (`/v1/digest`, `/transparency/register-statement`,
`/anchor/*`) for existing callers.

**These are Steven's clicks — nothing below goes live without running it.**

```bash
# (once) verify the subdomain if not already covered by an apex verification
# in Search Console for agentactioncapsule.org:
gcloud domains verify witness.agentactioncapsule.org      # skip if already verified

# Map witness.aac onto the EXISTING capsule-anchor Cloud Run service (not a new one):
gcloud run domain-mappings create \
  --service=capsule-anchor \
  --domain=witness.agentactioncapsule.org \
  --region=us-central1 \
  --project=PROJECT_ID
```

`gcloud` prints the DNS record(s) to add at the registrar/zone for
`agentactioncapsule.org` — add exactly what it prints, the same procedure already used
for `anchor.aac`. For a Cloud Run subdomain mapping this is normally a single:

```
Type: CNAME   Name: witness   Value: ghs.googlehosted.com.
```

(If it instead lists 4×A + 4×AAAA, add those.) TLS provisions automatically once DNS
resolves (a few minutes to ~an hour). No `--set-secrets`, no new Cloud SQL grants, no new
signing key — this mapping points at the identical running service, so it inherits
`CAPSULE_ANCHOR_SIGNING_KEY` / `CAPSULE_ANCHOR_DATABASE_URL` and answers with the same
`key_id`.

**`anchor.agentactioncapsule.org` keeps its existing domain mapping unchanged** — it is
already mapped to `capsule-anchor`; nothing to redo. It becomes vocabulary-deprecated
(docs mark its registration routes "record registration (legacy)"; "anchor" never
appears as service vocabulary in new docs) — its removal is its own, later decision
(~a quarter out), not part of this change.

Add a second uptime check alongside the existing `anchor.aac` one (same `/health` path,
same alerting policy):

```bash
gcloud monitoring uptime create "capsule-anchor /health (witness)" \
  --resource-type=uptime-url \
  --resource-labels="host=witness.agentactioncapsule.org,project_id=PROJECT_ID" \
  --path=/health \
  --period=1 \
  --timeout=10 \
  --project=PROJECT_ID
```

Verify after DNS resolves:

```bash
curl -s https://witness.agentactioncapsule.org/health | python3 -m json.tool

# a checkpoint registers and gets a stamp:
curl -s -X POST https://witness.agentactioncapsule.org/checkpoints \
  -H 'content-type: application/json' -d '{ ...a real CLL checkpoint... }'

# a non-checkpoint is refused via the ONE named rejection path (never counter-signed):
curl -s -X POST https://witness.agentactioncapsule.org/checkpoints \
  -H 'content-type: application/json' -d '{"not":"a checkpoint"}'

# opt-in registration still works on the same host:
curl -s -X POST https://witness.agentactioncapsule.org/register \
  -H 'content-type: application/json' \
  -d '{"capsule_id":"0000000000000000000000000000000000000000000000000000000000000001"}'

# anchor.aac keeps answering its legacy route, unchanged:
curl -s -X POST https://anchor.agentactioncapsule.org/v1/digest \
  -H 'content-type: application/json' \
  -d '{"capsule_id":"0000000000000000000000000000000000000000000000000000000000000002"}'
```

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

## Second domain: witness.agentactioncapsule.org (checkpoint-witness role)

`capsule-anchor` is a conforming SCITT Transparency Service and already answers
`POST /v1/digest` + `GET /anchor/authority-pubkey` — the exact surface a
checkpoint witness needs (see `capsule-ledger/capsule_ledger/mmr/checkpoint.py`
and `capsule-emit/capsule_emit/checkpoint/emit.py`, both of which register
checkpoint digests through this same route). `witness.agentactioncapsule.org`
is a second custom domain mapped onto this **same** service — not a second
deployment, not a second signing key, not a second database. The
anchor-vs-witness distinction is purely which name a caller uses for which
purpose (per-capsule anchor vs. per-stream checkpoint witness); there is no
server-side role flag.

```bash
# One-time, if not already covered by an apex/wildcard verification for
# agentactioncapsule.org in Search Console:
#   gcloud domains verify witness.agentactioncapsule.org

gcloud run domain-mappings create \
  --service=capsule-anchor \
  --domain=witness.agentactioncapsule.org \
  --region=us-central1 \
  --project=PROJECT_ID
```

`gcloud` prints the DNS record(s) to add at the registrar — add exactly what
it prints (same procedure already used for `anchor.agentactioncapsule.org`).
No `--set-secrets`, no new Cloud SQL grants, no new signing key: this mapping
points at the identical running service, so it inherits
`CAPSULE_ANCHOR_SIGNING_KEY` / `CAPSULE_ANCHOR_DATABASE_URL` and answers with
the same `key_id`.

Add a second uptime check alongside the existing `anchor.aac` one (same
`/health` path, same alerting policy):

```bash
gcloud monitoring uptime create "capsule-anchor /health (witness)" \
  --resource-type=uptime-url \
  --resource-labels="host=witness.agentactioncapsule.org,project_id=PROJECT_ID" \
  --path=/health \
  --period=1 \
  --timeout=10 \
  --project=PROJECT_ID
```

Both hostnames stay live indefinitely — `anchor.aac` remains the legacy
per-capsule default and the CT-log browse/verify surface existing receipts
depend on; `witness.aac` is the per-stream checkpoint default since
capsule-emit 0.5.0. Neither redirects to the other; they are two names for
the same log. See `~/dev/asg/_work/witness-aac-deploy-spec.md` for the full
spec (checkpoint-witness API surface, trust-tier upgrade path, and the DNS
ruling) this section summarizes.

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

Create a Cloud Monitoring uptime check on `/health` so any future DB-connectivity
500 pages on-call immediately rather than going unnoticed:

```bash
# Create a public HTTPS uptime check on /health (pings every 1 min from global PoPs).
gcloud monitoring uptime create "capsule-anchor /health" \
  --resource-type=uptime-url \
  --resource-labels="host=anchor.agentactioncapsule.org,project_id=PROJECT_ID" \
  --path=/health \
  --period=1 \
  --timeout=10 \
  --project=PROJECT_ID
```

The check passes when the response is HTTP 200. A non-200 (including 500) triggers
a Cloud Monitoring alert if an alerting policy is attached. Set one up in the
Cloud Console: Monitoring → Alerting → Create policy → Uptime check policy →
notify via email or PagerDuty.

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
