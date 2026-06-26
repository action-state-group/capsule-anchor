# Deploying capsule-anchor (Cloud Run)

## Runtime configuration

| Variable | Source in prod | Purpose |
|---|---|---|
| `CAPSULE_ANCHOR_SIGNING_KEY` | Secret Manager | Hex-encoded Ed25519 seed. Absent → ephemeral key generated (loud warning). |
| `CAPSULE_ANCHOR_SIGNING_KEY_FILE` | Mounted secret file | Alt: path to PEM/seed file. |
| `CAPSULE_ANCHOR_HOST` / `CAPSULE_ANCHOR_PORT` | env | Bind address (default `0.0.0.0:8000`). |
| `CAPSULE_ANCHOR_TSA_ENABLED` | env | Set to `1` to enable RFC3161 TSA timestamps (opt-in). |
| `CAPSULE_ANCHOR_TSA_URL` | env | Override TSA endpoint (default: FreeTSA). |

Storage: without a Postgres URL the service uses in-memory storage (state
resets on restart). Install the `[postgres]` extra and set a
`CAPSULE_ANCHOR_DB_URL` for durable persistence.

## Quick deploy (source-based, no Artifact Registry needed)

```bash
# 1. Generate and store a signing key
python3 -c "import os; print(os.urandom(32).hex())" | \
  gcloud secrets create capsule-anchor-signing-key --data-file=- --project=PROJECT_ID

# 2. Deploy
gcloud run deploy capsule-anchor \
  --source . \
  --project=PROJECT_ID \
  --region=us-central1 \
  --port=8000 \
  --max-instances=1 \
  --allow-unauthenticated \
  --set-secrets=CAPSULE_ANCHOR_SIGNING_KEY=capsule-anchor-signing-key:latest
```

## cloudbuild.yaml deploy

```bash
gcloud builds submit --config deploy/cloudbuild.yaml \
  --substitutions \
    _REGION=us-central1,\
    _REGISTRY=us-central1-docker.pkg.dev/PROJECT_ID/anchor,\
    _SIGNING_KEY_SECRET=capsule-anchor-signing-key \
  --project=PROJECT_ID
```
