# Operator Guide — Running a Witness

A witness is one node in a plurality. The trust story for a transparency log is not
"one trusted operator" — it is math plus independently operated witnesses. This guide
tells you how to stand up and run your own.

---

## 1. What a witness is

A witness is a SCITT Transparency Service (RFC 9943) that issues
[RFC 9162](https://www.rfc-editor.org/rfc/rfc9162) COSE Receipts over a
Certificate-Transparency Merkle tree. When a log submitter sends it a checkpoint or
a signed statement, the witness:

1. Verifies the submission's Ed25519 signature (it never signs something it
   could not verify).
2. Appends a content-addressed entry to its own append-only CT log.
3. Returns a COSE Receipt — a `COSE_Sign1` carrying an RFC 9162 inclusion proof,
   signed by the witness's stable Ed25519 authority key.

A receipt proves that a given entry was in the witness's log at a specific tree size.
The proof is mathematical: a verifier recomputes the Merkle root from the audit path
and checks the signature, without contacting the witness again. It does not establish
a witness-observed time: the receipt signs the log root, not a clock.

**Plurality is the trust story.** A single witness, however well-operated, is
self-attested to a relying party outside its operator's trust domain. Two or more
independently operated witnesses that have each issued a receipt for the same
checkpoint give a relying party cryptographic evidence from multiple parties who
could not have colluded undetected — that is the meaningful transparency guarantee.
A witness is one row in an alphabetical directory, not a moat.

---

## 2. Stand one up

### Service endpoints

The canonical witness surface exposes two routes at the top level (no prefix):

| Method | Path | What it does |
|--------|------|-------------|
| `POST` | `/checkpoints` | Register a CLL checkpoint (`draft-mih-scitt-checkpointed-local-log`). The default path for any `capsule-emit` client. Returns a `CheckpointStampResponse` with `receipt_b64`, `entry_hash`, and `continuity_grade` (`first-seen` / `registered` / `continuity-witnessed`). Verifies the submitter's Ed25519 signature before signing; refuses non-checkpoint bodies with a named 400, and refuses a `consistency_proof`-bearing checkpoint that fails either continuity check with a named 409. |
| `GET`  | `/checkpoints/{log_id}` | Read back the last checkpoint witnessed for `log_id`, including any equivocations detected. 200 if witnessed at least once, 404 if never. |
| `POST` | `/register` | Explicit opt-in, plain-SCITT-interop digest registration. Accepts `{"capsule_id": "<64-hex SHA-256>"}`. Returns a full COSE Receipt. A default `capsule-emit` client never calls this. |

Additional routes available for monitors and legacy callers:

| Method | Path | Description |
|--------|------|-------------|
| `GET`  | `/anchor/sth` | Current RFC 6962 Signed Tree Head |
| `GET`  | `/anchor/inclusion-proof-ct` | RFC 6962 inclusion proof for a log entry |
| `GET`  | `/anchor/consistency-proof` | RFC 6962 consistency proof between two tree sizes |
| `GET`  | `/anchor/authority-pubkey` | Authority Ed25519 public key (`pubkey_hex` + `key_id`) |
| `GET`  | `/.well-known/did.json` | Authority key as a DID document (JWK OKP, `did:web:<host>`) |
| `GET`  | `/health` (or `/healthz`, `/livez`) | Health check — `ok`, `tree_size`, `storage`, `signing_key_source`, `key_id`, `entry_retention` |
| `POST` | `/v1/digest` | Legacy alias of `/register`, kept for existing callers |
| `POST` | `/transparency/register-statement` | Register a COSE_Sign1 Signed Statement (base64 in JSON envelope) |

The service is a FastAPI application. Interactive API docs are available at `/docs`
on any running instance.

### Log store schema

The production backend is Postgres (`PostgresLogStore`). The schema is created
idempotently at startup — no migration tool is needed for a fresh deployment. The
tables are:

| Table | Purpose |
|-------|---------|
| `log_entries` | Append-only CT log. PK: `log_index BIGINT`. Hash-chained via `prev_log_hash`; per-entry Ed25519 `log_signature` over the tree head. Never pruned by any retention setting — its row count IS `tree_size`. |
| `submitted_statements` | Idempotent dedup + re-issue cache: `entry_hash TEXT PRIMARY KEY` → `receipt BYTEA`, `leaf_index`, `tree_size`. The ONLY table `CAPSULE_ANCHOR_ENTRY_RETENTION` prunes — see "Retention" below. |
| `checkpoint_records` | One row per `(log_id, mmr_size)` position ever witnessed. First-seen root wins; a conflicting later root triggers an equivocation record instead. Carries the `continuity_grade` this witness assigned when it was accepted. |
| `checkpoint_witnesses` | Chain-tip only: the last-ACCEPTED checkpoint per `log_id`. Backs both the legacy `mmr-checkpoint` monotonicity check and stage 2's continuity gate (`POST /checkpoints`, [capsule-anchor-checkpoint-aware-witness]) -- only advanced on `first-seen` or a verified `continuity-witnessed` acceptance, never on a bare `registered` one. |
| `checkpoint_equivocations` | Fork evidence: appended whenever a different root arrives for an already-witnessed `(log_id, mmr_size)`. Never deleted. |
| `countersigned_roots` | Legacy anchoring path. |
| `log_capsule_bindings` | Sidecar: `log_index → capsule_id` binding for the legacy `GET /v1/inclusion/{capsule_id}` resolve. |
| `subject_index` | Discovery: `(subject, entry_hash)` → `capsule_id_digest`, for `GET /transparency/statements`. |
| `signed_tree_heads` | Single-row singleton: the latest persisted Signed Tree Head (refreshed every 60 s by a background thread even when no new entries arrive). |
| `signed_tree_head_history` | One row per `tree_size` an STH was ever signed at. Indefinitely retained, independent of `CAPSULE_ANCHOR_ENTRY_RETENTION` — see "Retention" below. |

Schema version bumps add columns or tables with `ALTER TABLE … ADD COLUMN IF NOT
EXISTS`. The append-only invariant is that a row, once written, is never MUTATED —
`log_entries`, `signed_tree_head_history`, and `checkpoint_equivocations` are also
never deleted, full stop. `submitted_statements` is the one table this does NOT
apply to: rows there age out under `CAPSULE_ANCHOR_ENTRY_RETENTION` (still never
updated in place — a stale row is deleted outright, not mutated). Prior wording
here said "rows are never deleted or updated" without distinguishing which
invariant covered which table; that read as an unqualified forever-promise this
service was not actually keeping any code to back up. See "Retention" below.

Note: there is also a `SqliteLogStore` (single-file, for local durability testing)
and an `InMemoryLogStore` (volatile, for development only). Use Postgres in
production.

### Configuration

The service is fail-closed on startup. It refuses to start if any required variable
is missing — never silently degraded.

| Variable | Required | Purpose |
|----------|----------|---------|
| `CAPSULE_ANCHOR_SIGNING_KEY` | Yes (or `_FILE`) | Hex-encoded Ed25519 seed (32 bytes = 64 hex chars). Loaded by `load_signing_key()`; never baked into the image. |
| `CAPSULE_ANCHOR_SIGNING_KEY_FILE` | Alt | Path to PEM/PKCS#8 or raw seed file. Used instead of `_SIGNING_KEY` when the file is mounted (e.g. from a secrets manager via a volume). |
| `CAPSULE_ANCHOR_DATABASE_URL` | Yes | Postgres connection URL. Cloud SQL unix-socket form: `postgresql://USER:PASS@/DB?host=/cloudsql/PROJECT:REGION:INSTANCE`. Standard TCP: `postgresql://USER:PASS@HOST:5432/DB`. |
| `CAPSULE_ANCHOR_PUBLIC_HOST` | Yes | The hostname this instance is actually served from. Becomes `did:web:<host>` at `/.well-known/did.json`. No default — must be set, or startup fails. |
| `CAPSULE_ANCHOR_OPERATOR` | No | Optional self-declared operator string, published as the `operator` field in `did.json`. Absent unless you set it. |
| `CAPSULE_ANCHOR_HOST` | No | Bind address (default `0.0.0.0`). |
| `CAPSULE_ANCHOR_PORT` | No | Bind port (default `8000`). |
| `CAPSULE_ANCHOR_STH_REFRESH_INTERVAL` | No | Background STH refresh interval in seconds (default `60`). |
| `CAPSULE_ANCHOR_ENTRY_RETENTION` | No | Entry-retention window: `unlimited` (default) or a positive integer number of seconds. See "Retention" in §4 "Operate". Defaults to today's behavior — unset changes nothing on upgrade. |
| `CAPSULE_ANCHOR_ENTRY_RETENTION_SWEEP_INTERVAL` | No | Seconds between background retention sweeps (default `3600`). Only read — and only starts a thread — when `CAPSULE_ANCHOR_ENTRY_RETENTION` is set. |
| `CAPSULE_ANCHOR_CHECKPOINT_SUBMITTERS_FILE` | No | Path to a JSON array of enrolled submitter entries. If absent, the in-package default is used; if empty, all `log_id`s use the open self-asserted-key behavior. |
| `CAPSULE_ANCHOR_PUBLIC_LOG` | No | `rekor` or `none` (default `none`). Publishes this witness's own STHs to an external public log — see §6 "Plurality" and `docs/architecture/18-public-log-anchor.md`. Refuses to start with `rekor` if the signing key is ephemeral. |
| `CAPSULE_ANCHOR_REKOR_URL` | No | Rekor instance base URL (default `https://rekor.sigstore.dev`). Only read when `CAPSULE_ANCHOR_PUBLIC_LOG=rekor`. |
| `CAPSULE_ANCHOR_PUBLIC_LOG_INTERVAL` | No | Seconds between scheduled publish attempts (default `300`). |
| `CAPSULE_ANCHOR_PUBLIC_LOG_TIMEOUT` | No | HTTP timeout in seconds for the public-log backend (default `10`). |
| `CAPSULE_ANCHOR_INSECURE_EPHEMERAL_KEY` | Dev only | Set `1` to allow startup without a configured signing key. An ephemeral key changes on every restart and invalidates all prior receipts. Never set in production. |
| `CAPSULE_ANCHOR_INSECURE_IN_MEMORY` | Dev only | Set `1` to allow startup without `CAPSULE_ANCHOR_DATABASE_URL`. All log state is lost on restart. Never set in production. |

### Identity and key custody

The authority key is the existential asset of the log. Every COSE Receipt, STH, and
countersigned root is signed with it.

**Generate a key (one-time):**

```bash
python3 -c "import os; print(os.urandom(32).hex())"
```

Treat the 64-hex output as a secret — it fully reconstructs the authority identity.
Store it in a secrets manager, not in the image, not in a config file committed to a
repo, and not in a shell history file.

**Key identity.** `key_id` is the first 16 hex characters of `sha256(pubkey_bytes)`
— derived the same way wherever it appears (`/health`, `/anchor/authority-pubkey`,
`/.well-known/did.json`, and every JSON `Signature` object). Note where it does
*not* appear: a COSE Receipt carries no `kid`, so a verifier resolves the key from
one of those surfaces rather than from the receipt. See **Key rotation** below.

**`did:web` identity.** The DID document at `/.well-known/did.json` is derived from
`CAPSULE_ANCHOR_PUBLIC_HOST` at request time — never hard-coded. When you host an
instance under your own domain, the DID is `did:web:<your-domain>` and the
`verificationMethod` carries your authority public key. This is how a verifier
resolves your key out-of-band without depending on any other operator.

**Software key vs. KMS.** The current implementation (`StaticKeyProvider`) loads the
key from env or file into process memory for signing. A hardware-backed alternative
(`GcpKmsKeyProvider` or equivalent) where the private bytes never enter the process
is the higher-custody path — the `KeyProvider` interface in
`capsule_anchor.contracts.protocols` is the seam for that integration. The KMS path
is not yet implemented in this repo (planned).

---

## 3. Deploy

### Local development (volatile — not for production)

```bash
pip install 'capsule-anchor[postgres]'

# Generate a throwaway key for dev only
export CAPSULE_ANCHOR_SIGNING_KEY=$(python3 -c "import os; print(os.urandom(32).hex())")
export CAPSULE_ANCHOR_PUBLIC_HOST=localhost
export CAPSULE_ANCHOR_INSECURE_IN_MEMORY=1
capsule-anchor
# Listening on http://localhost:8000
```

Or with Docker:

```bash
docker build -t capsule-anchor .
docker run -p 8000:8000 \
  -e CAPSULE_ANCHOR_SIGNING_KEY=<your-hex-seed> \
  -e CAPSULE_ANCHOR_PUBLIC_HOST=your-domain.example.com \
  -e CAPSULE_ANCHOR_INSECURE_IN_MEMORY=1 \
  capsule-anchor
```

### Production (Postgres-backed, Cloud Run)

**Provision the database:**

```bash
# Cloud SQL instance (adjust tier and region for your setup)
gcloud sql instances create YOUR_INSTANCE_NAME \
  --database-version=POSTGRES_15 \
  --tier=db-f1-micro \
  --region=YOUR_REGION \
  --project=YOUR_PROJECT_ID

# Database and user
gcloud sql databases create YOUR_DB_NAME \
  --instance=YOUR_INSTANCE_NAME \
  --project=YOUR_PROJECT_ID

gcloud sql users create YOUR_DB_USER \
  --instance=YOUR_INSTANCE_NAME \
  --password=YOUR_STRONG_PASSWORD \
  --project=YOUR_PROJECT_ID

# Store the connection URL in your secrets manager
# Cloud Run unix-socket form (no TCP, no VPC connector):
echo -n "postgresql://YOUR_DB_USER:YOUR_STRONG_PASSWORD@/YOUR_DB_NAME?host=/cloudsql/YOUR_PROJECT_ID:YOUR_REGION:YOUR_INSTANCE_NAME" | \
  gcloud secrets create YOUR_DB_SECRET_NAME --data-file=- --project=YOUR_PROJECT_ID
```

**Provision the signing key:**

```bash
python3 -c "import os; print(os.urandom(32).hex())" | \
  gcloud secrets create YOUR_SIGNING_KEY_SECRET_NAME --data-file=- --project=YOUR_PROJECT_ID
```

**Deploy-currency rule (important):** before deploying with `--source .`, always
pull to the current remote tip first. A stale local checkout deploys old code —
`--source .` reads whatever is on disk, not what is on the remote. Deploy from a
worktree that is up to date:

```bash
git fetch origin
git pull --ff-only origin main     # or your base branch
```

**Deploy to Cloud Run:**

```bash
gcloud run deploy YOUR_SERVICE_NAME \
  --source . \
  --project=YOUR_PROJECT_ID \
  --region=YOUR_REGION \
  --port=8000 \
  --allow-unauthenticated \
  --add-cloudsql-instances=YOUR_PROJECT_ID:YOUR_REGION:YOUR_INSTANCE_NAME \
  --set-env-vars=CAPSULE_ANCHOR_PUBLIC_HOST=YOUR_DOMAIN \
  --set-secrets=\
CAPSULE_ANCHOR_SIGNING_KEY=YOUR_SIGNING_KEY_SECRET_NAME:latest,\
CAPSULE_ANCHOR_DATABASE_URL=YOUR_DB_SECRET_NAME:latest
```

**Preserving existing env on updates.** Use `--update-env-vars` and
`--update-secrets` when redeploying to change only the named variables.
`--set-env-vars` drops all previously set variables that are not in the new list,
which can silently unset required config and crash-loop the service. The safe
pattern for a source redeploy that should not touch existing config is:

```bash
gcloud run deploy YOUR_SERVICE_NAME \
  --source . \
  --project=YOUR_PROJECT_ID \
  --region=YOUR_REGION \
  --port=8000
# (no --set-env-vars; --source . picks up the code; existing env and secrets survive)
```

If you need to add or change a variable, name it explicitly with `--update-env-vars`
or `--update-secrets`.

**Map a custom domain:**

```bash
gcloud beta run domain-mappings create \
  --service=YOUR_SERVICE_NAME \
  --domain=YOUR_DOMAIN \
  --region=YOUR_REGION \
  --project=YOUR_PROJECT_ID
```

The command prints the DNS record to add (typically a single
`CNAME <name> ghs.googlehosted.com.`). TLS provisions automatically once DNS
resolves.

**Verify the deployment:**

```bash
curl -s https://YOUR_DOMAIN/health | python3 -m json.tool
# Expect: ok=true, storage=postgres, signing_key_ephemeral=false, tree_size>=0

curl -s https://YOUR_DOMAIN/.well-known/did.json | python3 -m json.tool
# Expect: id = "did:web:YOUR_DOMAIN"
```

---

## 4. Operate

### Health and monitoring

The `/health` endpoint (aliases: `/healthz`, `/livez`) returns a JSON object with:

- `ok` — `true` when the service is up and the store is reachable.
- `storage` — `"postgres"` in production; `"memory"` only for dev.
- `signing_key_ephemeral` — `false` in production. If `true`, the key is throwaway
  and will change on restart. This is a misconfiguration in production.
- `signing_key_source` — `"env"`, `"file:<path>"`, or `"generated"`.
- `key_id` — first 16 hex chars of `sha256(pubkey_bytes)`.
- `tree_size` — current number of entries in the CT log.
- `latest_sth_timestamp` and `latest_root_hash` — present when `tree_size > 0`.
- `entry_retention` — the declared retention posture: `"unlimited"` or `"<seconds>s"`.
  See "Retention" below. Always present — check it before depending on this witness
  for re-issuing a lost receipt.

A witness that stops advancing `latest_sth_timestamp` for longer than your Maximum
Merge Delay (MMD) threshold looks identical to a dead witness to any monitor that
relies on it. The background STH refresh thread (default interval: 60 seconds)
re-signs and persists the STH even when no new entries arrive, so a live-but-idle
witness keeps its timestamp current. Monitor `latest_sth_timestamp` in addition to
`ok`.

**Recommended checks:**

- Uptime check on `GET /health`, expect HTTP 200, interval 1 minute.
- Synthetic write check on `POST /checkpoints` with a garbage body, expect HTTP 400
  (named refusal — the service is up and processing). This does not write to the log
  and is safe to run continuously as a canary.
- Alert on elevated 5xx rate (e.g. Cloud Monitoring `run.googleapis.com/request_count`
  `response_code_class=5xx` > 5 over 5 minutes).
- Alert on elevated latency (e.g. p95 > 3000 ms over 5 minutes).

**Rate limits.** The service enforces a sliding-window rate limit of 300 POST
registrations per minute per process instance (global across `/checkpoints`,
`/register`, `/transparency/register-statement`). In a multi-instance deployment this
limit is per-instance; for a hard cluster-wide cap, add a reverse proxy or WAF in
front. Exceeding the limit returns HTTP 429. Read routes (`GET`) have no rate limit.

Enrolled submitters (see below) are additionally subject to their own per-identity
per-minute cap, configured in `packages/capsule_anchor/config/checkpoint_submitters.json`.

### Backup and restore

**The transparency log is the primary durable state.** If the log store is lost
and not recoverable, all previously issued receipts become unverifiable (the Merkle
tree they reference no longer exists). Backup is not optional.

**Back up the Postgres database.** Enable automated daily backups and
point-in-time recovery (PITR) on your database instance. With Cloud SQL:

```bash
# Confirm automated backups are enabled
gcloud sql instances describe YOUR_INSTANCE_NAME \
  --project=YOUR_PROJECT_ID \
  --format='get(settings.backupConfiguration)'

# List recent backups
gcloud sql backups list \
  --instance=YOUR_INSTANCE_NAME \
  --project=YOUR_PROJECT_ID
```

**Restore procedure (tested against the reference instance):**

Do not restore directly into a production database instance as the first step.
Restore into a fresh scratch instance, verify it, then cut over.

```bash
# Step 1: restore the backup into a new scratch instance
gcloud sql backups restore BACKUP_ID \
  --restore-instance=YOUR_SCRATCH_INSTANCE \
  --backup-instance=YOUR_INSTANCE_NAME \
  --project=YOUR_PROJECT_ID

# Step 2: for sub-daily precision, use PITR instead
gcloud sql instances clone YOUR_INSTANCE_NAME YOUR_SCRATCH_INSTANCE \
  --point-in-time RFC3339_TIMESTAMP \
  --project=YOUR_PROJECT_ID
```

**Cryptographic verification of a restore.** After restoring, verify the data
before cutting over:

1. Recompute the RFC 6962 Merkle root from the restored `log_entries` rows (indices
   `0..N-1`) and confirm it matches the `sth_json` stored in `signed_tree_heads`.
2. Verify the STH Ed25519 signature against your authority public key.
3. Fetch `GET /anchor/consistency-proof?old_size=N&new_size=M` from the production
   instance (where `N` is the restored size and `M` is production's current size) and
   verify the proof offline — this proves the restored snapshot is a valid prefix of
   the live log.

Once verification passes, cut over by updating `CAPSULE_ANCHOR_DATABASE_URL` in
your secrets manager to point at the new instance, then redeploy (source redeploy
picks up the new secret automatically if you use `--set-secrets … :latest`).

### Retention

**Three retentions, not one.** A receipt is self-contained bytes the HOLDER
keeps — verifying it needs the receipt, the entry hash, the audit path, and
this witness's public key, never this witness itself online or holding
anything (see §5 "Verify — offline"). What this witness's OWN retention
actually governs is narrower than "how long is my data safe":

1. **Re-issuing a receipt someone lost** — convenience only. Backed by the
   `submitted_statements` cache, keyed by `entry_hash`.
2. **Consistency from an old entry to the present** — the load-bearing
   property. Backed by `signed_tree_head_history`, retained indefinitely,
   independent of (1).
3. **Equivocation/fork detection over time** — backed by
   `checkpoint_equivocations`, retained indefinitely, independent of (1).

Only (2) and (3) are load-bearing. (1) is the only one `CAPSULE_ANCHOR_ENTRY_RETENTION`
touches.

**The asymmetric trade.** Roots are `O(checkpoints)` — small. Entries are
`O(entries)` — the thing that actually grows without bound, and specifically
`submitted_statements`, which stores every issued receipt as `BYTEA` keyed
by `entry_hash`. Historically this witness kept every entry forever and
persisted only a SINGLE latest Signed Tree Head — the expensive thing was
kept forever and the cheap thing was not retained at all. This inverts that:
`signed_tree_head_history` retains every signed root indefinitely (small); entry
retention — meaning the `submitted_statements` re-issue cache — is now
configurable via `CAPSULE_ANCHOR_ENTRY_RETENTION`. Indefinite root retention
means a receipt can always be checked against the root it was issued under —
it does not mean the receipt verifies forever: that also depends on the
signing key staying published (see **Key rotation** below).

**What pruning does and does not touch.** Setting `CAPSULE_ANCHOR_ENTRY_RETENTION`
to a number of seconds deletes `submitted_statements` rows older than that
window (a background thread sweeps every `CAPSULE_ANCHOR_ENTRY_RETENTION_SWEEP_INTERVAL`
seconds, default 3600). It NEVER touches `log_entries` (the append-only log
whose row count IS `tree_size` — partial deletion there would corrupt the CT
tree for every future proof, not just old ones), `signed_tree_head_history`,
or `checkpoint_equivocations`. **What you give up:** `GET /v1/inclusion/{capsule_id}`
and any other re-issue lookup for a pruned entry returns 404 instead of the
cached receipt — the ORIGINAL receipt, already handed to the holder at
registration time, is completely unaffected by pruning. It remains
independently verifiable exactly as described under **Key rotation** below:
against the retained root, for as long as the signing key that issued it
remains published — pruning the re-issue cache changes none of that. A
resubmission of the exact same statement after
its cache row was pruned is treated as new (a fresh log entry, a fresh
receipt) rather than an idempotent cache hit — a policy tradeoff, not
corruption; both entries verify.

**Default is unlimited.** Unset — or explicitly `CAPSULE_ANCHOR_ENTRY_RETENTION=unlimited`
— means nothing is ever pruned, byte-identical to every prior release.
Upgrading to this code changes nothing until you opt in.

**Do not copy CCF's retention-relaxation conclusion.** Microsoft's CCF-based
transparency services can relax retention because hardware attestation plus
reproducible, auditable code measurements give a verifier a substitute for
re-deriving the log's own history — the hardware vouches for what the code
did even after the data is gone. This witness has no confidential-computing
attestation. Taking CCF's retention-relaxation conclusion without that
substitute would leave a relying party with NEITHER property: no attestation
AND no re-derivable history. That is why (2) and (3) above are retained
indefinitely and only (1), the convenience cache, is ever configurable.

### Key rotation

Rotation does not invalidate historical receipts — but **a COSE Receipt does not
identify the key that signed it**, so publishing retired keys is not optional.

A COSE Receipt's protected header carries `alg` (1) and `vds` (395), plus, when
present, the CWT claims map (15, holding `iat`), the witness grade (-65537) and the
continuity assertion (-65538). It carries **no COSE `kid` (4)**. A verifier
therefore resolves the witness key out of band — `GET /.well-known/did.json` or
`GET /anchor/authority-pubkey`.

**Both of those endpoints return only the current signing key — the service serves
no key history.** Across a rotation boundary, a verifier that resolves the key live
gets *only the new key*: a receipt signed by a retired key will **not** verify
against it, and there is no endpoint from which to fetch the old one. Historical-receipt
verifiability across a rotation is therefore **not automatic** — it depends on the
operator having published the retired key out of band (procedure step 3 below) and
the verifier knowing to consult that record. Do not rely on the live endpoints to
verify a pre-rotation receipt.

The JSON `Signature` object is a different surface and does the opposite: STHs,
`/anchor/anchor` receipts and transparency-log entries each carry `key_id` (the
first 16 hex chars of `sha256(pubkey)`), naming their key directly. Do not
generalise from those to COSE Receipts.

**Rotation procedure:**

1. Generate a new seed and store it as a new secret version:
   ```bash
   python3 -c "import os; print(os.urandom(32).hex())" | \
     gcloud secrets versions add YOUR_SIGNING_KEY_SECRET_NAME \
     --data-file=- --project=YOUR_PROJECT_ID
   ```

2. Redeploy pointing at the new version:
   ```bash
   gcloud run services update YOUR_SERVICE_NAME \
     --region=YOUR_REGION \
     --update-secrets=CAPSULE_ANCHOR_SIGNING_KEY=YOUR_SIGNING_KEY_SECRET_NAME:latest \
     --project=YOUR_PROJECT_ID
   ```
   STHs and `Signature` objects produced after this redeploy carry the new
   `key_id`. COSE Receipts carry no key identifier either side of the rotation —
   which key signed one is determined only by which published key verifies it.

3. Publish the old public key alongside the new one. After rotation,
   `GET /.well-known/did.json` and `GET /anchor/authority-pubkey` return **only the
   new key** — neither serves prior keys. Verifiers that resolve the key at
   verify-time pick up the new key automatically; verifiers that pinned the old key
   out-of-band must update their pin. **Because the endpoints serve no key history,
   the operator must publish retired keys out of band — this is the only path that
   works today:**

   - **Out-of-band publication (the actionable path today):** publish retired public
     keys (with `key_id`, raw hex, and rotation date) in your `CHANGELOG.md` or a
     `keys/` directory in this repo, and point verifiers at it. A verifier holding a
     pre-rotation COSE Receipt must fetch the retired key from this record — it
     cannot obtain it from the live endpoints.
   - **DID document history (recommended target — NOT yet built):** the intended
     future design is to include each retired key as an additional
     `verificationMethod` entry in `/.well-known/did.json`, so a verifier could fetch
     the full key set from the endpoint and try each. **The service does not do this
     yet** — `did.json` emits only the current key. Until it is built, do not rely on
     the endpoint for historical keys; use out-of-band publication above.

### Recovery after a failed checkpoint

If a checkpoint submission is interrupted mid-flight and you are unsure whether it
was recorded, resubmit. The service is idempotent: resubmitting the same checkpoint
(same `log_id`, `mmr_size`, and root) returns the original stamp without creating a
new log entry. A `GET /checkpoints/{log_id}` tells you the last checkpoint the
witness recorded for that `log_id` and its `mmr_size`.

If a checkpoint was accepted but the network dropped the response before the client
received it, the same resubmit behavior applies — the response on resubmit is the
original stamp.

**A witness upgrade does not re-stamp already-witnessed checkpoints.** Idempotency is
keyed on the content-addressed `entry_hash` of the checkpoint itself (`v`, `kind`,
`log_id`, `mmr_size`, `root`, `prev_size`, `prev_root`, `key_id`, `timestamp`), never
on when it was submitted or what code was deployed at the time. If the witness is
redeployed with new receipt fields, a new grade, or any other change to what the
protected header carries, **re-submitting a checkpoint you already submitted before
the redeploy still returns the original stamp — including its original protected
header** — because the bytes are identical and the dedup fires before any new
receipt is built. This has already surprised two of us and an external integrator
who each expected a resubmission to pick up the new format. To see a receipt in the
new format, submit a checkpoint this witness has genuinely never seen before (a new
`mmr_size`/root for that `log_id`) — there is no way to force a re-stamp of an
already-witnessed position short of that.

---

## 5. Verify — offline, without the witness

A receipt is self-contained. Verification does not contact the issuing witness again.

**What the receipt proves:** the entry was in the CT log at the tree size recorded in
the receipt. The inclusion proof is an RFC 9162 Merkle audit path. The receipt is
signed by the witness's authority key.

**Steps:**

1. Obtain the witness's authority public key out-of-band. Resolve
   `GET /.well-known/did.json` at setup time and extract the `x` field from the
   `verificationMethod` (base64url-encoded raw Ed25519 public key), OR fetch
   `GET /anchor/authority-pubkey` for the raw hex and `key_id`. Pin this key
   — the point is to verify without trusting the same party again.

2. Recompute the entry hash from the submission you made:
   - For `POST /register` (capsule_id submit): `entry_hash = sha256(bytes.fromhex(capsule_id))`.
   - For `POST /checkpoints` (CLL checkpoint): the `entry_hash` in the response is
     `sha256` of the checkpoint's own canonical signing body. The service's response
     field states this; an independent verifier holding the checkpoint record can
     recompute it without trusting the response.
   - For `POST /transparency/register-statement` (COSE_Sign1 Signed Statement):
     `entry_hash` is `sha256` of the RFC 9052 `Sig_structure` when the statement is a
     parseable `COSE_Sign1` with an embedded payload (`entry_hash_scheme: "sig_structure"`),
     or `sha256` of the raw bytes otherwise (`entry_hash_scheme: "legacy"`).

3. Compute the CT leaf hash: `sha256(b"\x00" + bytes.fromhex(entry_hash))`.
   This is the RFC 9162 leaf preimage — the `0x00` byte is the leaf-node prefix.

4. Fold the Merkle audit path: starting from the leaf hash, for each element in the
   audit path, combine with `sha256(b"\x01" + left + right)` (RFC 9162 internal
   node hashing), taking the left/right order from the audit path.

5. Verify the COSE Receipt: parse the `receipt_b64` as a `COSE_Sign1` (CBOR tag 18),
   check that the `root_hash` from step 4 matches the root in the receipt's protected
   header, and verify the Ed25519 signature using the pinned public key from step 1.

The [`agent-action-capsule`](https://github.com/action-state-group/agent-action-capsule)
library and [`scitt-cose`](https://github.com/action-state-group/scitt-cose) verifier
implement this full offline verification path. Any SCITT-compatible verifier that
understands RFC 9162 COSE Receipts can also verify — the format is standard, not
specific to this implementation.

---

## 6. Plurality — registering with more than one witness

Plurality is not a feature of a single witness. It is a property of the system you
build with multiple witnesses.

**Why it matters.** A receipt from one witness proves inclusion in that witness's log
— it does not prove anything about what other witnesses saw or did not see. A relying
party that holds receipts from two or more independently operated witnesses that
each recorded the same checkpoint at consistent positions has cryptographic evidence
from multiple independent parties. That is the trust story — the math across
independently operated parties, not any single operator's assurance.

**How to register with multiple witnesses.** Point your log client at each witness
URL in turn (or in parallel) after emitting a checkpoint. For `POST /checkpoints`,
each witness issues its own independent receipt signed by its own authority key.
Collect all receipts and store them alongside the checkpoint record.

```bash
# Example: register the same checkpoint with two witnesses
CHECKPOINT_BODY=<your-COSE-checkpoint-bytes>

curl -s -X POST https://WITNESS_A_DOMAIN/checkpoints \
  -H 'Content-Type: application/cll-checkpoint+cbor' \
  --data-binary "$CHECKPOINT_BODY" | python3 -m json.tool

curl -s -X POST https://WITNESS_B_DOMAIN/checkpoints \
  -H 'Content-Type: application/cll-checkpoint+cbor' \
  --data-binary "$CHECKPOINT_BODY" | python3 -m json.tool
```

Each response carries its own `receipt_b64` and `entry_hash`. A relying party can
verify each receipt independently against each witness's own public key (resolved from
each witness's `/.well-known/did.json`).

**What witnesses check.** Each witness independently verifies the checkpoint's
Ed25519 signature before signing, records the entry in its own CT log, and
issues a COSE Receipt. It also remembers, per `log_id`, the last checkpoint it
accepted: a checkpoint that omits the optional `consistency_proof` claim is
registered only (graded `registered`, exactly the original inclusion-only behavior —
never refused for the proof's absence), while one that carries a `consistency_proof`
is checked on two axes — the claimed `prev_size`/`prev_root` must equal what this
witness itself last accepted, AND the proof must independently verify (via the
neutral CLL core's `verify_consistency`) as extending that same state — refused with
409 on either failing, graded `continuity-witnessed` on both passing. A `log_id` this
witness has never seen is graded `first-seen`. See the main README's
[`/checkpoints`](README.md#checkpoints--checkpoint-witnessing-default-witness-host)
section for the full three-grade table. **Honesty:** a `continuity-witnessed` grade
describes only what THIS witness independently checked against its own recorded
view — it is operated by the party that publishes the specification, and
independence of that operator is yours to assess. Running more than one witness (see
above) remains the anti-equivocation lever a single witness's own claim cannot
provide.

**Equivocation detection.** If the same `(log_id, mmr_size)` position is submitted
twice with different roots, the witness records both as an equivocation event (in the
`checkpoint_equivocations` table) and surfaces them on
`GET /checkpoints/{log_id}` under the `equivocations` field. This is the
detect-and-surface mechanism; refusing the write on equivocation is planned for a
later stage.

**Operating your own witness.** Any party can run this software under their own
domain, sign with their own key, and contribute an independent receipt. Nothing in
the protocol requires a specific operator. `CAPSULE_ANCHOR_PUBLIC_HOST` derives the
DID from whatever hostname you actually serve from, so the witness's identity is
yours, not ours.

**Rekor as the first external log.** Running more than one *witness* (above) is one
axis of plurality; a witness can also publish its OWN Signed Tree Heads into a
third-party-operated transparency log it does not control — set
`CAPSULE_ANCHOR_PUBLIC_LOG=rekor` (off by default) to publish to Sigstore's public
Rekor instance on a schedule. This is orthogonal to multi-witness plurality: it does
not replace running a second witness, it gives ANY single witness (including one you
run yourself) an externally-checkable claim that its own tree head history has never
been rewritten. See `docs/architecture/18-public-log-anchor.md` for the full design
and `GET /anchor/public-log/latest` for the current publication state.

**Adding a second external log.** The `PublicLog` protocol
(`capsule_anchor.contracts.protocols`) is the seam: a peer witness reachable via
`POST /checkpoints` (the code already supports this — see "How to register with
multiple witnesses" above) or a second transparency-log backend both satisfy it.
Rekor plus one independently-operated peer witness is a strong plural story without
requiring a second Rekor-shaped log to exist.

---

## Appendix: enrolled submitters

`POST /checkpoints` is open by default — any COSE_Sign1 checkpoint verifying under
its own self-asserted `kid` is accepted for any `log_id`. A named external log can
additionally be *enrolled*: a config-driven allowlist
(`packages/capsule_anchor/config/checkpoint_submitters.json`) pins a specific
`log_id` (the CWT `iss`) to a specific Ed25519 public key. For an enrolled `log_id`,
the witness uses only the pinned key — the envelope's own `kid` is ignored — so a
stranger cannot mint a stamp for an enrolled identity by self-signing with an
arbitrary key.

An enrolled entry's stamp additionally carries a `grade`:

| `grade` | Meaning |
|---------|---------|
| `mmr-verified` | The submitter's commitment is the CLL MMR peaks-and-root scheme, which this witness fully understands. |
| `countersigned-observed` | A foreign accumulator this witness does not independently verify — it observes, timestamps, and countersigns the submitted commitment bytes. Never equivalent to `mmr-verified`. |

Enrollment is a committed config change and redeploy, not an open signup mechanism.
Every `log_id` that is not enrolled keeps the default open self-asserted-key behavior
and receives no grade.

**One entry in the shipped config, `asg-selftest/v1`, is self-operated — read it as
zero evidence, not a second witness.** It exists solely so the `grade: mmr-verified`
code path can be exercised end to end at all (there is otherwise no live way to
observe it: the one native-MMR checkpoint this witness has ever seen was witnessed
before that grade existed, and re-submitting it returns the original pre-upgrade
stamp — see "A witness upgrade does not re-stamp already-witnessed checkpoints"
above). A grade this witness assigns to a log it also operates corroborates nothing
about independence — the same "producer-operated witness is not independent" limit
that applies to every self-hosted witness applies here with no exception. If you see
a receipt for `asg-selftest/v1`, it proves the code emits a signed grade; it is never
citable as a second party's attestation.

---

## References

- [RFC 9943](https://www.rfc-editor.org/rfc/rfc9943) — SCITT Architecture (Transparency Service)
- [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162) — Certificate Transparency v2
- [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962) — Certificate Transparency v1
- [draft-ietf-cose-merkle-tree-proofs](https://datatracker.ietf.org/doc/draft-ietf-cose-merkle-tree-proofs/) — COSE Receipt format
- [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) — Ed25519
- [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052) — COSE_Sign1
- [draft-mih-scitt-checkpointed-local-log](https://datatracker.ietf.org/doc/draft-mih-scitt-checkpointed-local-log/) — CLL checkpoint wire format
- [`agent-action-capsule`](https://github.com/action-state-group/agent-action-capsule) — reference library and offline verifier
- [`scitt-cose`](https://github.com/action-state-group/scitt-cose) — vendor-neutral RFC 9162 receipt verifier
- [`deploy/DEPLOY.md`](deploy/DEPLOY.md) — Cloud Run deployment walkthrough
- [`deploy/KEY-MANAGEMENT.md`](deploy/KEY-MANAGEMENT.md) — full key rotation and custody story
