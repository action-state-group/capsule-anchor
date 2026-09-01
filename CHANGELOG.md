# Changelog

All notable changes to `capsule-anchor` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project uses
[Semantic Versioning](https://semver.org/) once it reaches 1.0.

## [Unreleased]

### Added

- **Ops readiness tooling for the witness deployment** (`deploy/monitoring.sh`,
  `deploy/burst_test.py`, `deploy/verify_restore.py`, `deploy/check_revision.sh`,
  `deploy/BACKUP-RESTORE.md`): uptime monitoring + alerting as code for both the
  read path (`GET /health`) and the checkpoint-submit path (`POST /checkpoints`,
  a named-refusal canary that doesn't require a real allowlisted submitter
  identity); a load-sanity tool for burst-testing `/checkpoints` and read routes
  with a distinguished "demo identity"; an append-only hash-chain integrity
  checker for restore drills; and a mechanical deployed-revision-vs-origin/main
  check. `cloudbuild.yaml` now tags images by commit SHA instead of `latest` and
  includes `--add-cloudsql-instances`, and its `_SERVICE` default was corrected
  to `capsule-witness` (the actual deployed service name, finalized 2026-08-28).

- **Witness-host canonical routes, `POST /checkpoints` (default) + `POST /register`
  (opt-in)**: single-host reconciliation (2026-08-27) of the checkpoint-only witness
  surface added in `witness-checkpoint-only-stage1`. `/checkpoints` is a rename of that
  PR's `POST /v1/checkpoint` (never documented, never called by any client — renamed
  outright, no dual-mount) to its canonical witness-host name: accepts a CLL
  `CheckpointRecord` verbatim, refuses anything else with a named `400`, verifies the
  checkpoint's own Ed25519 signature before ever counter-signing (`401` on failure), and
  is stage-1 stateless. `POST /register` is the new canonical name for the existing
  `POST /v1/digest` digest-registration surface (same handler, kept as a legacy alias) —
  the explicit opt-in, plain-SCITT-interop per-record registration path. Privacy is now
  enforced at the ROUTE level, not a host-level gate: both routes are always reachable on
  one deployment.
- **Checkpoint witness surface**: `POST /transparency/register-statement` now
  auto-recognizes a self-declared `artifact_type: mmr-checkpoint` payload (no new route)
  and checks it against the log's last-witnessed checkpoint for its `log_id` before
  co-signing — monotonic size + chain-linkage, honest `"first-seen"` grading for an
  unknown `log_id`, and a `409` (never co-signed) on rollback/fork. Response gains a
  `checkpoint_witness` field (`null` for non-checkpoint statements).

### Removed

- **`WITNESS_ONLY` deployment mode**, added in `witness-checkpoint-only-stage1` for a
  separate checkpoint-only `capsule-witness` Cloud Run deployment — that plan is
  superseded by the single-host, two-route model above (one deployment answers both
  `/checkpoints` and `/register`, differentiated by route rather than a host-level env
  gate). The env var is now a no-op; no separate deployment is planned.

### Changed

- **`entry_hash` derivation (entry-identity-second-rule-sweep, Option 1)**: now
  `SHA256(Sig_structure)` — malleability-immune — for any submitted statement that decodes
  as a COSE_Sign1 with an embedded payload; unchanged (`SHA256` of the raw bytes) for
  everything else, including `/v1/digest`. A signature-malleated resubmission of the same
  signing act now returns the ORIGINAL receipt instead of minting a second CT leaf. A
  dual-lookup window keeps statements registered before this change resolving as the same
  entry. `RegisterStatementResponse` gains an `entry_hash_scheme` field
  (`"sig_structure"` | `"legacy"`) signaling which derivation produced `entry_hash`.

## [0.1.1] — production hardening

### Changed

- **Fail-closed startup**: the service now refuses to start unless both a signing key
  (`CAPSULE_ANCHOR_SIGNING_KEY` / `CAPSULE_ANCHOR_SIGNING_KEY_FILE`) and a durable store
  (`CAPSULE_ANCHOR_DATABASE_URL`) are configured. Silent in-memory storage and ephemeral
  key generation are blocked by default; each requires an explicit dev-only opt-in env var.
- `CAPSULE_ANCHOR_INSECURE_EPHEMERAL_KEY=1` — dev escape hatch that allows an ephemeral
  signing key (set automatically in the test suite via `conftest.py`).
- `CAPSULE_ANCHOR_INSECURE_IN_MEMORY=1` — dev escape hatch that allows volatile in-memory
  storage (set automatically in the test suite via `conftest.py`).
- `deploy/DEPLOY.md` updated: Postgres Cloud SQL setup, HA configuration
  (`--min-instances=1 --max-instances=10`, `--max-instances=1` removed), fail-closed env
  var table, link to key management doc.
- Root page live-log strip now includes an "Early access" label noting initial test
  submissions.

### Added

- `deploy/KEY-MANAGEMENT.md`: key rotation story (old key verifies historical receipts,
  new key signs forward), GCP KMS path sketch, `did:web` history approach for post-rotation
  verification.
- `TestFailClosed` test class: 4 tests verifying fail-closed behaviour and opt-in paths.
- `packages/tests/conftest.py`: session-level dev escape hatches so the test suite runs
  without a real Postgres URL or signing key.

### Security

- `POST /attest/sign` sign-oracle removed (was in v0.1.0 — unauthenticated endpoint
  signing arbitrary bytes with the authority key, enabling receipt/STH forgery).
- `GET /attest/pubkey` and `POST /attest/verify` removed along with the entire
  `/attest/*` HTTP surface. Authority public key remains at `GET /.well-known/did.json`.

### Fixed

- `CAPSULE_ANCHOR_DATABASE_URL` env var name corrected in docs (was incorrectly shown
  as `CAPSULE_ANCHOR_DB_URL` in `DEPLOY.md` and `README.md`).
- README `key_id` was hardcoded to a stale ephemeral value; now points to
  `/.well-known/did.json` for the live value.

[0.1.1]: https://github.com/action-state-group/capsule-anchor/compare/v0.1.0...v0.1.1

## [0.1.0] — alpha

Initial public release: the neutral SCITT Transparency Service layer for the
Agent Action Capsule ecosystem.

### Added

- `POST /v1/digest` — simple digest registration endpoint; accepts
  `{"capsule_id": "<64-hex>"}`, registers through the SCITT CT-log path,
  returns a COSE Receipt. Default endpoint for
  [`capsule-emit`](https://github.com/action-state-group/capsule-emit) via
  `AAC_ANCHOR_URL`.
- `POST /transparency/register-statement` — SCITT Transparency Service
  registration; accepts a COSE_Sign1 Signed Statement (base64), issues a COSE
  Receipt (CBOR tag 18) with RFC 9162 inclusion proof.
- `GET /anchor/sth` — current RFC 6962 Signed Tree Head.
- `GET /anchor/transparency-log` — append-only CT log feed for monitors.
- `GET /anchor/inclusion-proof-ct` — RFC 6962 CT inclusion proof for any leaf.
- `GET /anchor/consistency-proof` — RFC 6962 consistency proof between two sizes.
- `GET /anchor/authority-pubkey` — authority Ed25519 public key for out-of-band
  monitor pinning.
- `POST /anchor/anchor` — countersign a tenant Merkle root and anchor to the CT
  log (agent-action-capsule operator surface).
- `GET /health` / `/healthz` / `/livez` — health check with signing key source.
- Ed25519 authority key loaded from `CAPSULE_ANCHOR_SIGNING_KEY` (Secret
  Manager, env var, or file); falls back to ephemeral key with loud warning.
- In-memory CT log by default; durable SQLite (`db_path=`) and Postgres
  (`[postgres]` extra + `CAPSULE_ANCHOR_DB_URL`) options.
- Optional RFC 3161 TSA timestamps (`CAPSULE_ANCHOR_TSA_ENABLED=1`).
- Apache-2.0 license; neutrality CI gate; product-free substrate.

[Unreleased]: https://github.com/action-state-group/capsule-anchor/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/action-state-group/capsule-anchor/releases/tag/v0.1.0
