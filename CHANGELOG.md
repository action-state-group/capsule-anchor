# Changelog

All notable changes to `capsule-anchor` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project uses
[Semantic Versioning](https://semver.org/) once it reaches 1.0.

## [Unreleased]

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
