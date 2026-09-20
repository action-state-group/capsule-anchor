# 18 — Public-log anchor: publishing this witness's own STHs to Rekor

This document describes `packages/capsule_anchor/public_log/` and its wiring into
`app.py`: an additive, off-by-default rail that publishes this witness's own Signed
Tree Heads (STHs) to an external, third-party-operated transparency log (Sigstore
Rekor by default). It is the "we are witnessed too" story — proof that this witness's
own claim to append-only history is checkable somewhere it doesn't control, not only
by asking it.

---

## 1. Why Rekor, why `hashedrekord`

A witness that only ever asserts its own consistency is asking to be trusted on its
own say-so. Publishing each STH into a log this service does not operate gives any
stranger an independent point to check: "did this witness's history ever rewrite
itself?" is answerable by watching Rekor, not by trusting this service's own API.

Rekor's `hashedrekord` entry type is the right shape for that: "some bytes, signed
under some key." An STH is exactly that — a tree size, a Merkle root, and a
timestamp, Ed25519-signed by the authority key — never an in-toto claim *about* an
artifact. `public_log/rekor.py`'s `RekorBundle.build()` assembles that entry by hand
with `cbor2`/manual DER (no `cryptography`-only path needed for the SPKI wrapping),
so the module has no dependency beyond `httpx` for the actual submission.

## 2. The no-plaintext invariant

**Only STHs — tree_size, root_hash, timestamp — ever leave this service via the
public-log rail.** No tenant content, no capsule payloads, no submitter identity.
This is enforced structurally in two places:

- `public_log/wrapper.py`'s `attach_public_log` (the documented seam, used directly
  by tests) submits exactly `sth_payload(tree_size, root_hash, timestamp)` bytes —
  it never sees, and cannot forward, anything else.
- `public_log/scheduler.py`'s `PublicLogPublisher` (the production path — see §3)
  reads the same `sth_payload(...)` bytes from `AnchorerService.get_sth()` and passes
  them straight to `PublicLog.submit()`. Neither ever also carry the individual entry
  digests that make up the tree.

## 3. Cadence: a scheduled publisher, never inline

The wrapper (`attach_public_log`) monkey-patches `anchor()` so every anchoring call
also publishes — useful for tests and as a documented integration point, but wrong
for production: Rekor is rate-limited, and per-receipt latency to an external log
would make every witness response depend on a third party's availability.

The production path is `public_log/scheduler.py`'s `PublicLogPublisher`, wired by
`app.py` on a background daemon thread (the same shape as the existing STH-refresh
thread):

- Every `CAPSULE_ANCHOR_PUBLIC_LOG_INTERVAL` seconds (default 300), check the
  current STH; if its `tree_size` has not already been published for this backend,
  submit it and persist the result.
- **Never** called inline from `/checkpoints`, `/register`, or `/anchor/anchor`. A
  Rekor outage never fails a receipt to a caller.
- At most once per `tree_size` per backend — enforced by a persisted idempotent key
  `(backend, sth_tree_size, sth_root_hash)`, not by in-process state, so it is safe
  with N concurrently running instances.
- "Publish after key rotation": no `KeyProvider` this service actually wires
  supports in-process rotation today (`StaticKeyProvider.rotate()` is unimplemented)
  — a key change only happens via a redeploy/restart, and the first interval tick
  after that restart is this rail's "after rotation" publish. A future in-process
  `KeyProvider.rotate()` should call `publisher.publish_if_new()` directly for a
  true immediate publish.
- At graceful shutdown, `app.py`'s shutdown hook makes one best-effort final
  `publish_if_new()` call so the last STH before shutdown is externally visible.

## 4. Failure model

`PublicLogPublisher.publish_if_new()` **never raises**. On any failure (timeout,
non-2xx, malformed response):

- Logged at `WARNING`, with a running `consecutive_failures` count.
- Persisted to the `public_log_failures` table (backend, timestamp, error) — so a
  later auditor sees the gap honestly instead of inferring it from silence.
- After `degraded_after` consecutive failures (default 12 — one hour at the 5-minute
  default interval), `/health` reports `"public_log": "degraded"`. The top-level
  `"ok"` flag is **never** affected — the witness's core function (signing receipts,
  the CT log) does not depend on an external log being reachable.
- A success resets the counter to zero.

## 5. Persistence

`anchoring/store.py`'s three backends (`InMemoryLogStore`, `SqliteLogStore`,
`PostgresLogStore`) each gain a `public_log_receipts` table:

| Column | Meaning |
|---|---|
| `backend` | e.g. `rekor-public` |
| `sth_tree_size`, `sth_root_hash`, `sth_timestamp` | the published STH |
| `uuid`, `log_index`, `integrated_time`, `signed_entry_timestamp` | the backend's own receipt fields |
| `raw_response` | the backend's full response, JSON-encoded, for audit |
| `submitted_at` | when this service made the submission |

Primary key `(backend, sth_tree_size, sth_root_hash)` — the idempotency key the
scheduler checks before submitting.

## 6. Surfacing

- `GET /anchor/public-log/latest` — the most recently published receipt plus the STH
  it covers. 404 when the rail is disabled or nothing has published yet.
- `GET /anchor/public-log/entries?since=<tree_size>` — every receipt with
  `sth_tree_size > since`, oldest first. Empty list (never 404) when disabled or
  simply nothing newer.
- `POST /checkpoints`'s `CheckpointStampResponse` gains a `public_log` field:
  `{backend, uuid, log_index, sth_tree_size}` when an ALREADY-published entry covers
  this checkpoint's `tree_size` (append-only Merkle inclusion holds forward: a
  publication at a later, larger tree size still covers an earlier leaf) — `null` on
  every fresh registration, since the scheduler runs on its own interval and could
  not have published anything covering a checkpoint the same request just created.
- The COSE Receipt itself carries the same evidence in its **UNPROTECTED** header
  (private-use label `397`, `public_log/receipt_augment.py`) when present. This is
  attached at SERVE time, not at signing time — the receipt is signed once, at
  registration, and its bytes are cached verbatim for idempotent resubmission; a
  covering Rekor publication can only exist some time later. Because RFC 9052's
  Sig_structure covers only the protected header and payload, augmenting the
  unprotected header never invalidates the signature and never changes the
  PROTECTED bytes — every receipt's protected content and signature are
  byte-for-byte identical whether or not the rail is enabled, or whether or not a
  covering publication exists yet. See `receipt_augment.py`'s module docstring and
  `packages/tests/test_public_log_rail.py::TestByteStability`.

## 7. Grade discipline

A Rekor entry proves *existence and time* — a third party attests it was submitted
before some moment, and it is content-visible to anyone forever after. It never
independently re-verifies the CT tree's internal consistency. Per the register's
row-5 vocabulary, that is `countersigned-observed`, never `mmr-verified` — and this
rail does not participate in a checkpoint's `grade`/`continuity_grade` fields at all
(those describe the SUBMITTER's accumulator and this witness's own chain-tip check,
respectively; the public-log rail is a THIRD, orthogonal piece of evidence, reported
only in the separate `public_log` field).

## 8. Deep verification (not in this rail — a follow-on)

This rail proves *submission*, not deep cryptographic checking of Rekor's own
promises: `RekorPublicLog.verify()` today only confirms Rekor's `verification` block
is present, not that the Signed Entry Timestamp validates against Rekor's published
key or that an inclusion proof validates against a Rekor checkpoint. Building that
into the open verifier (`agent-action-capsule` / `verify.agentactioncapsule.org`) and
`cross_witness_conformance/checker.py` is the natural follow-on and can ship without
blocking this rail — the Trust page can link to the raw Rekor entry in the meantime.

## 9. Configuration

See `OPERATOR_GUIDE.md` §2 and `deploy/DEPLOY.md` for the full env var table. In
short: `CAPSULE_ANCHOR_PUBLIC_LOG=rekor` (default `none`) turns the rail on;
`CAPSULE_ANCHOR_REKOR_URL`, `_PUBLIC_LOG_INTERVAL`, `_PUBLIC_LOG_TIMEOUT` tune it.
Startup refuses `rekor` with an ephemeral signing key — publishing an identity that
changes on every restart into a permanent external log is noise, not evidence.

## 10. How to verify an entry by hand

Given a `uuid` from `GET /anchor/public-log/latest`:

```
rekor-cli get --uuid <uuid> --rekor_server https://rekor.sigstore.dev
```

Confirm the entry's `data.hash` equals `SHA256(sth_payload(tree_size, root_hash,
timestamp))` for the STH you expect, and `signature.publicKey` decodes to this
witness's authority key (`GET /anchor/authority-pubkey`).
