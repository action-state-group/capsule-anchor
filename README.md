# capsule-anchor

**A neutral SCITT Transparency Service** — submit a digest, get an
[RFC 9162](https://www.rfc-editor.org/rfc/rfc9162) Certificate-Transparency
COSE Receipt back.

[![CI](https://github.com/action-state-group/capsule-anchor/actions/workflows/python.yml/badge.svg)](https://github.com/action-state-group/capsule-anchor/actions/workflows/python.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

---

## What it does

`capsule-anchor` implements the
[SCITT Transparency Service (RFC 9943)](https://www.rfc-editor.org/rfc/rfc9943)
(TS) interface, backed by an RFC 9162 (RFC 6962) Certificate-Transparency
Merkle tree:

1. **Register** a SHA-256 digest (or a full COSE_Sign1 Signed Statement) into
   the append-only CT log.
2. **Receive** a COSE Receipt — a COSE_Sign1 (CBOR tag 18) carrying an RFC 9162
   inclusion proof, signed by a stable Ed25519 authority key.
3. **Verify offline** with
   [`agent-action-capsule`](https://github.com/action-state-group/agent-action-capsule)
   or any SCITT-compatible verifier — the receipt proves the digest was in the
   log at a given tree size, without trusting the anchor service itself.

What it keeps is what callers submit: digests, checkpoints (signed commitments
to a log), and Signed Statements. Nothing leaves it unless the operator turns
it on: its own signed tree heads to an external public log, a root's hash to an
RFC 3161 timestamp authority, or a countersignature to a requester's webhook.
A Signed Statement's embedded payload is stored detached (only its SHA-256)
unless the statement was made over a hash; submit a statement over a hash and
keep the content yourself. The policy is published at
[`/transparency/registration-policy`](#data-what-is-stored-and-what-leaves).

---

## Public instance

```
https://witness.agentactioncapsule.org
```

A "witness" here is a SCITT Transparency Service registering checkpoint statements under
a consistency Registration Policy ([RFC 9943](https://www.rfc-editor.org/rfc/rfc9943)).
The policy is published in [`OPERATOR_GUIDE.md`](OPERATOR_GUIDE.md#registration-policy).

**One service, two vocabularies of route.** `witness.agentactioncapsule.org` is the
checkpoint/CLL-primary name: `POST /checkpoints` is the default route every
`capsule-emit` client registers against; `POST /register` is the explicit opt-in,
plain-SCITT-interop digest route. `anchor.agentactioncapsule.org` (and
`ts.agentactioncapsule.org`) CNAME onto the exact same Cloud Run service — same signing
key, same database, no server-side role flag — and keep answering the legacy routes
(`/v1/digest`, `/transparency/register-statement`, `/anchor/*`) for existing callers.
See [Witness host: checkpoints vs. registration](#witness-host-checkpoints-vs-registration)
below for the full picture, and `deploy/DEPLOY.md` for the DNS mapping.

- Public, unauthenticated — for every `log_id` NOT in the enrolled-submitter allowlist
  below, which is every `log_id` today except two.
- Stable Ed25519 authority key; resolve the current `key_id` at [`/.well-known/did.json`](https://witness.agentactioncapsule.org/.well-known/did.json)
- Interactive API docs: [`/docs`](https://witness.agentactioncapsule.org/docs)
- Health: [`/health`](https://witness.agentactioncapsule.org/health)
- **Rate limit**: 300 POST registrations/minute globally — abuse control, not a metering
  quota. The limiter is per-process; a multi-instance deployment's effective limit is
  `300 × instance count` unless a cluster-wide layer (Cloud Armor) is added in front — see
  `deploy/DEPLOY.md`. Exceeding the limit returns `429`.

### Enrolled external checkpoint submitters (`/checkpoints`)

`POST /checkpoints` (above) is open by default: any COSE_Sign1 checkpoint verifying under its
own self-asserted `kid` is signed and receipted, for any `log_id`. A NAMED external log can
additionally be **enrolled** — a config-driven allowlist (`packages/capsule_anchor/config/
checkpoint_submitters.json`, committed, never hand-edited on the deployed box) pins a specific
`log_id` (the CWT `iss`) to a specific Ed25519 key. For an enrolled `log_id`, verification uses
ONLY the pinned key — the envelope's own `kid` is ignored — so a stranger cannot mint a stamp
for an enrolled identity by self-signing with an arbitrary key. Every other `log_id` is
unaffected and keeps the open behavior above.

An enrolled entry's stamp additionally carries a `grade`:

| `grade` | Meaning |
|---|---|
| `mmr-verified` | The submitter's commitment is our own CLL MMR peaks-and-root scheme, which this witness fully understands. |
| `countersigned-observed` | The submitter's commitment is a FOREIGN accumulator this witness does not independently verify — it only observes, timestamps, and countersigns the submitted commitment bytes. **Never equivalent to `mmr-verified`** — this witness does not check a foreign log's own consistency proofs (out of scope for v1). |

Each enrolled entry also gets its own `rate_limit_per_min`, enforced in addition to (not instead
of) the global 300/min budget above.

Currently enrolled (`packages/capsule_anchor/config/checkpoint_submitters.json`):

- `trace-registry/v1`, the AgenTrust trace registry: a foreign accumulator
  (`countersigned-observed`), submitted in the JSON wire form.
- `asg-selftest/v1`: a self-operated test log of this service's operator, a
  native CLL MMR (`mmr-verified`), submitted as COSE.

---

## Witness host: checkpoints vs. registration

| We say | The route | What it does |
|---|---|---|
| **checkpoint witnessing** (default) | `POST /checkpoints` | Registers a CLL checkpoint (a signed snapshot of your whole log). This is the only route a default `capsule-emit` client ever calls — it structurally cannot register anything else (see below). |
| **record registration (legacy)** — opt-in route on the witness host (SCITT-interop) | `POST /register` (canonical) / `POST /v1/digest` (legacy alias) | Registers ONE record's digest and returns a full SCITT Receipt for it — the plain-SCITT-interop case. Never called by any default `capsule-emit` path; pinned by a no-egress CI test on the client. |

A bundle (capsule + inclusion proof + stamped checkpoint) is already per-record proof —
`/register` exists for verifiers that require a per-record SCITT Receipt specifically, not
as an upgrade path from a checkpoint stamp.

**Privacy is enforced at the route level, not the host level.** Both `/checkpoints` and
`/register` are always reachable on this one service; there is no host-level allow-list
that hides `/register`. What keeps a default `capsule-emit` process's egress
checkpoint-only is (1) `/checkpoints` itself refuses any non-checkpoint artifact with a
named error before any signature check or log write, and (2) the client never calls
`/register` from its default `emit()` path — a fact enforced by a CI test, not just
documentation.

---

## Quick start with capsule-emit

[`capsule-emit`](https://github.com/action-state-group/capsule-emit) contacts no
witness until you name one: there is no default. Name this service (the public
instance, or your own) for its checkpoint witnessing:

```bash
export CAPSULE_WITNESS_URL=https://witness.agentactioncapsule.org   # or your own host
python your_script.py
```

or pass `witness_url=` to `seal()`. The per-record `/register` route is the
legacy opt-in: `AAC_ANCHOR_URL=https://your-host/v1/digest`, or
`seal(payload, anchor_url=...)`. See capsule-emit's README for both.

---

## Registration Policy and Issuer Binding

### Open registration policy (public instance)

The public instance at `anchor.agentactioncapsule.org` runs an **open registration
policy**: any Signed Statement is accepted regardless of the issuer's identity or signing
key. No authentication of the `iss` claim is enforced at registration time. This is
intentional for a public neutral service — the log is append-only and the receipt
guarantees temporal inclusion; it does not attest issuer provenance.

Production deployments SHOULD enforce issuer binding. The open policy is explicitly stated
here so that relying parties know not to interpret a receipt from the public instance as a
guarantee that the issuer was authenticated.

The policy is open as to who may submit. The checkpoint paths additionally check what is
submitted: a checkpoint that claims to extend an earlier one is registered only if that
claim is consistent with the last checkpoint registered for the same log. That consistency
check is part of the published Registration Policy — see
[`OPERATOR_GUIDE.md`](OPERATOR_GUIDE.md#registration-policy) for exactly what is checked on
each path.

### Supported issuer-binding patterns

Three patterns are defined for binding the `iss` claim in a Capsule's CWT protected header
to a verifiable signing key:

| # | Pattern | What the TS verifies | Stable identifier | Trust anchor |
|---|---------|----------------------|-------------------|--------------|
| 1 | **did:web** | Resolves `iss` as a DID URI at registration/verification time to obtain the current signing key; verifies COSE signature against that key. | DID URI (resolution is live — no pinned cert expiry). | DID document (resolution-at-verification). |
| 2 | **x5chain** | Validates the certificate chain in the COSE `x5chain` protected header; leaf's public key MUST match the signing key; chain MUST terminate at a configured CA trust root. | `iss` distinguished name or subject URI (RP decision). | Pinned CA trust root. |
| 3 | **SPIFFE SVID** | Variant of x5chain: the leaf certificate MUST carry a SPIFFE ID URI in its Subject Alternative Name; `iss` MUST equal that SPIFFE ID URI; chain terminates at a SPIFFE trust bundle (not a generic CA store). | SPIFFE ID URI (`spiffe://trust-domain/path`) — persists across SPIRE-managed certificate renewals. | SPIFFE trust bundle. |

All three patterns share the same verification entry point: establish the issuer's current
public key, then verify the COSE signature. They differ in how the key is obtained and
what makes the issuer identifier stable across key rotations.

### Degraded assurance for bare kid

A Capsule whose signing key is a bare, unresolvable `kid` with no `x5chain` and no
resolvable DID maps to a **degraded assurance grade** in the registration policy. This
state MUST be reported explicitly — it is not a silent pass. A relying party that requires
issuer authentication SHOULD reject or flag Capsules in this state.

### No cross-pattern substitution

Each pattern is verified under its own trust rules. A did:web resolution result does not
satisfy x5chain trust-chain verification, and neither satisfies SPIFFE trust-bundle
verification. A registration policy MUST NOT treat a successful verification under one
pattern as equivalent to verification under another.

### SPIFFE SVID — third binding type

SPIFFE SVID is the third issuer-binding type alongside did:web and x5chain. The mechanism
sketch — including how the X.509-SVID chain is carried in `x5chain`, why the SPIFFE ID
persists across SPIRE-managed short-lived cert rotations, and the representation discipline
for content-addressing the DER cert bytes — is expected to land in a dedicated profile spec.

---

## API

### `/checkpoints` — checkpoint witnessing (default, witness host)

```bash
curl -s -X POST https://witness.agentactioncapsule.org/checkpoints \
  -H 'Content-Type: application/cll-checkpoint+json' \
  -d '{"v":1,"kind":"mmr_checkpoint","log_id":"...","mmr_size":100,"root":"<64-hex>","prev_size":0,"prev_root":"","key_id":"<64-hex pubkey>","timestamp":"2026-08-27T00:00:00Z","signature":"<hex>"}' \
  | python3 -m json.tool
```

The body is a COSE_Sign1 checkpoint (the default wire form). The JSON form shown
above is accepted only with `Content-Type: application/cll-checkpoint+json`, and
only for a `log_id` enrolled with the JSON wire form (see the enrolled submitters
above); any other `Content-Type` is parsed as COSE.

Accepts a CLL (Checkpointed Local Log, `draft-mih-scitt-checkpointed-local-log`)
`CheckpointRecord` verbatim — nothing else. Any other shape is refused with a **named
400** (`NotACheckpointError`) before any signature check or log write; a checkpoint whose
`signature` doesn't verify against `key_id` is refused with **401** and never
signed. This is what makes the route's rejection policy — not a host-level gate —
the thing that keeps a default `capsule-emit` process's egress checkpoint-only.

Returns:

```json
{
  "receipt_b64": "<base64-encoded COSE Receipt>",
  "entry_hash": "<SHA-256 of the checkpoint digest>",
  "entry_hash_scheme": "legacy",
  "leaf_index": 0,
  "tree_size": 1,
  "continuity_grade": "first-seen"
}
```

**Checkpoint-aware witness (stage 2).** This witness remembers, per `log_id`, the last
checkpoint it accepted, and returns exactly one of three continuity grades — never bare
"witnessed":

| `continuity_grade` | Meaning |
|---|---|
| `first-seen` | This witness has never seen `log_id` before. Nothing to be consistent with; no continuity is implied, even if the log itself has a long history elsewhere. |
| `registered` | A known `log_id`, but the checkpoint carried no `consistency_proof`. Registration only. For a native CLL log this happens only under the `warn` (default) or `off` setting of `CAPSULE_ANCHOR_REQUIRE_CONSISTENCY_PROOF`; under `enforce` it is refused (409, `code: consistency_proof_required`). A foreign accumulator, or any JSON-wire submitter, is never refused for the proof's absence. |
| `continuity-witnessed` | A known `log_id`, a `consistency_proof` was submitted, and this witness independently verified BOTH that the submitted `prev_size`/`prev_root` equal its own last-accepted checkpoint for `log_id` (fork detection) AND that the proof itself (checked with the neutral CLL core's `verify_consistency` — this witness never builds trees) bridges its last-accepted state to the new one. Only this grade signs a continuity assertion into the receipt's protected header. |

A checkpoint carrying a `consistency_proof` that fails either check is refused with
**409** — never signed, no log append, treated as evidence of log mutation, never
retried. The response body carries this witness's own last-accepted `(mmr_size, root)` so
an honest client that skipped a cadence can re-prove from the witness's view:

```json
{
  "error": "checkpoint for log_id='...' prev_size/prev_root does not match this witness's own last-accepted checkpoint ...",
  "last_accepted_mmr_size": 100,
  "last_accepted_root": "<64-hex>"
}
```

Under `enforce`, a native log's later checkpoint with no `consistency_proof` is refused
with the same 409 shape plus `"code": "consistency_proof_required"`. A node that lost its
local log state must start a new `log_id`: it cannot prove it extends what this witness
already accepted.

**Honesty.** This service registers checkpoints and, when a consistency proof is
supplied, verifies that the new checkpoint extends the last one it accepted. It is
operated by the party that publishes the specification; independence is yours to assess.
A single witness's `continuity-witnessed` grade describes rewriting relative to *this*
witness's own view only — running more than one independent witness remains the
anti-equivocation lever a single witness's own claim cannot provide.

### `/register` — record registration (legacy: `/v1/digest`), opt-in route (SCITT-interop)

```bash
curl -s -X POST https://witness.agentactioncapsule.org/register \
  -H 'Content-Type: application/json' \
  -d '{"capsule_id": "'"$(echo -n hello | sha256sum | awk '{print $1}')"'"}' \
  | python3 -m json.tool
```

Returns:

```json
{
  "receipt_b64": "<base64-encoded COSE Receipt>",
  "entry_hash": "<SHA-256 of the raw digest bytes>",
  "entry_hash_scheme": "legacy",
  "leaf_index": 0,
  "tree_size": 1
}
```

**Offline verify:** `entry_hash = SHA256(bytes.fromhex(capsule_id))` — the CT
leaf the inclusion proof covers, reconstructable from the `capsule_id` alone.

`POST /v1/digest` is the same handler under its legacy name, kept for existing callers
registered against `anchor.agentactioncapsule.org`. **This route is opt-in** — a
default `capsule-emit` client never calls it; see
[Witness host: checkpoints vs. registration](#witness-host-checkpoints-vs-registration).

### SCITT Signed Statement registration

```bash
curl -s -X POST https://anchor.agentactioncapsule.org/transparency/register-statement \
  -H 'Content-Type: application/json' \
  -d '{"signed_statement_b64": "<base64-COSE_Sign1>"}' \
  | python3 -m json.tool
```

Returns:

```json
{
  "receipt_b64": "<base64-encoded COSE Receipt>",
  "entry_hash": "<CT-log entry hash>",
  "entry_hash_scheme": "sig_structure",
  "leaf_index": 0,
  "tree_size": 1,
  "checkpoint_witness": null
}
```

**Entry identifier derivation.** `entry_hash` is `SHA256` of the RFC 9052 SS4.4
`Sig_structure` (the signed-over bytes, excluding the signature) when the submitted bytes
are a well-formed COSE_Sign1 with an embedded payload — `entry_hash_scheme:
"sig_structure"`. This is malleability-immune: an ECDSA signature is not a function of the
signing act (for any valid `(r, s)`, `(r, n−s)` also verifies with no private key needed),
so a signature-malleated re-encoding of the same signed statement now registers as the
SAME entry and returns the ORIGINAL receipt, instead of minting a second leaf. Statements
that aren't a parseable COSE_Sign1 (e.g. the `/v1/digest` surface's raw digest bytes, which
were never a signed structure) keep hashing the raw bytes — `entry_hash_scheme: "legacy"`,
unchanged behavior. `entry_hash` doubles as the CT leaf preimage hex
(`SHA256(0x00 || bytes.fromhex(entry_hash))` is the leaf a monitor recomputes) for
whichever scheme minted that entry — historical leaves keep the scheme they were minted
with; only new registrations of a parseable COSE_Sign1 move to `sig_structure`.

**Dual-lookup window.** Resubmitting bytes that were registered before this migration
(under the legacy full-envelope scheme) still returns the original receipt: on a
new-scheme cache miss, the service falls back to a legacy-scheme lookup before deciding a
submission is genuinely new. No leaf is lost and no signature is invalidated by this
migration — only the identifier surface for new registrations changed shape.

### Checkpoint witness surface (`mmr-checkpoint`) on `/transparency/register-statement`

Not to be confused with `/checkpoints` above — this is a SEPARATE, older mechanism: a
checkpoint capsule — a signed snapshot of one log's MMR peak set, e.g. from
[`capsule-emit`'s `checkpoint` module](https://github.com/action-state-group/capsule-emit)
— wrapped as a Signed Statement, so it registers through the SAME
`/transparency/register-statement` endpoint above with zero new routes. What's different
is WITNESS behavior: a statement whose payload self-declares `"artifact_type":
"mmr-checkpoint"` is auto-recognized and checked against the log's own last-witnessed
checkpoint for its `log_id` before being co-signed. Any other `artifact_type` (or none)
registers exactly as an ordinary Signed Statement — `checkpoint_witness` stays `null`.
`/checkpoints` accepts the bare `CheckpointRecord` wire shape directly and verifies its
signature server-side, which this path does not. It is not stateless: it remembers, per
`log_id`, the last checkpoint it accepted, and advances that record only on a `first-seen`
or `continuity-witnessed` acceptance (never on a bare `registered` one) — see the
`/checkpoints` section above. Both surfaces read and write that same per-`log_id` record,
so a client uses one or the other for a given `log_id`, not both.

Payload shape (JSON, embedded as the COSE_Sign1's payload):

```json
{
  "artifact_type": "mmr-checkpoint",
  "log_id": "<caller-chosen log identifier>",
  "key_id": "<signer's key id -- doubles as a peer id>",
  "mmr_root": "<64-hex, 32-byte MMR root at mmr_size>",
  "mmr_size": 250,
  "prev_size": 100,
  "timestamp": "2026-08-22T00:00:00Z"
}
```

Checks performed, in order:

1. **Self-consistency** (400 on failure): `prev_size` strictly less than `mmr_size`,
   `mmr_root` is 64-hex, `log_id`/`key_id`/`timestamp` are non-empty strings.
2. **Witness consistency** (409 on failure, response `detail` explains why): unknown
   `log_id` → accepted and graded `"first-seen"` — honestly, since there is nothing yet to
   be consistent with, no continuity is implied. A known `log_id` must chain exactly from
   the last checkpoint this service witnessed (`prev_size` equal to that checkpoint's
   `mmr_size`, and `mmr_size` strictly greater) → graded `"witnessed"`. Anything else — a
   rollback, a fork, a gap — is refused and **never co-signed**: no log append, no
   signature, `tree_size` does not change.

This is a chain-linkage check against what THIS service has witnessed, not an independent
recomputation of the MMR's peaks (the witness never sees the raw log) — the strongest
check available given the accepted wire shape above.

### Every route

From `packages/capsule_anchor/app.py` and `anchoring/router.py` (and
`countersign/router.py`, mounted only when countersign is on). FastAPI's
`/docs`, `/redoc` and `/openapi.json` are served too.

| Method | Path | Description |
|--------|------|-------------|
| `GET`  | `/` | Static landing page |
| `GET`  | `/health`, `/healthz`, `/livez` | Health: signing-key source, `key_id`, tree size, storage, entry retention, latest tree head, and the public-log state when that is on |
| `GET`  | `/.well-known/did.json` | Authority key as a DID document (JWK OKP), from `CAPSULE_ANCHOR_PUBLIC_HOST` |
| `POST` | `/checkpoints` | Register a CLL checkpoint (above) |
| `GET`  | `/checkpoints/{log_id}` | The last checkpoint witnessed for `log_id`, with any equivocations recorded (404 if never seen) |
| `POST` | `/register` | Register a 64-hex digest (above) |
| `POST` | `/v1/digest` | Legacy alias of `/register` |
| `GET`  | `/v1/inclusion/{capsule_id}` | Inclusion proof and receipt for a registered digest (404 if absent); never registers |
| `POST` | `/transparency/register-statement` | Register a SCITT Signed Statement (above) |
| `GET`  | `/transparency/statements?subject=` | Every statement registered under a CWT `sub`, with what was kept of its payload and `payload_form` (unauthenticated claims; see [Data](#data-what-is-stored-and-what-leaves)) |
| `GET`  | `/transparency/registration-policy` | This service's registration policy (embedded-payload storage, size limits, issuer binding) and privacy posture (what it stores, what leaves it) |
| `POST` | `/anchor/anchor` | Countersign a caller's `{tenant_id, root_hash, seq_from, seq_to}` and append it to the log; adds an RFC 3161 timestamp when the TSA is on |
| `GET`  | `/anchor/countersigned-root` | Look up a countersigned root by `tenant_id` and `root_hash` |
| `GET`  | `/anchor/sth` | Current RFC 6962 Signed Tree Head |
| `GET`  | `/anchor/transparency-log` | Append-only log feed |
| `GET`  | `/anchor/inclusion-proof-ct` | RFC 6962 CT inclusion proof |
| `GET`  | `/anchor/consistency-proof` | RFC 6962 consistency proof |
| `POST` | `/anchor/inclusion-proof` | A Merkle proof over leaf hashes the caller supplies |
| `POST` | `/anchor/verify-inclusion` | Check a Merkle proof; returns `{valid}` |
| `GET`  | `/anchor/authority-pubkey` | Authority Ed25519 public key |
| `GET`  | `/anchor/public-log/latest` | The latest external public-log receipt (404 when that rail is off or nothing is published yet) |
| `GET`  | `/anchor/public-log/entries?since=` | External public-log receipts after a tree size (`[]` when the rail is off) |
| `POST` | `/countersign/register` | Countersign an Evidence Bundle (only when countersign is on; see below) |

---

## Data: what is stored and what leaves

**Stored** (SQLite or Postgres; `anchoring/store.py`): the log's leaf hashes;
countersigned roots with their caller-chosen `tenant_id`; the capsule ids bound
to log entries; the receipt cache; per-`log_id` checkpoint state and recorded
equivocations; the tree heads; public-log receipts and failures; and a subject
index for Signed Statements.

**A Signed Statement's embedded payload is stored detached by default.**
`/transparency/register-statement` accepts any COSE_Sign1 up to 64 KB and does
not verify its signature. When the statement's protected header carries a CWT
`sub`, the service indexes it under that subject and keeps, of its payload
(`anchoring/payload_policy.py`):

| The statement | Kept in the subject index | `payload_form` |
|---|---|---|
| made over a hash: the [RFC 9943](https://www.rfc-editor.org/rfc/rfc9943) §6.2 hash envelope (protected header 258 `payload_hash_alg`, payload of that digest's length), or a 32-byte `capsule_id` under `application/vnd.agent-action-capsule.capsule-id+octet-stream` | the payload as submitted (it is a digest) | `digest` |
| any other embedded payload (the default) | only the payload's SHA-256 (§8.4) | `sha256` |
| any other embedded payload, when the operator opts in and it is within the cap | the payload as submitted | `embedded` |

`GET /transparency/statements` returns that value with its `payload_form`.
**Submit a statement made over a hash** (§6.2): put the digest in the payload
and keep the preimage yourself.

**Receipts are unaffected.** A receipt covers the entry hash, the SHA-256 of
the statement's `Sig_structure`, which includes the payload and is computed at
registration, so it verifies offline with any SCITT verifier exactly as before.
What a detached payload changes is who can re-check the statement's signature
later: anyone holding the statement from its issuer can; this service no longer
holds the payload to (§5.1.3). A relying party gets the statement, payload
included, from its issuer.

**The registration policy is the operator's and is published** (§5.1.1):
`CAPSULE_ANCHOR_STORE_EMBEDDED_PAYLOADS` (`off` by default, or `on`) and
`CAPSULE_ANCHOR_EMBEDDED_PAYLOAD_MAX_BYTES` (the cap for `on`, default 1024;
a larger payload is stored detached). A malformed value stops startup.
`GET /transparency/registration-policy` publishes this policy and the service's
privacy posture (what it stores, what leaves it) so an issuer can decide what
to submit: RFC 9943 §8.2 puts that check on issuers. `/health` carries
`embedded_payloads` (`detached` or `as_submitted_up_to_cap`).

**Statements registered before this policy** keep what was stored then (their
payload as submitted; `payload_form` is `null`). The policy applies to new
registrations only; nothing is rewritten.

The subject and a countersigned root's `tenant_id` are stored verbatim.

**What leaves the service**, each only when the operator turns it on:

- **External public log** (`CAPSULE_ANCHOR_PUBLIC_LOG=rekor`): the service's own
  Signed Tree Heads, as below.
- **RFC 3161 timestamps** (`CAPSULE_ANCHOR_TSA_ENABLED=1`): the SHA-256 of a
  countersigned root, sent to the TSA from `/anchor/anchor` only.
- **Countersign webhooks** (countersign on, and the request names a webhook):
  the countersignature the request produced, sent to the URL in that request.

Nothing else is sent anywhere; there is no telemetry.

## Publishing tree heads to an external public log (optional)

`packages/capsule_anchor/public_log/` publishes this service's own Signed Tree
Heads to an external transparency log, so that anyone can see which tree heads
it issued. It is **off unless `CAPSULE_ANCHOR_PUBLIC_LOG=rekor`** (the only other
accepted value is `none`, the default; anything else stops startup), and with
it on an ephemeral signing key is refused.

- **What is published:** only the current tree head, as canonical JSON of
  `{tree_size, root_hash, timestamp}`, in a DSSE envelope signed by the
  service's authority key, to `CAPSULE_ANCHOR_REKOR_URL` (default
  `https://rekor.sigstore.dev`). No record, digest or checkpoint is published.
- **When:** a background thread wakes every `CAPSULE_ANCHOR_PUBLIC_LOG_INTERVAL`
  seconds (default 300) and calls `publish_if_new`: nothing when the log is
  empty or the current tree head is already published; otherwise it submits it
  and stores the external receipt. Once more at shutdown. Never inline on a
  registration request.
- **Failures** are logged, counted and stored; after 12 in a row `/health`
  reports `public_log: "degraded"` (without changing `ok`).
- **Reading back:** `GET /anchor/public-log/latest` and
  `GET /anchor/public-log/entries`. When a published receipt already covers a
  `/checkpoints` response's tree size, the response names it (`public_log`),
  and a copy of the receipt carries it in an unprotected header; the stored
  receipt and its signature are unchanged.

## Countersign (optional, off by default)

`POST /countersign/register` is mounted only when both
`CAPSULE_ANCHOR_COUNTERSIGN=1` and `CAPSULE_ANCHOR_REGISTRATION_POLICY=strict`
are set (`countersign/config.py`). It countersigns an Agent Action Capsule
Evidence Bundle v2 for a requester this service already knows:

1. **The bundle** must be an Evidence Bundle v2 with no payloads
   (`completeness.payloads_mode` is `"none"`, and no `disclosures`); its digest
   is computed by `agent-action-capsule`'s neutral bundle library.
2. **The requester** must be on the issuer allowlist,
   `CAPSULE_ANCHOR_COUNTERSIGN_ISSUERS_FILE` (a JSON array of
   `{ledger_id, pubkey_hex}`). With no file the allowlist is empty and every
   request is refused; a malformed file stops startup. The requester's key must
   be the pinned one, and its Ed25519 signature over the bundle digest must
   verify. Any refusal is a 422.
3. **Checks are recomputed** from the bundle (range membership through the
   neutral library's `verify_bundle`, profile coverage, and others reported as
   established, failed, not present, not checked or inconclusive).
4. **The countersignature** (`countersign/v1`) is signed by the service's
   authority key over the canonical statement of those results, says whether the
   signer is independent of the requester, and is registered in the log; its
   receipt comes back with it. `CAPSULE_ANCHOR_PUBLIC_HOST` must be set (503
   otherwise).
5. **A webhook**, when the request names both a `webhook_url` and a
   `webhook_secret`: the countersignature is POSTed there after signing, HMAC-
   SHA256-signed (`X-Countersign-Signature`). The URL must be https, resolve
   only to public addresses (checked at admission and again at delivery, with
   the connection pinned to the checked address and no redirects), and match
   `CAPSULE_ANCHOR_COUNTERSIGN_WEBHOOK_ALLOWED_HOSTS` when that is set. Four
   attempts, backing off 1, 4 and 16 seconds; nothing is stored about delivery.

See [`COUNTERSIGN.md`](COUNTERSIGN.md).

## Other modules

- `cross_witness_conformance/`: checks an external CLL checkpoint submitter
  (`trace-registry/v1` by default) against this witness: wire form and enrolled
  identity and grade, the tie-back through `/v1/inclusion/{capsule_id}` with
  offline receipt verification, and chain continuity.
  `python -m capsule_anchor.cross_witness_conformance.watcher <checkpoint-file|-> [--witness-base-url URL]`.
- `anchoring/retention.py`: optional pruning of the receipt cache only
  (`CAPSULE_ANCHOR_ENTRY_RETENTION`, seconds; unset means never). Log entries,
  tree heads and recorded equivocations are never pruned.
- `attestation/`: the single Ed25519 signing root (tree heads, COSE receipts,
  countersigned roots, countersignatures). It has no HTTP route: a public
  sign-these-bytes endpoint would let anyone mint this service's signature.
- `contracts/`: the shared data models (`types.py`) and protocols
  (`protocols.py`), and a pure-Python crypto shim (`crypto_shim.py`).
- `examples/cross-witness-checkpoint-smoke/`: build a COSE checkpoint, submit it
  to `/checkpoints`, fetch it back through `/v1/inclusion/{digest}` and verify it
  offline; with a walkthrough and a recorded transcript.

---

## Self-host

Anyone can run one. The DID published at `/.well-known/did.json` is derived from
`CAPSULE_ANCHOR_PUBLIC_HOST` — when you host it, the DID is yours, not ours; there is no default
to our domain, so you must set it to the hostname you actually serve from.

### pip

```bash
pip install capsule-anchor

# Generate a signing key — keep it, it is your service's identity
python3 -c "import os; print(os.urandom(32).hex())"

CAPSULE_ANCHOR_SIGNING_KEY=<your-hex-seed> CAPSULE_ANCHOR_PUBLIC_HOST=your-domain.example.com capsule-anchor
# Service listening on http://localhost:8000
```

### Docker

```bash
docker build -t capsule-anchor .
docker run -p 8000:8000 \
  -e CAPSULE_ANCHOR_SIGNING_KEY=<your-hex-seed> \
  -e CAPSULE_ANCHOR_PUBLIC_HOST=your-domain.example.com \
  capsule-anchor
```

### Cloud Run (one command)

```bash
gcloud run deploy capsule-anchor \
  --source . \
  --project=YOUR_PROJECT \
  --region=us-central1 \
  --port=8000 \
  --max-instances=1 \
  --allow-unauthenticated \
  --set-env-vars=CAPSULE_ANCHOR_PUBLIC_HOST=your-domain.example.com \
  --set-secrets=CAPSULE_ANCHOR_SIGNING_KEY=your-signing-key-secret:latest
```

The public instance at `witness.agentactioncapsule.org` is deployed this way on
GCP. See [`deploy/DEPLOY.md`](deploy/DEPLOY.md) for the full walkthrough.

---

## Configuration

The service is **fail-closed by default**: it refuses to start without both a stable signing key
and a durable store. The `INSECURE_*` env vars below are dev-only escape hatches.

| Env var | Default | Purpose |
|---------|---------|---------|
| `CAPSULE_ANCHOR_SIGNING_KEY` | _(required)_ | Hex-encoded Ed25519 seed (from Secret Manager). Absent → startup fails. |
| `CAPSULE_ANCHOR_SIGNING_KEY_FILE` | — | Alternative: path to a PEM/seed file. |
| `CAPSULE_ANCHOR_DATABASE_URL` | _(required)_ | Postgres connection URL. Absent → startup fails. |
| `CAPSULE_ANCHOR_HOST` | `0.0.0.0` | Bind host. |
| `CAPSULE_ANCHOR_PORT` | `8000` | Bind port. |
| `CAPSULE_ANCHOR_PUBLIC_HOST` | _(required)_ | The hostname you serve from; the DID and countersign signer id derive from it. |
| `CAPSULE_ANCHOR_OPERATOR` | — | Optional `operator` field in `/.well-known/did.json`. |
| `CAPSULE_ANCHOR_REQUIRE_CONSISTENCY_PROOF` | `warn` | `off`, `warn` or `enforce`, for native CLL checkpoints (above). |
| `CAPSULE_ANCHOR_CHECKPOINT_SUBMITTERS_FILE` | packaged `config/checkpoint_submitters.json` | The enrolled-submitter allowlist. |
| `CAPSULE_ANCHOR_STH_REFRESH_INTERVAL` | `60` | Seconds between tree-head refreshes. |
| `CAPSULE_ANCHOR_ENTRY_RETENTION` | unlimited | Prune the receipt cache after this many seconds. |
| `CAPSULE_ANCHOR_ENTRY_RETENTION_SWEEP_INTERVAL` | `3600` | Seconds between retention sweeps. |
| `CAPSULE_ANCHOR_TSA_ENABLED` | `0` | Set `1` to add RFC 3161 TSA timestamps to anchors. |
| `CAPSULE_ANCHOR_TSA_URL` | FreeTSA | Override the TSA endpoint. |
| `CAPSULE_ANCHOR_PUBLIC_LOG` | `none` | `rekor` publishes this service's tree heads (see above). |
| `CAPSULE_ANCHOR_REKOR_URL` | `https://rekor.sigstore.dev` | Where they go. |
| `CAPSULE_ANCHOR_PUBLIC_LOG_INTERVAL` | `300` | Seconds between publish attempts. |
| `CAPSULE_ANCHOR_PUBLIC_LOG_TIMEOUT` | `10` | HTTP timeout, seconds. |
| `CAPSULE_ANCHOR_COUNTERSIGN` | — | `1`, with `CAPSULE_ANCHOR_REGISTRATION_POLICY=strict`, mounts countersign. |
| `CAPSULE_ANCHOR_REGISTRATION_POLICY` | — | `strict` (needed for countersign). |
| `CAPSULE_ANCHOR_COUNTERSIGN_ISSUERS_FILE` | — | The countersign issuer allowlist; unset refuses every request. |
| `CAPSULE_ANCHOR_COUNTERSIGN_WEBHOOK_ALLOWED_HOSTS` | — | Optional comma list of webhook hosts. |
| `CAPSULE_ANCHOR_STORE_EMBEDDED_PAYLOADS` | `off` | `on` keeps a Signed Statement's embedded payload as submitted, up to the cap; `off` stores it detached (its SHA-256). |
| `CAPSULE_ANCHOR_EMBEDDED_PAYLOAD_MAX_BYTES` | `1024` | The cap for `on`; a larger payload is stored detached. |
| `AAC_ANCHOR_URL` | — | Consumed by `capsule-emit` to point at this instance. |
| `CAPSULE_ANCHOR_INSECURE_EPHEMERAL_KEY` | — | **Dev only.** Set `1` to allow startup without a signing key. |
| `CAPSULE_ANCHOR_INSECURE_IN_MEMORY` | — | **Dev only.** Set `1` to allow startup without `CAPSULE_ANCHOR_DATABASE_URL`. |

**Storage:** Postgres (`[postgres]` extra + `CAPSULE_ANCHOR_DATABASE_URL`) is required in production.
For Cloud Run, use the unix-socket URL form with `--add-cloudsql-instances`. See [`deploy/DEPLOY.md`](deploy/DEPLOY.md).

---

## Pairing with capsule-emit

`capsule-anchor` is the server-side counterpart to
[`capsule-emit`](https://github.com/action-state-group/capsule-emit), the
producer library for the
[Agent Action Capsule](https://github.com/action-state-group/agent-action-capsule)
profile.

```
capsule-emit  →  POST /checkpoints  →  capsule-anchor  →  COSE Receipt
                 (or the opt-in POST /register)
                                          ↓
                                  RFC 9162 CT log (append-only)
                                          ↓
                               agent-action-capsule verify (offline)
```

The `AAC_ANCHOR_URL` environment variable or `anchor_url=` parameter in
`capsule-emit` lets you repoint at any `capsule-anchor` instance — the
public one, a private self-hosted deployment, or a local instance for
development. This is the per-capsule `anchor=`/`/register` path — since 0.5.0,
`capsule-emit`'s witnessing path is the per-stream CLL checkpoint
(`CAPSULE_WITNESS_URL`, which has no default: name the witness you use);
see [Witness host: checkpoints vs. registration](#witness-host-checkpoints-vs-registration).

**See [ADOPT.md](ADOPT.md) for the full adoption ladder** — no anchor, self-hosted,
public, and the roadmap toward issuer-binding-enforced registration — stated as
what works today vs. what's still designed, not yet built.

---

## Third-party usage

Independent parties have registered statements and verified receipts against the
live public instance. The Microsoft-signed statement at leaf 151 and the
[examples-repo PR #4](https://github.com/action-state-group/agent-action-capsule/pull/4)
are on the public record; receipts from that run were verified by an independent
verifier written on a different COSE stack, confirming the log and receipt format
interoperate across implementations.

---

## Provenance, neutrality & governance

`capsule-anchor` is developed by **Action State Group, Inc.** and published as
open-source software (Apache-2.0). It is product-free — no commercial features,
tier gates, or telemetry are present.

The service implements:

- [RFC 9943](https://www.rfc-editor.org/rfc/rfc9943) — SCITT Architecture (Transparency Service)
- [RFC 9162 / RFC 6962](https://www.rfc-editor.org/rfc/rfc9162) — Certificate Transparency log
- [draft-ietf-cose-merkle-tree-proofs](https://datatracker.ietf.org/doc/draft-ietf-cose-merkle-tree-proofs/) — COSE Receipt format
- [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) / [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052) — Ed25519 / COSE_Sign1

It is designed with a clean transfer path to a neutral standards body or
foundation donation when the ecosystem matures.

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
