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

No plaintext is ever submitted or stored. All inputs are digests or
content-free Signed Tree Heads.

---

## Free public instance

```
https://witness.agentactioncapsule.org
```

**One service, two vocabularies of route.** `witness.agentactioncapsule.org` is the
checkpoint/CLL-primary name: `POST /checkpoints` is the default route every
`capsule-emit` client registers against; `POST /register` is the explicit opt-in,
plain-SCITT-interop digest route. `anchor.agentactioncapsule.org` (and
`ts.agentactioncapsule.org`) CNAME onto the exact same Cloud Run service — same signing
key, same database, no server-side role flag — and keep answering the legacy routes
(`/v1/digest`, `/transparency/register-statement`, `/anchor/*`) for existing callers.
See [Witness host: checkpoints vs. registration](#witness-host-checkpoints-vs-registration)
below for the full picture, and `deploy/DEPLOY.md` for the DNS mapping.

- Free, public, unauthenticated — for every `log_id` NOT in the enrolled-submitter allowlist
  below, which is every `log_id` today except one.
- Stable Ed25519 authority key; resolve the current `key_id` at [`/.well-known/did.json`](https://witness.agentactioncapsule.org/.well-known/did.json)
- Interactive API docs: [`/docs`](https://witness.agentactioncapsule.org/docs)
- Health: [`/health`](https://witness.agentactioncapsule.org/health)
- **Rate limit**: 300 POST registrations/minute globally — abuse control, not a metering
  quota. The limiter is per-process; a multi-instance deployment's effective limit is
  `300 × instance count` unless a cluster-wide layer (Cloud Armor) is added in front — see
  `deploy/DEPLOY.md`. Exceeding the limit returns `429`.

### Enrolled external checkpoint submitters (`/checkpoints`)

`POST /checkpoints` (above) is open by default: any COSE_Sign1 checkpoint verifying under its
own self-asserted `kid` is counter-signed, for any `log_id`. A NAMED external log can
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

Currently enrolled: the AgenTrust trace registry (`trace-registry/v1`, `countersigned-observed`
grade) — see `packages/capsule_anchor/config/checkpoint_submitters.json`.

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

If you use [`capsule-emit`](https://github.com/action-state-group/capsule-emit),
anchoring is on by default and hits the free public instance automatically:

```python
from capsule_emit import emit

cap = emit(action="summarize", outcome="ok", anchor=True)
print(cap.capsule_id)    # SHA-256 hex digest
print(cap.anchored)      # True
```

To point at your own `capsule-anchor` instance, set `AAC_ANCHOR_URL`:

```bash
export AAC_ANCHOR_URL=https://your-anchor-host/v1/digest
python your_script.py
```

Or per-call:

```python
cap = emit(..., anchor=True, anchor_url="https://your-anchor-host/v1/digest")
```

---

## Registration Policy and Issuer Binding

### Open registration policy (public instance)

The free public instance at `anchor.agentactioncapsule.org` runs an **open registration
policy**: any Signed Statement is accepted regardless of the issuer's identity or signing
key. No authentication of the `iss` claim is enforced at registration time. This is
intentional for a public neutral service — the log is append-only and the receipt
guarantees temporal inclusion; it does not attest issuer provenance.

Production deployments SHOULD enforce issuer binding. The open policy is explicitly stated
here so that relying parties know not to interpret a receipt from the public instance as a
guarantee that the issuer was authenticated.

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
for content-addressing the DER cert bytes — is in the internal design note
`_work/spiffe-who-binding-note.md` and is expected to land in a dedicated profile spec.

---

## API

### `/checkpoints` — checkpoint witnessing (default, witness host)

```bash
curl -s -X POST https://witness.agentactioncapsule.org/checkpoints \
  -H 'Content-Type: application/json' \
  -d '{"v":1,"kind":"mmr_checkpoint","log_id":"...","mmr_size":100,"root":"<64-hex>","prev_size":0,"prev_root":"","key_id":"<64-hex pubkey>","timestamp":"2026-08-27T00:00:00Z","signature":"<hex>"}' \
  | python3 -m json.tool
```

Accepts a CLL (Checkpointed Local Log, `draft-mih-scitt-checkpointed-local-log`)
`CheckpointRecord` verbatim — nothing else. Any other shape is refused with a **named
400** (`NotACheckpointError`) before any signature check or log write; a checkpoint whose
`signature` doesn't verify against `key_id` is refused with **401** and never
counter-signed. This is what makes the route's rejection policy — not a host-level gate —
the thing that keeps a default `capsule-emit` process's egress checkpoint-only.

Returns:

```json
{
  "receipt_b64": "<base64-encoded COSE Receipt>",
  "entry_hash": "<SHA-256 of the checkpoint digest>",
  "entry_hash_scheme": "legacy",
  "leaf_index": 0,
  "tree_size": 1
}
```

Stage 1 is **stateless**: existence-and-time evidence for this checkpoint only, no
per-`log_id` monotonicity/rollback check. Nothing about this route's storage or keying
choices precludes the stage-2 checkpoint-aware upgrade (two-check continuity: `prev_*`
equality AND consistency-proof verification), which lands additively once available.

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
`/checkpoints` (stage 1 of the CLL checkpoint witness) accepts the bare `CheckpointRecord`
wire shape directly, verifies its own signature server-side, and is stateless — the two
surfaces are independent; a client uses one or the other, not both.

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

### CT monitor endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET`  | `/anchor/sth` | Current RFC 6962 Signed Tree Head |
| `GET`  | `/anchor/transparency-log` | Append-only log feed |
| `GET`  | `/anchor/inclusion-proof-ct` | RFC 6962 CT inclusion proof |
| `GET`  | `/anchor/consistency-proof` | RFC 6962 consistency proof |
| `GET`  | `/anchor/authority-pubkey` | Authority Ed25519 public key |
| `GET`  | `/.well-known/did.json` | Authority key as a DID document (JWK OKP) |
| `GET`  | `/health` | Health + signing key source |

---

## Self-host

### pip

```bash
pip install capsule-anchor

# Generate a signing key — keep it, it is your service's identity
python3 -c "import os; print(os.urandom(32).hex())"

CAPSULE_ANCHOR_SIGNING_KEY=<your-hex-seed> capsule-anchor
# Service listening on http://localhost:8000
```

### Docker

```bash
docker build -t capsule-anchor .
docker run -p 8000:8000 \
  -e CAPSULE_ANCHOR_SIGNING_KEY=<your-hex-seed> \
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
  --set-secrets=CAPSULE_ANCHOR_SIGNING_KEY=your-signing-key-secret:latest
```

The public instance at `anchor.agentactioncapsule.org` is deployed this way on
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
| `CAPSULE_ANCHOR_TSA_ENABLED` | `0` | Set `1` to add RFC 3161 TSA timestamps to anchors. |
| `CAPSULE_ANCHOR_TSA_URL` | FreeTSA | Override the TSA endpoint. |
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
capsule-emit  →  POST /v1/digest  →  capsule-anchor  →  COSE Receipt
                                          ↓
                                  RFC 9162 CT log (append-only)
                                          ↓
                               agent-action-capsule verify (offline)
```

The `AAC_ANCHOR_URL` environment variable or `anchor_url=` parameter in
`capsule-emit` lets you repoint at any `capsule-anchor` instance — the free
public one, a private self-hosted deployment, or a local instance for
development. This is the per-capsule `anchor=`/`/register` path — since 0.5.0,
`capsule-emit`'s **default** witnessing path is the per-stream CLL checkpoint
(`CAPSULE_WITNESS_URL`, defaulting to `witness.agentactioncapsule.org/checkpoints`);
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
