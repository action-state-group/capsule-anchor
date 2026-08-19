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
https://anchor.agentactioncapsule.org
```

- Free, public, unauthenticated
- Stable Ed25519 authority key; resolve the current `key_id` at [`/.well-known/did.json`](https://anchor.agentactioncapsule.org/.well-known/did.json)
- Interactive API docs: [`/docs`](https://anchor.agentactioncapsule.org/docs)
- Health: [`/health`](https://anchor.agentactioncapsule.org/health)

`ts.agentactioncapsule.org` resolves to the same service.

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

### Simple digest endpoint (capsule-emit default)

```bash
curl -s -X POST https://anchor.agentactioncapsule.org/v1/digest \
  -H 'Content-Type: application/json' \
  -d '{"capsule_id": "'"$(echo -n hello | sha256sum | awk '{print $1}')"'"}' \
  | python3 -m json.tool
```

Returns:

```json
{
  "receipt_b64": "<base64-encoded COSE Receipt>",
  "entry_hash": "<SHA-256 of the raw digest bytes>",
  "leaf_index": 0,
  "tree_size": 1
}
```

**Offline verify:** `entry_hash = SHA256(bytes.fromhex(capsule_id))` — the CT
leaf the inclusion proof covers, reconstructable from the `capsule_id` alone.

### SCITT Signed Statement registration

```bash
curl -s -X POST https://anchor.agentactioncapsule.org/transparency/register-statement \
  -H 'Content-Type: application/json' \
  -d '{"signed_statement_b64": "<base64-COSE_Sign1>"}' \
  | python3 -m json.tool
```

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
development.

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
