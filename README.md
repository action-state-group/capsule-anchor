# capsule-anchor

**A neutral SCITT Transparency Service** — submit a digest, get an
[RFC 9162](https://www.rfc-editor.org/rfc/rfc9162) Certificate-Transparency
COSE Receipt back.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

---

## What it does

`capsule-anchor` implements the
[SCITT Transparency Service](https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/)
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
- Stable Ed25519 authority key (key_id: `19a9ab3e02fad55c`)
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
| `GET`  | `/attest/pubkey` | Authority pubkey (attestation path) |
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

| Env var | Default | Purpose |
|---------|---------|---------|
| `CAPSULE_ANCHOR_SIGNING_KEY` | _(required in prod)_ | Hex-encoded Ed25519 seed. Absent → ephemeral key (loud warning at startup). |
| `CAPSULE_ANCHOR_SIGNING_KEY_FILE` | — | Alternative: path to a PEM/seed file. |
| `CAPSULE_ANCHOR_HOST` | `0.0.0.0` | Bind host. |
| `CAPSULE_ANCHOR_PORT` | `8000` | Bind port. |
| `CAPSULE_ANCHOR_TSA_ENABLED` | `0` | Set `1` to add RFC 3161 TSA timestamps to anchors. |
| `CAPSULE_ANCHOR_TSA_URL` | FreeTSA | Override the TSA endpoint. |
| `AAC_ANCHOR_URL` | — | Consumed by `capsule-emit` to point at this instance. |

**Storage:** in-memory by default (state resets on restart). Install the
`[postgres]` extra and set `CAPSULE_ANCHOR_DB_URL` for durable persistence.

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

---

## Provenance, neutrality & governance

`capsule-anchor` is developed by **Action State Group, Inc.** and published as
open-source software (Apache-2.0). It is product-free — no commercial features,
tier gates, or telemetry are present.

The service implements:

- [draft-ietf-scitt-architecture](https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/) — SCITT Transparency Service
- [RFC 9162 / RFC 6962](https://www.rfc-editor.org/rfc/rfc9162) — Certificate Transparency log
- [draft-ietf-cose-merkle-tree-proofs](https://datatracker.ietf.org/doc/draft-ietf-cose-merkle-tree-proofs/) — COSE Receipt format
- [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) / [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052) — Ed25519 / COSE_Sign1

It is designed with a clean transfer path to a neutral standards body or
foundation donation when the ecosystem matures.

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
