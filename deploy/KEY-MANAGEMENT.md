# Key Management and Rotation

## The authority key

capsule-anchor's Ed25519 authority key is the existential asset of the transparency
log. Every COSE Receipt, Signed Tree Head (STH), and countersigned root is signed with
it. The key must be:

1. **Stable** — it must never change without a documented rotation (see below).
2. **Non-ephemeral** — the service refuses to start without a configured key
   (`CAPSULE_ANCHOR_INSECURE_EPHEMERAL_KEY=1` is a dev-only escape hatch).
3. **Out of the image** — never baked into a Docker image or committed to the repo.

The key is a 32-byte Ed25519 seed, hex-encoded, stored in Secret Manager and injected
via the `CAPSULE_ANCHOR_SIGNING_KEY` environment variable at container start.

## Current production path (GCP Secret Manager)

```
Secret Manager: capsule-anchor-signing-key
  └── value: <64-hex-char Ed25519 seed>
        ↓ injected by Cloud Run at container start
Cloud Run: CAPSULE_ANCHOR_SIGNING_KEY=<seed>
        ↓ read by load_signing_key() in signing_key.py
StaticKeyProvider in-process signer
```

The private key is in memory only while the process runs. It is never written to disk
or logged.

### Generating the initial key

```bash
python3 -c "import os; print(os.urandom(32).hex())"
# → store the output in Secret Manager, never anywhere else
```

## Key rotation

Rotation does **not** invalidate historical receipts. Each COSE Receipt carries a
`key_id` (the first 16 hex characters of the public key) in the `Signature` structure.
Verifiers use the `key_id` to look up the correct public key for verification.

### Rotation procedure

1. **Generate a new seed** and store it as a new Secret Manager version:
   ```bash
   python3 -c "import os; print(os.urandom(32).hex())" | \
     gcloud secrets versions add capsule-anchor-signing-key --data-file=- --project=PROJECT_ID
   ```

2. **Redeploy** pointing at the new version (or `latest`):
   ```bash
   gcloud run services update capsule-anchor \
     --region=us-central1 \
     --update-secrets=CAPSULE_ANCHOR_SIGNING_KEY=capsule-anchor-signing-key:latest \
     --project=PROJECT_ID
   ```
   Receipts issued after this redeploy carry the new `key_id`. The old version of the
   secret can be kept in Secret Manager for reference.

3. **Publish the new public key.** After rotation, `GET /.well-known/did.json` returns
   the new key. Monitors and verifiers that resolve the DID document at verify-time
   automatically pick up the new key. Verifiers that pinned the old public key must
   update their pin.

### Historical receipt verification after rotation

Old receipts (issued before the rotation) carry the **old** `key_id` and are signed
with the old key. They remain verifiable as long as the verifier knows the old public
key. Two approaches:

**Option A — DID document history (recommended):** Implement a `verificationMethod`
history in `/.well-known/did.json` listing all active and retired public keys. The
verifier uses the `key_id` in the receipt to select the correct key. This is the
standard `did:web` approach.

**Option B — Out-of-band distribution:** Publish old public keys in the repository
`CHANGELOG.md` or a `keys/` directory, with the `key_id`, the raw hex public key, and
the rotation date. Verifiers can retrieve the key out-of-band.

The current service implements a single-key `/.well-known/did.json`. When a rotation
occurs, update the DID document to include the retired key as a historical
`verificationMethod` entry before removing it from the active set.

## GCP Cloud KMS path (future — for production with hardware custody)

The `contracts.protocols.KeyProvider` interface is the seam for KMS/HSM integration.
A `GcpKmsKeyProvider` would:

1. Construct an `AsymmetricSigner` from Cloud KMS (`cloudkms.googleapis.com`).
2. Route all `sign()` calls to the KMS API — the private key bytes never enter the
   process.
3. Pass the provider to `AttestorService(key_provider=GcpKmsKeyProvider(...))`.

The `StaticKeyProvider` (current production) is the software floor; a KMS provider
is the production ceiling when regulatory or audit requirements call for it.

```python
# Sketch — not yet implemented in this repo
class GcpKmsKeyProvider:
    def __init__(self, key_name: str):
        # key_name: "projects/.../cryptoKeyVersions/..."
        from google.cloud import kms
        self._client = kms.KeyManagementServiceClient()
        self._key_name = key_name

    def sign(self, payload: bytes, key_id=None):
        digest = hashlib.sha256(payload).digest()
        resp = self._client.asymmetric_sign(
            name=self._key_name,
            digest={"sha256": digest},
        )
        return Signature(key_id=self.active_key_id(), signature=resp.signature.hex())

    def public_key(self, key_id=None) -> bytes:
        resp = self._client.get_public_key(name=self._key_name)
        # parse PEM → raw bytes
        ...
```

To wire it in, replace `StaticKeyProvider(loaded)` in `app.py` with
`GcpKmsKeyProvider(os.environ["CAPSULE_ANCHOR_KMS_KEY_NAME"])` and remove
`CAPSULE_ANCHOR_SIGNING_KEY` from the Cloud Run secrets.
