"""``RekorPublicLog`` -- Sigstore Rekor backend for the ``PublicLog`` seam.

Submits a ``hashedrekord`` entry whose ``data.hash`` is the SHA-256 of the
caller-supplied payload (typically a Signed Tree Head) and whose
``signature.content`` is the AS authority Ed25519 attestation over those exact
payload bytes, with the AS public key in ``signature.publicKey.content``.

Why ``hashedrekord``? It is Rekor's simplest type and is the right shape for
"some bytes, signed under some key" -- which is exactly what an STH is. We
avoid the in-toto attestation type because we are not making an SLSA-style
claim *about* an artifact; we are publishing the AS tree head itself.

CRITICAL: the HTTP client is INJECTABLE. The default ``httpx.Client`` is built
only when a caller does not pass one. Tests inject an ``httpx.Client`` backed
by an ``httpx.MockTransport`` that returns canned Rekor responses; real
network calls are opt-in. See ``test_rekor_public_log.py``.

NO PLAINTEXT INVARIANT: this module submits whatever ``payload`` bytes a caller
hands it. The ``attach_public_log`` wrapper guarantees those bytes are an STH
(content-free) -- this module deliberately does not need to inspect them.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

import httpx

from capsule_anchor.contracts.types import Signature


# Rekor's hashedrekord schema:
#   https://github.com/sigstore/rekor/blob/main/types/hashedrekord/v0.0.1/hashedrekord_v0_0_1_schema.json
#
# We pin v0.0.1 because that is the long-stable schema; if/when v0.0.2 ships
# the bundle builder is the only thing that needs to change.
_HASHEDREKORD_API_VERSION = "0.0.1"
_HASHEDREKORD_KIND = "hashedrekord"
_REKOR_ENTRIES_PATH = "/api/v1/log/entries"
_PEM_PUBLIC_KEY_FORMAT = b"-----BEGIN PUBLIC KEY-----"


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _ed25519_raw_to_pem(raw_pubkey: bytes) -> bytes:
    """Wrap a 32-byte Ed25519 public key in a SubjectPublicKeyInfo PEM.

    Rekor stores public keys as PEM (X.509 SPKI) in ``signature.publicKey``.
    We construct the SPKI manually rather than pulling in ``cryptography`` here
    -- the Ed25519 OID + raw key prefix is fixed:

        ASN.1: SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING raw_key }
    """
    if len(raw_pubkey) != 32:
        raise ValueError("Ed25519 raw public key must be 32 bytes")
    # Hand-assembled DER for an Ed25519 SubjectPublicKeyInfo. The prefix is
    # constant across all Ed25519 SPKIs.
    spki_prefix = bytes.fromhex("302a300506032b6570032100")
    der = spki_prefix + raw_pubkey
    b64 = base64.encodebytes(der).strip().decode("ascii")
    # 64-char line wrapping is the PEM convention but Rekor accepts unwrapped.
    return (
        b"-----BEGIN PUBLIC KEY-----\n"
        + b64.encode("ascii")
        + b"\n-----END PUBLIC KEY-----\n"
    )


class RekorBundle:
    """Builder for a Rekor ``hashedrekord`` request body.

    Kept as a small static class so tests can assert the wire shape without
    spinning up a full ``RekorPublicLog``.
    """

    @staticmethod
    def build(payload: bytes, sig: Signature, raw_pubkey: bytes) -> dict[str, Any]:
        """Return the JSON-serializable body Rekor expects on POST /entries.

        ``payload``     -- the STH bytes the AS attestor signed.
        ``sig``         -- the AS signature (hex) over those bytes.
        ``raw_pubkey``  -- the AS authority Ed25519 raw 32-byte public key.
        """
        payload_sha256 = hashlib.sha256(payload).hexdigest()
        sig_bytes = bytes.fromhex(sig.signature)
        pem_pubkey = _ed25519_raw_to_pem(raw_pubkey)
        return {
            "apiVersion": _HASHEDREKORD_API_VERSION,
            "kind": _HASHEDREKORD_KIND,
            "spec": {
                "data": {
                    "hash": {
                        "algorithm": "sha256",
                        "value": payload_sha256,
                    },
                },
                "signature": {
                    "content": _b64(sig_bytes),
                    "publicKey": {
                        "content": _b64(pem_pubkey),
                    },
                },
            },
        }


class RekorPublicLog:
    """``PublicLog`` against a Sigstore-style Rekor REST API."""

    _LOG_NAME = "rekor-public"

    def __init__(
        self,
        authority_pubkey: bytes,
        rekor_url: str = "https://rekor.sigstore.dev",
        httpx_client: httpx.Client | None = None,
        timeout: float = 10.0,
    ) -> None:
        """Build a Rekor backend.

        ``authority_pubkey`` -- the AS authority Ed25519 raw 32-byte public key
        (matches ``AnchorerService.authority_pubkey()``). Embedded in every
        submitted entry so Rekor can verify the signature server-side.

        ``rekor_url``   -- base URL of the Rekor instance.
        ``httpx_client``-- INJECTED HTTP client. Tests pass an ``httpx.Client``
                           with a ``MockTransport``; production passes None and
                           we build a default client. Real network is opt-in.
        """
        self._authority_pubkey = bytes(authority_pubkey)
        self._rekor_url = rekor_url.rstrip("/")
        self._owns_client = httpx_client is None
        self._client = httpx_client or httpx.Client(timeout=timeout)

    # --- PublicLog protocol -------------------------------------------------
    def submit(self, payload: bytes, sig: Signature) -> dict:
        """POST a ``hashedrekord`` entry to Rekor; return a receipt dict."""
        body = RekorBundle.build(payload, sig, self._authority_pubkey)
        resp = self._client.post(
            f"{self._rekor_url}{_REKOR_ENTRIES_PATH}",
            json=body,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        # Rekor returns 201 Created on success.
        if resp.status_code not in (200, 201):
            raise RuntimeError(
                f"Rekor submit failed: {resp.status_code} {resp.text[:200]}"
            )
        parsed = resp.json()
        # The response shape is {"<uuid>": {logIndex, integratedTime,
        # verification: {signedEntryTimestamp, inclusionProof?}, body, ...}}.
        if not isinstance(parsed, dict) or not parsed:
            raise RuntimeError("Rekor returned empty response")
        uuid, entry = next(iter(parsed.items()))
        verification = entry.get("verification") or {}
        return {
            "uuid": uuid,
            "log_index": int(entry.get("logIndex", -1)),
            "integrated_time": entry.get("integratedTime"),
            "signed_entry_timestamp": verification.get("signedEntryTimestamp"),
            "location": f"{self._rekor_url}{_REKOR_ENTRIES_PATH}/{uuid}",
            "log": self._LOG_NAME,
        }

    def verify(self, receipt: dict) -> bool:
        """Fetch the entry by uuid; confirm ``verification`` is present + SET non-empty.

        Deeper SET verification (against Rekor's pubkey using the canonical
        verification payload) is a documented stretch -- see
        ``docs/architecture/18-public-log-anchor.md``. The core property we
        check here is *third-party visibility*: the entry exists in the public
        log and Rekor's own attestation over it is present.
        """
        uuid = receipt.get("uuid")
        if not uuid:
            return False
        try:
            resp = self._client.get(
                f"{self._rekor_url}{_REKOR_ENTRIES_PATH}/{uuid}",
                headers={"Accept": "application/json"},
            )
        except httpx.HTTPError:
            return False
        if resp.status_code != 200:
            return False
        try:
            parsed = resp.json()
        except json.JSONDecodeError:
            return False
        if not isinstance(parsed, dict) or uuid not in parsed:
            return False
        entry = parsed[uuid]
        verification = entry.get("verification") or {}
        set_value = verification.get("signedEntryTimestamp")
        if not set_value:
            return False
        # If the caller already has a SET, require it matches what Rekor serves.
        receipt_set = receipt.get("signed_entry_timestamp")
        if receipt_set is not None and receipt_set != set_value:
            return False
        return True

    def name(self) -> str:
        return self._LOG_NAME

    # --- lifecycle ---------------------------------------------------------
    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> "RekorPublicLog":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()
