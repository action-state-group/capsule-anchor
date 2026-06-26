"""Stable signing-identity loader for the authority root Ed25519 key.

TRUST MODEL
===========
The authority's Ed25519 root key is the existential asset: every
countersignature, transparency-log tree head, CT STH, and the identity CA root
chain back to it. If it is regenerated per process (the prior behaviour), every
restart silently rotates the authority identity — relying parties that pinned
the old public key can no longer verify anything, and the "neutral operator"
guarantee collapses. This module makes the identity STABLE and CONFIGURED.

Resolution order (first match wins)
------------------------------------
1. ``CAPSULE_ANCHOR_SIGNING_KEY``      — raw 32-byte Ed25519 seed, hex-encoded,
                                       supplied directly via env (e.g. injected
                                       from a secret at container start).
2. ``CAPSULE_ANCHOR_SIGNING_KEY_FILE`` — path to a PEM (PKCS#8) or raw/hex seed
                                       file. In production on GCP this path is a
                                       mounted **Secret Manager** secret
                                       (``--set-secrets`` / CSI volume); the
                                       loader never talks to a cloud API itself,
                                       keeping it account-portable and testable.
3. (dev only) generate a fresh key and **WARN LOUDLY**. The process is usable
   but its identity is ephemeral — never acceptable in production.

SECURITY NOTES
--------------
* No private key material is ever committed to the repo or baked into an image.
  The configured source (env/file/Secret Manager) is the only origin in prod.
* The file/env value is a *seed* (or PKCS#8 PEM). It is read into memory only to
  construct the in-process signer; for the strongest posture, prefer
  ``KmsKeyProvider`` (HSM/KMS) where the private bytes never enter the process.
  This loader is the software floor; the KMS provider is the production ceiling.
* A loud warning on generate is intentional: a missing prod secret must fail
  *visibly* (logs + ``ephemeral=True`` on the result) rather than silently
  minting a throwaway identity.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

logger = logging.getLogger(__name__)

ENV_KEY_HEX = "CAPSULE_ANCHOR_SIGNING_KEY"
ENV_KEY_FILE = "CAPSULE_ANCHOR_SIGNING_KEY_FILE"


@dataclass(frozen=True)
class LoadedSigningKey:
    """A loaded Ed25519 signing key plus provenance for observability/audit."""

    private_key: Ed25519PrivateKey
    source: str  # "env" | "file:<path>" | "generated"
    ephemeral: bool  # True only when freshly generated (dev fallback)


def _from_seed_hex(hex_seed: str) -> Ed25519PrivateKey:
    raw = bytes.fromhex(hex_seed.strip())
    if len(raw) != 32:
        raise ValueError(
            f"signing key seed must be 32 bytes (got {len(raw)}); expected a "
            "hex-encoded raw Ed25519 seed"
        )
    return Ed25519PrivateKey.from_private_bytes(raw)


def _from_file(path: str) -> Ed25519PrivateKey:
    data = Path(path).read_bytes()
    # Try PEM/PKCS#8 first, then DER, then a raw/hex seed file.
    try:
        key = serialization.load_pem_private_key(data, password=None)
        if isinstance(key, Ed25519PrivateKey):
            return key
        raise ValueError("PEM key is not Ed25519")
    except ValueError:
        pass
    try:
        key = serialization.load_der_private_key(data, password=None)
        if isinstance(key, Ed25519PrivateKey):
            return key
        raise ValueError("DER key is not Ed25519")
    except ValueError:
        pass
    text = data.decode("ascii", "ignore").strip()
    return _from_seed_hex(text)


def load_signing_key(env: dict[str, str] | None = None) -> LoadedSigningKey:
    """Resolve the authority signing key per the documented precedence.

    Pure-functional w.r.t. ``env`` (defaults to ``os.environ``) so it is unit
    testable without mutating global state.
    """
    e = os.environ if env is None else env

    hex_seed = (e.get(ENV_KEY_HEX) or "").strip()
    if hex_seed:
        return LoadedSigningKey(_from_seed_hex(hex_seed), source="env", ephemeral=False)

    key_file = (e.get(ENV_KEY_FILE) or "").strip()
    if key_file:
        return LoadedSigningKey(
            _from_file(key_file), source=f"file:{key_file}", ephemeral=False
        )

    # Dev fallback: generate + WARN LOUDLY. NEVER acceptable in production.
    logger.warning(
        "AS AUTHORITY SIGNING KEY: no %s or %s configured -- GENERATING AN "
        "EPHEMERAL Ed25519 ROOT KEY. The authority identity will change on every "
        "restart and relying parties CANNOT pin it. Set a configured key (a "
        "mounted Secret Manager secret in production) before going live.",
        ENV_KEY_HEX,
        ENV_KEY_FILE,
    )
    return LoadedSigningKey(Ed25519PrivateKey.generate(), source="generated", ephemeral=True)


class StaticKeyProvider:
    """A ``contracts.KeyProvider`` backed by a single fixed Ed25519 key.

    This adapts a :class:`LoadedSigningKey` to the ``KeyProvider`` seam so the
    attestation/anchoring subsystems sign through the SAME stable authority
    identity. Unlike ``SoftwareKeystore`` it does not seal at rest (the key
    already came from a configured/sealed source — env, mounted secret, etc.)
    and ``rotate`` is intentionally unsupported: rotation of the configured root
    is an operational action (provision a new secret), not a runtime call.

    For production with hardware custody, prefer ``KmsKeyProvider`` where private
    bytes never enter the process.
    """

    def __init__(self, loaded: LoadedSigningKey, crypto=None) -> None:
        from capsule_anchor.contracts import default_crypto

        self._crypto = crypto or default_crypto()
        self._priv_raw = loaded.private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        self._pub = loaded.private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self._key_id = self._crypto.sha256(self._pub)[:16]
        self.source = loaded.source
        self.ephemeral = loaded.ephemeral

    def active_key_id(self) -> str:
        return self._key_id

    def public_key(self, key_id: str | None = None) -> bytes:
        if key_id is not None and key_id != self._key_id:
            raise KeyError(f"unknown key_id: {key_id}")
        return self._pub

    def sign(self, payload: bytes, key_id: str | None = None):
        if key_id is not None and key_id != self._key_id:
            raise KeyError(f"unknown key_id: {key_id}")
        return self._crypto.sign(self._priv_raw, payload)

    def verify(self, payload: bytes, sig) -> bool:
        if sig.key_id != self._key_id:
            return False
        return self._crypto.verify(self._pub, payload, sig)

    def rotate(self) -> str:
        raise NotImplementedError(
            "StaticKeyProvider does not rotate; provision a new configured key "
            "(e.g. a new Secret Manager version) and restart."
        )

    def list_keys(self) -> list[str]:
        return [self._key_id]


def signing_key_seed_hex(key: Ed25519PrivateKey) -> str:
    """Hex-encode an Ed25519 private key's 32-byte seed (for provisioning/tests).

    Helper for operators generating a key to store in Secret Manager. Treat the
    output as a SECRET — it fully reconstructs the authority identity.
    """
    raw = key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    return raw.hex()
