"""AttestorService — Ed25519 signing under the capsule-anchor authority key.

The single signing root the anchoring subsystem reuses to countersign tenant
Merkle roots and to sign Signed Tree Heads for the SCITT transparency log.

KEY CUSTODY (production):
    The authority keypair below is generated IN-PROCESS via ``default_crypto``
    for scaffolding and tests ONLY. In production this private key MUST live in
    an HSM / KMS and never be materialized in application memory (BUILD-PLAN.md
    Section 5; trust-model doc -- "Authority key compromise (DigiNotar)"). The
    ``AttestorService`` interface is deliberately the only place the key is
    used, so swapping the backend to an HSM signer is a constructor change, not
    an interface change.
"""

from __future__ import annotations

from capsule_anchor.contracts import default_crypto
from capsule_anchor.contracts.protocols import CryptoCore, KeyProvider
from capsule_anchor.contracts.types import Signature


class AttestorService:
    """In-process Ed25519 attestor. Satisfies the ``AttestorService`` protocol.

    Holds the authority keypair. ``attest`` signs an arbitrary payload; the
    countersignatures the anchoring subsystem produces all flow through here so
    there is exactly one authority signing root.

    KEY CUSTODY SEAM (additive): pass ``key_provider`` (a
    ``contracts.KeyProvider``) to route all signing/verification through the
    key-custody subsystem (HSM/KMS in production, never materializing private
    bytes here). When ``key_provider is None`` we fall back to the original
    in-process keypair, so this service stays usable without the custody agent
    and all prior behaviour is preserved byte-for-byte.
    """

    def __init__(
        self,
        crypto: CryptoCore | None = None,
        key_provider: KeyProvider | None = None,
    ) -> None:
        self._crypto: CryptoCore = crypto or default_crypto()
        self._key_provider = key_provider
        if key_provider is None:
            # PRODUCTION: replace this in-process generation with an HSM handle
            # (or inject a KeyProvider). Fallback path only.
            self._private_key, self._public_key = self._crypto.generate_keypair()
        else:
            self._private_key = None
            self._public_key = None

    # --- AttestorService protocol -----------------------------------------
    def attest(self, payload: bytes) -> Signature:
        """Sign ``payload`` with the authority private key."""
        if self._key_provider is not None:
            return self._key_provider.sign(payload)
        return self._crypto.sign(self._private_key, payload)

    def verify(self, payload: bytes, sig: Signature) -> bool:
        """Verify a signature was produced by THIS authority key."""
        if self._key_provider is not None:
            return self._key_provider.verify(payload, sig)
        return self._crypto.verify(self._public_key, payload, sig)

    def authority_pubkey(self) -> bytes:
        """Raw Ed25519 public key relying parties verify against."""
        if self._key_provider is not None:
            return self._key_provider.public_key()
        return self._public_key

    # --- convenience ------------------------------------------------------
    @property
    def key_id(self) -> str:
        """Stable id of the authority key (matches ``Signature.key_id``)."""
        if self._key_provider is not None:
            return self._key_provider.active_key_id()
        return self._crypto.sign(self._private_key, b"").key_id

    @property
    def crypto(self) -> CryptoCore:
        """The crypto core, exposed so downstream subsystems share one core."""
        return self._crypto
