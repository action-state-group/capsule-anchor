"""Protocol interfaces — the seams every subsystem implements or depends on.

Two kinds live here:

1. ``CryptoCore`` — the Python-facing interface for signing, hashing, and
   Merkle operations. A pure-Python shim (``crypto_shim.ShimCryptoCore``)
   satisfies this for tests and development; production uses an HSM-backed
   implementation injected at construction time.

2. Service protocols — ``AnchorerService``, ``AttestorService``,
   ``KeyProvider``, and ``PublicLog`` — the seams between the anchor
   subsystems. Keeping the interfaces explicit here makes the boundaries
   clear and each subsystem testable in isolation.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from .types import (
    AnchorReceipt,
    Commitment,
    CountersignedRoot,
    MerkleProof,
    Signature,
    TransparencyLogEntry,
)


# ---------------------------------------------------------------------------
# Crypto core
# ---------------------------------------------------------------------------


@runtime_checkable
class CryptoCore(Protocol):
    """Signing, hashing, Merkle, and commitment primitives.

    All bytes in/out are raw; hex encoding happens at the model boundary.
    A pure-Python reference shim exists in ``contracts.crypto_shim`` for
    tests and to unblock parallel work without a compiled artifact.
    """

    # --- signing ---
    def generate_keypair(self) -> tuple[bytes, bytes]:
        """Return (private_key, public_key) for Ed25519."""

    def sign(self, private_key: bytes, payload: bytes) -> Signature: ...

    def verify(self, public_key: bytes, payload: bytes, sig: Signature) -> bool: ...

    # --- hashing / chain ---
    def sha256(self, payload: bytes) -> str: ...

    def merkle_root(self, leaf_hashes: list[str]) -> str:
        """SHA-256 Merkle root: empty list → '' ; odd node promoted unchanged."""

    def merkle_proof(self, leaf_hashes: list[str], index: int) -> MerkleProof: ...

    def verify_merkle_proof(self, proof: MerkleProof) -> bool: ...

    def verify_chain(self, commitments: list[Commitment]) -> bool:
        """Verify prev_hash linkage across an ordered commitment list."""

    # --- commitments (salted commit-and-reveal) ---
    def commit(self, plaintext: bytes, salt: bytes) -> str:
        """Hiding+binding commitment to plaintext."""

    def verify_commitment(self, plaintext: bytes, salt: bytes, commit: str) -> bool: ...


# ---------------------------------------------------------------------------
# Anchor subsystem protocols
# ---------------------------------------------------------------------------


@runtime_checkable
class AnchorerService(Protocol):
    """Countersign a tenant root and publicly anchor it."""

    def anchor(self, tenant_id: str, root_hash: str,
               seq_range: tuple[int, int]) -> AnchorReceipt: ...

    def get_countersigned_root(self, tenant_id: str,
                               root_hash: str) -> CountersignedRoot | None: ...

    def transparency_log(self, after_index: int = 0) -> list[TransparencyLogEntry]: ...


@runtime_checkable
class AttestorService(Protocol):
    """Ed25519 signing under the authority key."""

    def attest(self, payload: bytes) -> Signature: ...

    def verify(self, payload: bytes, sig: Signature) -> bool: ...

    def authority_pubkey(self) -> bytes: ...


@runtime_checkable
class KeyProvider(Protocol):
    """Custody of the authority's signing keys.

    Subsystems sign through this seam instead of holding raw key bytes.
    A software implementation encrypts keys at rest; an HSM/KMS
    implementation never exposes private bytes. Key rotation + multiple
    key ids let a relying party verify historical signatures after a
    rotation without losing the ability to verify the past.
    """

    def active_key_id(self) -> str:
        """The key id new signatures are produced under."""

    def public_key(self, key_id: str | None = None) -> bytes:
        """Raw Ed25519 public key for ``key_id`` (active key if None)."""

    def sign(self, payload: bytes, key_id: str | None = None) -> Signature: ...

    def verify(self, payload: bytes, sig: Signature) -> bool:
        """Verify against whichever stored key matches ``sig.key_id``."""

    def rotate(self) -> str:
        """Generate a new key, make it active, return its key id."""

    def list_keys(self) -> list[str]:
        """All key ids known to the provider (active + retired)."""


@runtime_checkable
class PublicLog(Protocol):
    """An external append-only public log (Sigstore Rekor / CT operator).

    The anchor writes its Signed Tree Heads here so the anchor claim is
    independently visible to anyone, not just the anchor's own users.
    Operators can swap this backend without touching the anchor core.
    """

    def submit(self, payload: bytes, sig: Signature) -> dict:
        """Submit a signed payload (typically a Signed Tree Head).

        Returns a receipt dict with at minimum a ``location`` (URL or
        coordinate) and a ``log_index`` / ``uuid`` for independent lookup.
        """

    def verify(self, receipt: dict) -> bool:
        """Verify a receipt is genuinely in the public log."""

    def name(self) -> str:
        """Identifier of the log (e.g. ``rekor-public``, ``in-memory``)."""
