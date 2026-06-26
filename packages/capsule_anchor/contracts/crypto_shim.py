"""Pure-Python reference implementation of ``CryptoCore``.

This is the dependency-decoupler: subsystems and tests use this so they don't
block on the Rust build. The Rust crate ``crates/as-crypto-core`` is the
production implementation and MUST produce byte-identical hashes/Merkle roots
(the OSS hash-chain compatibility depends on it). Differential tests in
``tests/test_crypto_parity.py`` pin shim == Rust.

Uses ``cryptography`` for Ed25519; ``hashlib`` for everything else.
"""

from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .types import Commitment, MerkleProof, Signature


def _now() -> datetime:
    return datetime.now(timezone.utc)


class ShimCryptoCore:
    """Reference ``CryptoCore``. Not for production signing (no HSM)."""

    # --- signing ---
    def generate_keypair(self) -> tuple[bytes, bytes]:
        sk = Ed25519PrivateKey.generate()
        priv = sk.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        pub = sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return priv, pub

    def sign(self, private_key: bytes, payload: bytes) -> Signature:
        sk = Ed25519PrivateKey.from_private_bytes(private_key)
        sig = sk.sign(payload)
        pub = sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return Signature(
            signature=sig.hex(),
            key_id=hashlib.sha256(pub).hexdigest()[:16],
            alg="ed25519",
            created_at=_now(),
        )

    def verify(self, public_key: bytes, payload: bytes, sig: Signature) -> bool:
        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(
                bytes.fromhex(sig.signature), payload
            )
            return True
        except Exception:
            return False

    # --- hashing / chain ---
    def sha256(self, payload: bytes) -> str:
        return hashlib.sha256(payload).hexdigest()

    def merkle_root(self, leaf_hashes: list[str]) -> str:
        # Odd node promoted unchanged; empty list → "". Matches downstream engine semantics.
        if not leaf_hashes:
            return ""
        level = list(leaf_hashes)
        while len(level) > 1:
            nxt: list[str] = []
            for i in range(0, len(level), 2):
                if i + 1 < len(level):
                    combined = (level[i] + level[i + 1]).encode()
                    nxt.append(hashlib.sha256(combined).hexdigest())
                else:
                    nxt.append(level[i])  # odd node promoted unchanged
            level = nxt
        return level[0]

    def merkle_proof(self, leaf_hashes: list[str], index: int) -> MerkleProof:
        if not leaf_hashes or not (0 <= index < len(leaf_hashes)):
            raise IndexError("leaf index out of range")
        path: list[tuple[str, bool]] = []
        level = list(leaf_hashes)
        idx = index
        while len(level) > 1:
            nxt: list[str] = []
            for i in range(0, len(level), 2):
                if i + 1 < len(level):
                    combined = (level[i] + level[i + 1]).encode()
                    parent = hashlib.sha256(combined).hexdigest()
                    if i == idx or i + 1 == idx:
                        sib_right = (idx == i)  # sibling on the right
                        sib = level[i + 1] if sib_right else level[i]
                        path.append((sib, sib_right))
                        idx = len(nxt)
                    nxt.append(parent)
                else:
                    if i == idx:
                        idx = len(nxt)
                    nxt.append(level[i])
            level = nxt
        return MerkleProof(
            leaf_hash=leaf_hashes[index], root_hash=level[0], path=path
        )

    def verify_merkle_proof(self, proof: MerkleProof) -> bool:
        acc = proof.leaf_hash
        for sib, sib_right in proof.path:
            combined = (acc + sib) if sib_right else (sib + acc)
            acc = hashlib.sha256(combined.encode()).hexdigest()
        return acc == proof.root_hash

    def verify_chain(self, commitments: list[Commitment]) -> bool:
        prev: str | None = None
        for c in sorted(commitments, key=lambda x: x.seq):
            if c.prev_hash != prev:
                return False
            prev = c.entry_hash
        return True

    # --- commitments ---
    def commit(self, plaintext: bytes, salt: bytes) -> str:
        return hashlib.sha256(salt + b"\x00" + plaintext).hexdigest()

    def verify_commitment(self, plaintext: bytes, salt: bytes, commit: str) -> bool:
        return hmac.compare_digest(self.commit(plaintext, salt), commit)


def default_crypto() -> ShimCryptoCore:
    """Factory used across subsystems until the Rust core is wired in."""
    return ShimCryptoCore()
