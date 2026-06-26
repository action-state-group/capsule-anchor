"""Shared data models for the capsule-anchor transparency service.

These types are the integration contract between the attestation, anchoring,
and public-log subsystems. They define only the crypto primitives and log
structures that the public anchor service needs — no tenant, billing, or
identity-management types are included.

Trust-model invariant: the anchor stores and reasons over digests and
commitments, never plaintext. Any field that could carry content is typed as
opaque bytes or a hash so a reviewer can see at a glance that the service is
blind to content.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Crypto primitives
# ---------------------------------------------------------------------------


class Signature(BaseModel):
    """An Ed25519 signature produced by the authority key."""

    signature: str  # hex
    key_id: str
    alg: str = "ed25519"
    created_at: datetime


class MerkleProof(BaseModel):
    """Inclusion proof: leaf is in the tree with this root."""

    leaf_hash: str
    root_hash: str
    # ordered sibling hashes from leaf to root; bool = sibling-is-right
    path: list[tuple[str, bool]]


class Commitment(BaseModel):
    """Hiding+binding commitment to a single ledger entry.

    The anchor sees this, never the entry. ``entry_hash`` and ``prev_hash``
    reproduce the hash-chain so integrity can be verified blind.
    """

    stable_id: str  # opaque tenant-chosen id (not plaintext)
    entry_hash: str  # SHA-256 of the entry
    prev_hash: str | None  # chain link (None at genesis)
    entry_commit: str  # commitment (hash w/ salt) binding full plaintext
    field_commits: dict[str, str] = Field(default_factory=dict)
    seq: int  # append index within the tenant chain


# ---------------------------------------------------------------------------
# Anchoring & attestation
# ---------------------------------------------------------------------------


class AnchorReceipt(BaseModel):
    """Receipt issued by the anchor service for a countersigned tenant root.

    The tenant computes a periodic Merkle root over their (encrypted) chain;
    the authority countersigns it and writes it to a public transparency log.
    """

    root_hash: str
    tenant_id: str
    anchored_at: datetime
    location: str  # transparency-log URL / coordinate
    log_index: int | None = None  # position in the public log
    countersignature: Signature  # signed by authority key
    proof: dict = Field(default_factory=dict)  # backend-specific inclusion proof
    # Optional RFC 3161 timestamp-authority signature over ``root_hash``.
    # Opt-in via ``CAPSULE_ANCHOR_TSA_ENABLED=1``; default None.
    tsa_signature: bytes | None = None
    tsa_token_b64: str | None = None


class CountersignedRoot(BaseModel):
    """A tenant Merkle root the authority has attested at time T.

    Third parties verify the countersignature against the authority public key.
    """

    tenant_id: str
    root_hash: str
    seq_range: tuple[int, int]  # [from, to] entries covered
    attested_at: datetime
    countersignature: Signature


class TransparencyLogEntry(BaseModel):
    """An append-only transparency-log record (CT / Sigstore-Rekor style).

    The public log is what makes the anchor independently auditable:
    a tamper-evident append-only structure that any monitor can watch.
    """

    log_index: int
    logged_at: datetime
    kind: str  # "countersigned_root" | "cert_issued" | "cert_revoked" | "scitt_statement"
    payload_hash: str  # hash of the logged object (no tenant plaintext)
    log_signature: Signature  # the log's own signed tree head linkage
    prev_log_hash: str | None
