"""Anchoring subsystem: countersign tenant roots + append-only transparency log.

Anchorer subsystem — countersigns tenant Merkle
roots with the AS authority key, writes them to a CT/Rekor-style append-only
public transparency log (making the authority auditable in turn), and provides
Merkle inclusion proofs so a relying party can prove a leaf is under an
anchored root.
"""

from __future__ import annotations

from . import ct
from .router import get_router, get_service
from .service import (
    AnchorerService,
    ConsistencyProof,
    InclusionProof,
    SignedTreeHead,
    countersign_payload,
    ct_leaf_hash,
    ct_leaf_payload,
    sth_payload,
    tree_head_payload,
)

__all__ = [
    "AnchorerService",
    "SignedTreeHead",
    "InclusionProof",
    "ConsistencyProof",
    "countersign_payload",
    "tree_head_payload",
    "ct_leaf_payload",
    "ct_leaf_hash",
    "sth_payload",
    "ct",
    "get_router",
    "get_service",
]
