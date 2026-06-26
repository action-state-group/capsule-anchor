"""Attestation subsystem: Ed25519 signing under the AS authority key.

Attestor subsystem — the authority keypair lives
here and is the single signing root the anchoring subsystem reuses to
countersign tenant Merkle roots and to sign transparency-log tree heads.
"""

from __future__ import annotations

from .router import get_router, get_service
from .service import AttestorService

__all__ = ["AttestorService", "get_router", "get_service"]
