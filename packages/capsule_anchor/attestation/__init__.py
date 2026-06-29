"""Attestation subsystem: Ed25519 signing under the authority key.

The authority keypair is the single signing root for STHs, COSE Receipts,
and countersigned roots.  No HTTP sign-oracle is exposed.
"""

from __future__ import annotations

from .router import get_service
from .service import AttestorService

__all__ = ["AttestorService", "get_service"]
