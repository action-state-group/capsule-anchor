"""Internal service wiring for the attestation subsystem.

The ``AttestorService`` is the single signing root for all authority
signatures (STH, COSE Receipts, countersigned roots).  No HTTP routes
are exposed here: a public sign-arbitrary-bytes oracle over the same key
would allow forgery of log artifacts.  The authority public key is already
available via ``GET /.well-known/did.json``.
"""

from __future__ import annotations

from .service import AttestorService

# One process-wide authority instance shared with the anchoring subsystem.
# Defaults to an in-process generated key (dev/test); the app factory installs
# a stable, configured signing key via ``configure_service``.
_SERVICE = AttestorService()


def get_service() -> AttestorService:
    """Return the shared authority attestor (reused by anchoring)."""
    return _SERVICE


def configure_service(service: AttestorService) -> None:
    """Install the authority attestor backed by the configured signing key."""
    global _SERVICE
    _SERVICE = service
