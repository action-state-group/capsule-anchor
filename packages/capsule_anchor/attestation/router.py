"""FastAPI router for the attestation subsystem (prefix ``/attest``).

Exposes the authority public key and a verify endpoint. The ``attest`` endpoint
signs a caller-supplied payload -- in production this would be authn-gated
(only the anchoring/identity subsystems sign), but for the scaffold it lets a
relying party round-trip a signature against the published authority key.
"""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from capsule_anchor.contracts.types import Signature

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


class AttestRequest(BaseModel):
    payload_hex: str


class VerifyRequest(BaseModel):
    payload_hex: str
    signature: Signature


class PubkeyResponse(BaseModel):
    public_key_hex: str
    key_id: str
    alg: str = "ed25519"


def get_router() -> APIRouter:
    router = APIRouter(prefix="/attest", tags=["attestation"])

    @router.get("/pubkey", response_model=PubkeyResponse)
    def pubkey() -> PubkeyResponse:
        svc = get_service()
        return PubkeyResponse(
            public_key_hex=svc.authority_pubkey().hex(),
            key_id=svc.key_id,
        )

    @router.post("/sign", response_model=Signature)
    def sign(req: AttestRequest) -> Signature:
        return get_service().attest(bytes.fromhex(req.payload_hex))

    @router.post("/verify")
    def verify(req: VerifyRequest) -> dict[str, bool]:
        ok = get_service().verify(bytes.fromhex(req.payload_hex), req.signature)
        return {"valid": ok}

    return router
