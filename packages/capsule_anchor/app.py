"""capsule-anchor FastAPI app — neutral public anchor service."""
from __future__ import annotations

import os

from fastapi import FastAPI


def create_app() -> FastAPI:
    app = FastAPI(
        title="Capsule Anchor",
        description=(
            "Neutral public SCITT Transparency Service. "
            "POST /transparency/register-statement: submit a SCITT Signed Statement "
            "(COSE_Sign1 bytes, base64), receive an RFC9162 COSE Receipt with an "
            "RFC6962 CT-log inclusion proof. Ed25519 authority key; append-only log."
        ),
        version="0.1.0",
    )

    from capsule_anchor.signing_key import StaticKeyProvider, load_signing_key
    from capsule_anchor.attestation.service import AttestorService
    from capsule_anchor.attestation.router import (
        configure_service as cfg_attest,
        get_router as attest_router,
    )
    from capsule_anchor.anchoring.service import AnchorerService
    from capsule_anchor.anchoring.router import (
        configure_service as cfg_anchor,
        get_router as anchor_router,
    )

    loaded = load_signing_key()
    provider = StaticKeyProvider(loaded)
    attestor = AttestorService(key_provider=provider)
    cfg_attest(attestor)
    cfg_anchor(AnchorerService(attestor=attestor))

    app.include_router(anchor_router())
    app.include_router(attest_router())

    @app.get("/health", tags=["meta"])
    @app.get("/healthz", tags=["meta"])
    @app.get("/livez", tags=["meta"])
    def health() -> dict:
        return {
            "ok": True,
            "signing_key_source": loaded.source,
            "signing_key_ephemeral": loaded.ephemeral,
        }

    return app


def main() -> None:
    """Console-script entry point (``capsule-anchor``)."""
    import uvicorn

    host = os.environ.get("CAPSULE_ANCHOR_HOST", "0.0.0.0")
    port = int(os.environ.get("CAPSULE_ANCHOR_PORT", "8000"))
    uvicorn.run("capsule_anchor.app:create_app", host=host, port=port, factory=True)


if __name__ == "__main__":
    main()
