"""capsule-anchor FastAPI app — neutral public anchor service."""
from __future__ import annotations

import base64
import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

_ROOT_HTML = Path(__file__).parent / "static" / "root.html"


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

    # Durable storage: read CAPSULE_ANCHOR_DB_PATH from env.
    # When set, the append-only CT log and dedup cache survive process restarts.
    # When unset (dev/test default), an in-memory store is used and state is lost
    # on restart. For production Cloud Run set this to a Cloud Filestore mount
    # path (e.g. /data/anchor.db); for Cloud SQL use CAPSULE_ANCHOR_DB_URL +
    # the [postgres] extra instead.
    db_path = os.environ.get("CAPSULE_ANCHOR_DB_PATH") or None
    cfg_anchor(AnchorerService(attestor=attestor, db_path=db_path))

    app.include_router(anchor_router())
    app.include_router(attest_router())

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    def root() -> HTMLResponse:
        return HTMLResponse(_ROOT_HTML.read_text(encoding="utf-8"))

    @app.get("/health", tags=["meta"])
    @app.get("/healthz", tags=["meta"])
    @app.get("/livez", tags=["meta"])
    def health() -> dict:
        from capsule_anchor.anchoring.router import get_service
        svc = get_service()
        pubkey_hex = svc.authority_pubkey().hex()
        tree_size = svc._store.size()
        result: dict = {
            "ok": True,
            "signing_key_source": loaded.source,
            "signing_key_ephemeral": loaded.ephemeral,
            "key_id": pubkey_hex[:16],
            "tree_size": tree_size,
            "storage": "sqlite" if db_path else "memory",
        }
        if tree_size > 0:
            try:
                sth = svc.get_sth()
                result["latest_sth_timestamp"] = sth.timestamp.isoformat()
                result["latest_root_hash"] = sth.root_hash
            except Exception:
                pass
        return result

    @app.get("/.well-known/did.json", tags=["meta"])
    def did_document() -> dict:
        """DID document for the authority's Ed25519 signing key (did:web).

        Allows verifiers and witnesses to resolve the authority's key identity
        out-of-band. The ``x`` field is the raw 32-byte Ed25519 public key
        encoded as base64url (no padding), per RFC 8037 / JWK OKP.
        """
        from capsule_anchor.anchoring.router import get_service
        pubkey_bytes = get_service().authority_pubkey()
        pubkey_b64url = base64.urlsafe_b64encode(pubkey_bytes).rstrip(b"=").decode()
        key_id = pubkey_bytes.hex()[:16]
        did = "did:web:anchor.agentactioncapsule.org"
        return {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": did,
            "verificationMethod": [
                {
                    "id": f"{did}#{key_id}",
                    "type": "JsonWebKey2020",
                    "controller": did,
                    "publicKeyJwk": {
                        "kty": "OKP",
                        "crv": "Ed25519",
                        "x": pubkey_b64url,
                    },
                }
            ],
            "assertionMethod": [f"{did}#{key_id}"],
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
