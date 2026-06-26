"""FastAPI router for the anchoring subsystem (prefix ``/anchor``).

This subsystem IS the Action State **Transparency Service (TS)**: a SCITT-style
(draft-ietf-scitt-architecture) append-only transparency log over an RFC9162
(RFC6962) Certificate-Transparency Merkle tree, with an Ed25519 authority key.

Endpoints:
  POST /anchor/anchor                 -> countersign a root + append to log
  GET  /anchor/countersigned-root     -> fetch a stored CountersignedRoot
  GET  /anchor/transparency-log       -> append-only log feed (for monitors)
  POST /anchor/inclusion-proof        -> build a Merkle inclusion proof
  POST /anchor/verify-inclusion       -> verify an inclusion proof

  --- SCITT Transparency Service (TS) ---
  POST /transparency/register-statement -> register a SCITT Signed Statement
                                           (COSE_Sign1) and issue a COSE Receipt

  --- CT monitor routes (Phase 4) ---
  GET  /anchor/sth                    -> current Signed Tree Head (RFC6962)
  GET  /anchor/inclusion-proof-ct     -> CT inclusion proof for a log entry
  GET  /anchor/consistency-proof      -> RFC6962 consistency proof between sizes
  GET  /anchor/authority-pubkey       -> authority public key (out-of-band pin)

The anchoring service reuses the attestation subsystem's shared authority
instance, so countersignatures verify against the key published at
``/attest/pubkey`` -- one signing root across the authority.
"""

from __future__ import annotations

import base64

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from capsule_anchor.attestation.router import get_service as get_attestor
from capsule_anchor.contracts.types import (
    AnchorReceipt,
    CountersignedRoot,
    MerkleProof,
    TransparencyLogEntry,
)

from .service import AnchorerService

# Shared anchorer, bound to the shared authority attestor.
_SERVICE = AnchorerService(attestor=get_attestor())


def get_service() -> AnchorerService:
    return _SERVICE


def configure_service(service: AnchorerService) -> None:
    """Install a durable-backed anchorer (called by the app factory from config)."""
    global _SERVICE
    _SERVICE = service


class AnchorRequest(BaseModel):
    tenant_id: str
    root_hash: str
    seq_from: int
    seq_to: int
    # Phase 3 (tail-add): optional capsule binding so the `gopher verify` CLI
    # can ask "where in the public log was capsule <id> anchored?". Anchored
    # values are stored on the TransparencyLogEntry's payload alongside the
    # countersigned root; existing callers may omit it (default None).
    capsule_id: str | None = None


class InclusionProofRequest(BaseModel):
    leaf_hashes: list[str]
    index: int


class VerifyInclusionRequest(BaseModel):
    proof: MerkleProof
    anchored_root_hash: str | None = None


class RegisterStatementRequest(BaseModel):
    """SCITT Signed Statement to register with the Transparency Service.

    ``signed_statement_b64`` is the base64 of a COSE_Sign1 (CBOR) Signed
    Statement. (We accept base64-in-JSON rather than a raw ``application/cose``
    body so the same convention round-trips request AND response.)
    """

    signed_statement_b64: str


class DigestRequest(BaseModel):
    """Simple digest registration — the capsule-emit default surface.

    ``capsule_id`` is a 64-character lowercase hex string representing a
    32-byte SHA-256 digest. The service derives deterministic statement bytes
    (``bytes.fromhex(capsule_id)``), registers them through the SAME CT log
    code path as ``/transparency/register-statement``, and returns the same
    COSE Receipt shape so offline verify works identically.
    """

    capsule_id: str


class RegisterStatementResponse(BaseModel):
    """COSE Receipt issued by the Transparency Service for a Signed Statement.

    ``receipt_b64`` is the base64 of the COSE Receipt (COSE_Sign1, CBOR tag 18)
    over the RFC9162 CT log. ``entry_hash`` is the CT-log entry hash,
    ``SHA256(statement_bytes).hex()`` -- the interop contract: verifiers
    recompute the Merkle leaf as ``SHA256(0x00 || SHA256(statement_bytes))``.
    """

    receipt_b64: str
    entry_hash: str
    leaf_index: int
    tree_size: int


def get_router() -> APIRouter:
    router = APIRouter(prefix="/anchor", tags=["anchoring"])

    @router.post("/anchor", response_model=AnchorReceipt)
    def anchor(req: AnchorRequest) -> AnchorReceipt:
        return get_service().anchor(
            req.tenant_id,
            req.root_hash,
            (req.seq_from, req.seq_to),
            capsule_id=req.capsule_id,
        )

    @router.get("/countersigned-root", response_model=CountersignedRoot)
    def countersigned_root(tenant_id: str, root_hash: str) -> CountersignedRoot:
        cs = get_service().get_countersigned_root(tenant_id, root_hash)
        if cs is None:
            raise HTTPException(status_code=404, detail="no countersigned root")
        return cs

    @router.get("/transparency-log", response_model=list[TransparencyLogEntry])
    def transparency_log(
        after_index: int = 0, capsule_id: str | None = None
    ) -> list[TransparencyLogEntry]:
        """Append-only log feed (for monitors).

        When ``capsule_id`` is supplied, return only entries bound to that
        capsule (Phase 3 — used by the ``gopher verify`` CLI to surface
        "this capsule was anchored at <timestamp> in batch <N>"). The
        ``after_index`` filter still applies on top.
        """
        svc = get_service()
        if capsule_id is not None:
            entries = svc.transparency_log_for_capsule(capsule_id)
            return [e for e in entries if e.log_index >= after_index]
        return svc.transparency_log(after_index)

    @router.post("/inclusion-proof", response_model=MerkleProof)
    def inclusion_proof(req: InclusionProofRequest) -> MerkleProof:
        try:
            return get_service().inclusion_proof(req.leaf_hashes, req.index)
        except IndexError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @router.post("/verify-inclusion")
    def verify_inclusion(req: VerifyInclusionRequest) -> dict[str, bool]:
        ok = get_service().verify_inclusion(req.proof, req.anchored_root_hash)
        return {"valid": ok}

    # --- CT monitor routes (Phase 4) ----------------------------------------

    from .service import SignedTreeHead, InclusionProof, ConsistencyProof

    @router.get("/sth", response_model=SignedTreeHead)
    def sth() -> SignedTreeHead:
        """Current RFC6962 Signed Tree Head.

        Returns 503 when the log is empty (no STH can be produced yet).
        """
        svc = get_service()
        s = svc.get_sth()
        if s.tree_size == 0:
            raise HTTPException(status_code=503, detail="log is empty; no STH available yet")
        return s

    @router.get("/inclusion-proof-ct", response_model=InclusionProof)
    def inclusion_proof_ct(leaf_index: int, tree_size: int | None = None) -> InclusionProof:
        """RFC6962 inclusion proof for log entry ``leaf_index``.

        ``tree_size`` defaults to the current log size. Returns 400 on invalid
        params, 404 when out of range.
        """
        if leaf_index < 0:
            raise HTTPException(status_code=400, detail="leaf_index must be >= 0")
        if tree_size is not None and tree_size <= 0:
            raise HTTPException(status_code=400, detail="tree_size must be > 0")
        svc = get_service()
        try:
            return svc.inclusion_proof_ct(leaf_index, tree_size)
        except IndexError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @router.get("/consistency-proof", response_model=ConsistencyProof)
    def consistency_proof(old_size: int, new_size: int) -> ConsistencyProof:
        """RFC6962 consistency proof between two tree sizes.

        Returns 400 when sizes are invalid (negative, old > new) or out of
        range for the current log.
        """
        if old_size < 0 or new_size < 0:
            raise HTTPException(status_code=400, detail="sizes must be >= 0")
        if old_size > new_size:
            raise HTTPException(status_code=400, detail="old_size must be <= new_size")
        svc = get_service()
        try:
            return svc.consistency_proof(old_size, new_size)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @router.get("/authority-pubkey")
    def authority_pubkey() -> dict[str, str]:
        """Authority public key for out-of-band monitor pinning.

        Returns ``pubkey_hex`` (raw 32-byte Ed25519 key as lowercase hex) and
        ``key_id`` (first 16 hex chars, a stable short handle). The monitor
        provisions this out-of-band and uses it to independently verify every
        STH signature -- this is what decouples the monitor from trusting the
        authority's own claims.
        """
        svc = get_service()
        raw: bytes = svc.authority_pubkey()
        pubkey_hex = raw.hex()
        return {"pubkey_hex": pubkey_hex, "key_id": pubkey_hex[:16]}

    # --- SCITT Transparency Service (TS) ------------------------------------
    # Mounted at the top level (``/transparency``), distinct from the ``/anchor``
    # operator surface, but backed by the SAME CT log + authority key. The parent
    # router below carries no prefix so this lands at ``/transparency/...``.
    ts = APIRouter(prefix="/transparency", tags=["transparency-service"])

    @ts.post("/register-statement", response_model=RegisterStatementResponse)
    def register_statement(req: RegisterStatementRequest) -> RegisterStatementResponse:
        """SCITT registration API: register a Signed Statement, issue a COSE Receipt.

        Accepts a SCITT Signed Statement (a COSE_Sign1 CBOR blob) as base64 in
        ``signed_statement_b64``. The Transparency Service computes the CT-log
        entry hash ``SHA256(statement_bytes).hex()``, appends it to the RFC9162
        (RFC6962) CT log, and returns a COSE Receipt (COSE_Sign1, CBOR tag 18)
        carrying an RFC6962 inclusion proof to the current signed CT root.
        """
        try:
            statement_bytes = base64.b64decode(req.signed_statement_b64, validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise HTTPException(
                status_code=400, detail=f"signed_statement_b64 is not valid base64: {exc}"
            ) from exc
        if not statement_bytes:
            raise HTTPException(status_code=400, detail="empty signed statement")

        svc = get_service()
        receipt, entry_hash, leaf_index, tree_size = svc.register_signed_statement(
            statement_bytes
        )
        return RegisterStatementResponse(
            receipt_b64=base64.b64encode(receipt).decode("ascii"),
            entry_hash=entry_hash,
            leaf_index=leaf_index,
            tree_size=tree_size,
        )

    # --- Simple digest surface (/v1/digest) ------------------------------------
    # The capsule-emit default endpoint: POST {"capsule_id": "<64-hex>"}.
    # Derives statement_bytes = bytes.fromhex(capsule_id) — deterministic, so
    # the offline verifier can recompute the CT leaf from the capsule_id alone —
    # then registers through the identical SCITT CT-log path. Same receipt shape.
    v1 = APIRouter(prefix="/v1", tags=["digest"])

    @v1.post("/digest", response_model=RegisterStatementResponse)
    def digest(req: DigestRequest) -> RegisterStatementResponse:
        """Register a capsule digest and receive an RFC9162 COSE Receipt.

        Accepts a 64-hex SHA-256 capsule_id. The service converts it to 32 raw
        bytes and registers them through the same SCITT CT-log path used by
        ``/transparency/register-statement``, issuing an identical COSE Receipt.

        Offline verification: ``entry_hash = SHA256(bytes.fromhex(capsule_id))``
        — that is the CT log entry hash the inclusion proof covers.
        """
        cid = req.capsule_id.lower().strip()
        if len(cid) != 64 or not all(c in "0123456789abcdef" for c in cid):
            raise HTTPException(
                status_code=400,
                detail="capsule_id must be a 64-character hex string (32-byte SHA-256 digest)",
            )
        statement_bytes = bytes.fromhex(cid)
        svc = get_service()
        receipt, entry_hash, leaf_index, tree_size = svc.register_signed_statement(
            statement_bytes
        )
        return RegisterStatementResponse(
            receipt_b64=base64.b64encode(receipt).decode("ascii"),
            entry_hash=entry_hash,
            leaf_index=leaf_index,
            tree_size=tree_size,
        )

    parent = APIRouter()
    parent.include_router(router)
    parent.include_router(ts)
    parent.include_router(v1)
    return parent
