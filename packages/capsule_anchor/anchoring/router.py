"""FastAPI router for the anchoring subsystem (prefix ``/anchor``).

This subsystem IS the Action State **Transparency Service (TS)**: a SCITT-style
(RFC 9943) append-only transparency log over an RFC9162
(RFC6962) Certificate-Transparency Merkle tree, with an Ed25519 authority key.

Endpoints:
  POST /anchor/anchor                 -> countersign a root + append to log
  GET  /anchor/countersigned-root     -> fetch a stored CountersignedRoot
  GET  /anchor/transparency-log       -> append-only log feed (for monitors)
  POST /anchor/inclusion-proof        -> build a Merkle inclusion proof
  POST /anchor/verify-inclusion       -> verify an inclusion proof

  --- SCITT Transparency Service (TS) ---
  POST /transparency/register-statement -> register a SCITT Signed Statement
                                           (COSE_Sign1) and issue a COSE Receipt.
                                           Also the checkpoint WITNESS surface: a
                                           statement whose payload self-declares
                                           artifact_type: mmr-checkpoint is
                                           auto-recognized here (no new route) --
                                           monotonic-size + chain-linkage checked
                                           against the log's last witnessed
                                           checkpoint per log_id before co-signing;
                                           see AnchorerService._check_checkpoint_consistency.
  POST /v1/digest                       -> register a capsule_id digest, issue a Receipt
  GET  /v1/inclusion/{capsule_id}       -> read-only resolve: capsule_id -> inclusion
                                           proof + Receipt (200 present / 404 absent)

  --- CT monitor routes (Phase 4) ---
  GET  /anchor/sth                    -> current Signed Tree Head (RFC6962)
  GET  /anchor/inclusion-proof-ct     -> CT inclusion proof for a log entry
  GET  /anchor/consistency-proof      -> RFC6962 consistency proof between sizes
  GET  /anchor/authority-pubkey       -> authority public key (out-of-band pin)

One signing root: the authority Ed25519 key signs all STHs, COSE Receipts,
and countersigned roots.  The public key is exposed at ``/.well-known/did.json``
(no sign-oracle endpoint is provided).
"""

from __future__ import annotations

import base64
import collections
import hashlib
import threading
import time

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from capsule_anchor.contracts.types import (
    AnchorReceipt,
    CountersignedRoot,
    MerkleProof,
    TransparencyLogEntry,
)

from .service import (
    MAX_STATEMENT_BYTES,
    AnchorerService,
    CheckpointPayloadError,
    RollbackError,
)


class _SlidingWindowLimiter:
    """Thread-safe sliding-window rate limiter (no external deps).

    Tracks call timestamps in a deque per key (IP or "global"). A call is
    allowed when fewer than ``max_calls`` have been made in the last
    ``window_s`` seconds; rejected calls do NOT count against the window.

    Note: in a Cloud Run deployment with multiple instances, this limiter is
    per-instance. For cluster-wide enforcement use Cloud Armor / API Gateway.
    """

    def __init__(self, max_calls: int, window_s: float) -> None:
        self._max = max_calls
        self._window = window_s
        self._windows: dict[str, collections.deque] = {}
        self._lock = threading.Lock()

    def is_allowed(self, key: str = "global") -> bool:
        now = time.monotonic()
        with self._lock:
            dq = self._windows.setdefault(key, collections.deque())
            cutoff = now - self._window
            while dq and dq[0] < cutoff:
                dq.popleft()
            if len(dq) >= self._max:
                return False
            dq.append(now)
            return True


# 300 POST submissions per minute globally (5/s average).
# Digest-only endpoint is the primary surface; register-statement shares the budget.
_POST_LIMITER = _SlidingWindowLimiter(max_calls=300, window_s=60.0)

# Shared anchorer; replaced by configure_service() in the app factory.
_SERVICE = AnchorerService()


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


class CheckpointWitnessInfo(BaseModel):
    """Witness outcome for a submitted ``mmr-checkpoint`` statement.

    ``status`` is ``"first-seen"`` (unknown ``log_id`` -- nothing to be
    consistent with; no continuity is implied), ``"witnessed"`` (extends the
    last checkpoint we saw for this ``log_id``), or ``"already-registered"``
    (idempotent resubmission of a previously-accepted checkpoint).
    """

    log_id: str
    key_id: str
    mmr_root: str
    mmr_size: int
    prev_size: int
    timestamp: str
    status: str


class RegisterStatementResponse(BaseModel):
    """COSE Receipt issued by the Transparency Service for a Signed Statement.

    ``receipt_b64`` is the base64 of the COSE Receipt (COSE_Sign1, CBOR tag 18)
    over the RFC9162 CT log. ``entry_hash`` is the CT-log entry hash;
    ``entry_hash_scheme`` signals how it was derived: ``"sig_structure"``
    (``SHA256`` of the RFC9052 Sig_structure -- malleability-immune, the
    default for a parseable COSE_Sign1 with an embedded payload) or
    ``"legacy"`` (``SHA256`` of the raw submitted bytes -- unchanged behavior
    for non-COSE_Sign1 input, e.g. the ``/v1/digest`` surface, and for any
    statement matched via the entry_hash migration's dual-lookup window). See
    the README's Entry identifier derivation section.

    ``checkpoint_witness`` is populated only when the statement self-declared
    ``artifact_type: mmr-checkpoint``; ``None`` for every other statement.
    """

    receipt_b64: str
    entry_hash: str
    entry_hash_scheme: str
    leaf_index: int
    tree_size: int
    checkpoint_witness: CheckpointWitnessInfo | None = None


class InclusionResolveResponse(BaseModel):
    """Read-only resolve of a ``capsule_id`` to its CT-log inclusion evidence.

    Returned by ``GET /v1/inclusion/{capsule_id}``. ``entry_hash`` is
    ``SHA256(bytes.fromhex(capsule_id)).hex()`` — the CT-log entry hash whose
    RFC6962 leaf is ``SHA256(0x00 || entry_hash_bytes)``. The fields let a
    relying party verify offline: ``verify_receipt(receipt, leaf_entry_hex=
    entry_hash, log_public_key_pem=…)`` reconstructs ``root_hash`` and checks
    the authority signature, and the ``audit_path`` folds to the same root.
    """

    capsule_id: str
    entry_hash: str
    leaf_index: int
    tree_size: int
    leaf_hash: str
    audit_path: list[str]
    root_hash: str
    receipt_b64: str


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

    from .service import ConsistencyProof, InclusionProof, SignedTreeHead

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
        ``key_id`` (first 16 hex chars of ``sha256(pubkey)`` -- the SAME
        derivation used for ``Signature.key_id`` on every STH/receipt, so this
        value always matches the key_id a relying party sees on a signature).
        The monitor provisions this out-of-band and uses it to independently
        verify every STH signature -- this is what decouples the monitor from
        trusting the authority's own claims.
        """
        svc = get_service()
        raw: bytes = svc.authority_pubkey()
        pubkey_hex = raw.hex()
        return {"pubkey_hex": pubkey_hex, "key_id": svc.attestor.key_id}

    # --- SCITT Transparency Service (TS) ------------------------------------
    # Mounted at the top level (``/transparency``), distinct from the ``/anchor``
    # operator surface, but backed by the SAME CT log + authority key. The parent
    # router below carries no prefix so this lands at ``/transparency/...``.
    ts = APIRouter(prefix="/transparency", tags=["transparency-service"])

    @ts.post("/register-statement", response_model=RegisterStatementResponse)
    def register_statement(
        req: RegisterStatementRequest, request: Request
    ) -> RegisterStatementResponse:
        """SCITT registration API: register a Signed Statement, issue a COSE Receipt.

        Accepts a SCITT Signed Statement (a COSE_Sign1 CBOR blob) as base64 in
        ``signed_statement_b64``. The Transparency Service computes the CT-log
        entry hash (see ``RegisterStatementResponse.entry_hash_scheme``), appends
        it to the RFC9162 (RFC6962) CT log, and returns a COSE Receipt
        (COSE_Sign1, CBOR tag 18) carrying an RFC6962 inclusion proof to the
        current signed CT root.

        Idempotent: submitting the same signing act twice (including a
        signature-malleated twin) returns the original receipt.

        A statement whose payload self-declares ``artifact_type: mmr-checkpoint``
        additionally goes through the checkpoint witness surface: 400 if the
        checkpoint payload is malformed, 409 if it doesn't extend the log's last
        witnessed checkpoint for its ``log_id`` (rollback/fork -- never co-signed).
        """
        if not _POST_LIMITER.is_allowed():
            raise HTTPException(status_code=429, detail="rate limit exceeded — try again later")
        try:
            statement_bytes = base64.b64decode(req.signed_statement_b64, validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise HTTPException(
                status_code=400, detail=f"signed_statement_b64 is not valid base64: {exc}"
            ) from exc
        if not statement_bytes:
            raise HTTPException(status_code=400, detail="empty signed statement")
        if len(statement_bytes) > MAX_STATEMENT_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"statement too large ({len(statement_bytes)} bytes; max {MAX_STATEMENT_BYTES})",
            )

        svc = get_service()
        try:
            result = svc.register_signed_statement_full(statement_bytes)
        except CheckpointPayloadError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except RollbackError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return RegisterStatementResponse(
            receipt_b64=base64.b64encode(result.receipt).decode("ascii"),
            entry_hash=result.entry_hash,
            entry_hash_scheme=result.entry_hash_scheme,
            leaf_index=result.leaf_index,
            tree_size=result.tree_size,
            checkpoint_witness=(
                CheckpointWitnessInfo(**result.checkpoint_witness)
                if result.checkpoint_witness is not None
                else None
            ),
        )

    # --- Simple digest surface (/v1/digest) ------------------------------------
    # The capsule-emit default endpoint: POST {"capsule_id": "<64-hex>"}.
    # Derives statement_bytes = bytes.fromhex(capsule_id) — deterministic, so
    # the offline verifier can recompute the CT leaf from the capsule_id alone —
    # then registers through the identical SCITT CT-log path. Same receipt shape.
    v1 = APIRouter(prefix="/v1", tags=["digest"])

    @v1.post("/digest", response_model=RegisterStatementResponse)
    def digest(req: DigestRequest, request: Request) -> RegisterStatementResponse:
        """Register a capsule digest and receive an RFC9162 COSE Receipt.

        Accepts a 64-hex SHA-256 capsule_id. The service converts it to 32 raw
        bytes and registers them through the same SCITT CT-log path used by
        ``/transparency/register-statement``, issuing an identical COSE Receipt.

        Idempotent: submitting the same capsule_id twice returns the original receipt.
        Offline verification: ``entry_hash = SHA256(bytes.fromhex(capsule_id))``
        — that is the CT log entry hash the inclusion proof covers.
        """
        if not _POST_LIMITER.is_allowed():
            raise HTTPException(status_code=429, detail="rate limit exceeded — try again later")
        cid = req.capsule_id.lower().strip()
        if len(cid) != 64 or not all(c in "0123456789abcdef" for c in cid):
            raise HTTPException(
                status_code=400,
                detail="capsule_id must be a 64-character hex string (32-byte SHA-256 digest)",
            )
        statement_bytes = bytes.fromhex(cid)
        svc = get_service()
        result = svc.register_signed_statement_full(statement_bytes)
        return RegisterStatementResponse(
            receipt_b64=base64.b64encode(result.receipt).decode("ascii"),
            entry_hash=result.entry_hash,
            entry_hash_scheme=result.entry_hash_scheme,
            leaf_index=result.leaf_index,
            tree_size=result.tree_size,
        )

    @v1.get("/inclusion/{capsule_id}", response_model=InclusionResolveResponse)
    def inclusion(capsule_id: str) -> InclusionResolveResponse:
        """Read-only resolve: ``capsule_id`` -> CT inclusion proof + COSE Receipt.

        Derives ``entry_hash = SHA256(bytes.fromhex(capsule_id))`` and looks it
        up in the log. Returns **200** with the inclusion evidence if the
        capsule's statement is registered, **404** if it is absent (the
        negative-case DENY), **400** on a malformed capsule_id. This is a pure
        read — it NEVER registers the capsule_id (contrast ``POST /v1/digest``).
        """
        cid = capsule_id.lower().strip()
        if len(cid) != 64 or not all(c in "0123456789abcdef" for c in cid):
            raise HTTPException(
                status_code=400,
                detail="capsule_id must be a 64-character hex string (32-byte SHA-256 digest)",
            )
        entry_hash = hashlib.sha256(bytes.fromhex(cid)).hexdigest()
        svc = get_service()
        cached = svc.get_registered_statement(entry_hash)
        if cached is None:
            raise HTTPException(
                status_code=404,
                detail="capsule_id not found in transparency log",
            )
        receipt_bytes, leaf_index, tree_size = cached
        proof = svc.inclusion_proof_ct(leaf_index, tree_size)
        return InclusionResolveResponse(
            capsule_id=cid,
            entry_hash=entry_hash,
            leaf_index=leaf_index,
            tree_size=tree_size,
            leaf_hash=proof.leaf_hash,
            audit_path=proof.audit_path,
            root_hash=proof.root_hash,
            receipt_b64=base64.b64encode(receipt_bytes).decode("ascii"),
        )

    parent = APIRouter()
    parent.include_router(router)
    parent.include_router(ts)
    parent.include_router(v1)
    return parent
