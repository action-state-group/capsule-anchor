# SPDX-License-Identifier: Apache-2.0
"""Independent COSE_Sign1 decode + verify for CLL checkpoints.

Mirrors ``capsule_emit.checkpoint.cose_wire``'s wire shape EXACTLY (same
content type, same claim-key names, same peak-list commitment encoding,
[cll-checkpoint-cose-wire]) -- but is reimplemented here from scratch on top
of ``scitt_cose`` alone. capsule-anchor never imports capsule-emit: the
witness must verify what a stranger's COSE bytes actually claim and sign,
not trust a co-deployed library's own opinion of them (same boundary rule
``anchoring/service.py``'s hand-rolled COSE Receipt assembly already follows
for the RECEIPT side of this route).

``POST /checkpoints`` (the single-host witness ruling, 2026-08-27) uses
:func:`parse_and_verify_checkpoint_cose` to turn a submitted COSE_Sign1
statement into the same 9-field dict shape the legacy JSON
``CheckpointRecord`` path already produced (``v, kind, log_id, mmr_size,
root, prev_size, prev_root, key_id, timestamp``) -- so
``AnchorerService.witness_checkpoint`` and its CT-log digest/idempotency
scheme (``_checkpoint_digest`` over that exact 9-field signing body) stay
completely unchanged; only how the checkpoint's fields are AUTHENTICATED and
extracted from the wire changes, from a JSON ``signature`` field to an
independently-verified COSE_Sign1 envelope.
"""
from __future__ import annotations

import hashlib

import cbor2

from .service import CheckpointSignatureError, NotACheckpointError

#: Must match capsule_emit.checkpoint.cose_wire.CLL_CHECKPOINT_CONTENT_TYPE
#: byte-for-byte -- this is the ONE wire shape both sides speak, not a
#: capsule-anchor-invented variant.
CLL_CHECKPOINT_CONTENT_TYPE = "application/cll-checkpoint+cbor"

#: Must match capsule_emit.checkpoint.cose_wire.WIRE_KIND.
WIRE_KIND = "cll-checkpoint"

#: COSE protected-header label for `kid` (RFC 9052 §3.1).
_HDR_KID = 4
#: COSE protected-header label for `content_type` (RFC 9052 §3.1).
_HDR_CONTENT_TYPE = 3

_DIGEST_LEN = 32


def _root_from_peaks(peak_hashes: list[bytes]) -> bytes:
    """Right-to-left pairwise fold, no domain-separator byte -- reimplements
    ``capsule_emit.checkpoint.core.root_from_peaks`` exactly (same fold
    order, same empty-MMR-is-32-zero-bytes convention) so a checkpoint's
    reconstructed ``root``/``prev_root`` match what the producer itself
    computed, without capsule-anchor importing capsule-emit to get there."""
    if not peak_hashes:
        return bytes(_DIGEST_LEN)
    hashes = list(peak_hashes)
    while len(hashes) > 1:
        right = hashes.pop()
        left = hashes.pop()
        hashes.append(hashlib.sha256(right + left).digest())
    return hashes[0]


def _decode_commitment(raw, *, what: str) -> list[bytes]:
    """Decode a ``commitment_object``-encoded bstr claim (canonical CBOR
    array of 32-byte peak hashes) back into the peak-hash list."""
    try:
        peaks = cbor2.loads(bytes(raw))
    except Exception as exc:  # noqa: BLE001 -- funnel every decode failure through one named error
        raise NotACheckpointError(f"{what} is not valid CBOR: {exc}") from exc
    if not isinstance(peaks, list) or not all(
        isinstance(p, (bytes, bytearray)) and len(p) == _DIGEST_LEN for p in peaks
    ):
        raise NotACheckpointError(f"{what} is not a CBOR array of 32-byte peak hashes")
    return [bytes(p) for p in peaks]


def _extract_protected_fields(cose_bytes: bytes) -> tuple[bytes | None, str | None]:
    """Structurally read ``kid`` and ``content_type`` out of the protected
    header WITHOUT verifying the signature -- needed before verification can
    even be attempted (the kid names which public key to check against), and
    ``content_type`` doubles as the checkpoint-only gate: any COSE_Sign1
    that isn't self-labelled a CLL checkpoint is refused here (NotACheckpointError,
    400) BEFORE a signature check ever runs, so a well-signed statement for a
    DIFFERENT purpose (e.g. a capsule producer envelope) is never mistaken
    for a bad-signature checkpoint (401).

    Uses ``scitt_cose.cose_sign1.strict_decode`` -- the same malleability-
    resistant decoder the verifying path itself uses -- so even this
    unauthenticated peek rejects a malformed/malleable envelope the same way
    the rest of the pipeline would.
    """
    from scitt_cose.cose_sign1 import CoseError, strict_decode

    try:
        outer = strict_decode(cose_bytes)
    except CoseError as exc:
        raise NotACheckpointError(f"malformed COSE_Sign1 message: {exc}") from exc
    value = outer.value
    if not isinstance(value, (list, tuple)) or len(value) != 4:
        raise NotACheckpointError("not a COSE_Sign1 message")
    protected_bstr = value[0]
    protected = cbor2.loads(bytes(protected_bstr)) if protected_bstr else {}
    if not isinstance(protected, dict):
        protected = {}
    kid = protected.get(_HDR_KID)
    kid = bytes(kid) if isinstance(kid, (bytes, bytearray)) else None
    content_type = protected.get(_HDR_CONTENT_TYPE)
    if isinstance(content_type, (bytes, bytearray)):
        content_type = bytes(content_type).decode("utf-8", errors="replace")
    return kid, content_type


def _ed25519_pubkey_pem(raw: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    key = Ed25519PublicKey.from_public_bytes(raw)
    return key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)


def parse_and_verify_checkpoint_cose(cose_bytes: bytes) -> dict:
    """Decode + independently verify a COSE-wire CLL checkpoint statement.

    Returns a dict shaped exactly like the legacy JSON ``CheckpointRecord``
    path's 9 signing-body fields (``v, kind, log_id, mmr_size, root,
    prev_size, prev_root, key_id, timestamp``), suitable for
    ``AnchorerService.witness_checkpoint`` unchanged.

    Order of checks (BEFORE any counter-signing, matching the JSON path's
    own two-phase gate):

    1. Structural + self-declared content type (:func:`_extract_protected_fields`)
       -- ``NotACheckpointError`` (-> 400) for anything malformed or not
       self-labelled a CLL checkpoint. This runs BEFORE the signature check
       so a well-formed-but-differently-purposed COSE statement is named
       "not a checkpoint", not misreported as a bad signature.
    2. Signature verification, via ``scitt_cose.statement.parse_signed_statement``
       against the Ed25519 public key reconstructed from the envelope's own
       ``kid`` (self-contained offline verify -- same trust model as
       ``capsule_emit.checkpoint.cose_wire.verify_checkpoint_cose_offline``)
       -- ``CheckpointSignatureError`` (-> 401) on failure. Never counter-signed.
    3. Claims-map decode (kind, log_size, commitment, prev_size,
       prev_commitment, issued_at, CWT subject) -- ``NotACheckpointError``
       (-> 400) for any structurally invalid claim. This step only ever
       reads AUTHENTICATED fields (``parsed["payload"]``/``parsed["issuer"]``/
       ``parsed["subject"]``), i.e. only once step 2 has already passed.

    Deliberately does NOT verify an attached ``consistency_proof`` (that is
    stage-2, per-``log_id`` continuity state this stateless route does not
    keep -- same STAGE 1 scope as the JSON path's ``witness_checkpoint``).
    """
    kid, content_type = _extract_protected_fields(cose_bytes)
    if content_type != CLL_CHECKPOINT_CONTENT_TYPE:
        raise NotACheckpointError(
            f"content_type is {content_type!r}, expected {CLL_CHECKPOINT_CONTENT_TYPE!r} "
            "-- not a CLL checkpoint statement"
        )
    if kid is None or len(kid) != _DIGEST_LEN:
        raise NotACheckpointError(
            "COSE checkpoint statement carries no 32-byte kid (label 4) -- cannot verify"
        )

    try:
        pubkey_pem = _ed25519_pubkey_pem(kid)
    except Exception as exc:  # noqa: BLE001 -- 32 arbitrary bytes always parse as SOME Ed25519 key, but stay defensive
        raise NotACheckpointError(f"kid is not a valid Ed25519 public key: {exc}") from exc

    from scitt_cose.statement import parse_signed_statement

    parsed = parse_signed_statement(cose_bytes, public_key_pem=pubkey_pem)
    if not parsed["signature_verified"]:
        raise CheckpointSignatureError(
            "COSE checkpoint signature does not verify under its own kid"
        )

    # Everything below reads only AUTHENTICATED fields (signature already verified above).
    issuer = parsed["issuer"]
    if not issuer:
        raise NotACheckpointError("statement carries no CWT issuer (log identity)")

    try:
        claims = cbor2.loads(parsed["payload"])
    except Exception as exc:  # noqa: BLE001
        raise NotACheckpointError(f"payload is not valid CBOR: {exc}") from exc
    if not hasattr(claims, "get"):
        raise NotACheckpointError("claims payload is not a map")
    if claims.get("kind") != WIRE_KIND:
        raise NotACheckpointError(f"claims 'kind' is {claims.get('kind')!r}, expected {WIRE_KIND!r}")

    mmr_size = claims.get("log_size")
    prev_size = claims.get("prev_size")
    commitment = claims.get("commitment")
    prev_commitment = claims.get("prev_commitment", b"")
    issued_at = claims.get("issued_at")

    if not isinstance(mmr_size, int) or isinstance(mmr_size, bool) or mmr_size <= 0:
        raise NotACheckpointError("log_size must be a positive integer")
    if not isinstance(prev_size, int) or isinstance(prev_size, bool) or prev_size < 0:
        raise NotACheckpointError("prev_size must be a non-negative integer")
    if prev_size >= mmr_size:
        raise NotACheckpointError(
            f"prev_size ({prev_size}) must be strictly less than log_size ({mmr_size})"
        )
    if not isinstance(commitment, (bytes, bytearray)):
        raise NotACheckpointError("commitment must be a CBOR byte string")
    new_peak_hashes = _decode_commitment(commitment, what="commitment")
    root = _root_from_peaks(new_peak_hashes).hex()

    if prev_commitment and not isinstance(prev_commitment, (bytes, bytearray)):
        raise NotACheckpointError("prev_commitment must be a CBOR byte string or empty")
    if prev_commitment:
        prev_peak_hashes = _decode_commitment(prev_commitment, what="prev_commitment")
        prev_root = _root_from_peaks(prev_peak_hashes).hex()
    else:
        prev_root = ""

    if not isinstance(issued_at, str):
        raise NotACheckpointError("issued_at must be a string (ISO 8601)")

    expected_subject = f"{issuer}#{mmr_size}"
    if parsed["subject"] != expected_subject:
        raise NotACheckpointError(
            f"CWT subject {parsed['subject']!r} does not match expected {expected_subject!r}"
        )

    return {
        "v": 1,
        "kind": "mmr_checkpoint",
        "log_id": issuer,
        "mmr_size": mmr_size,
        "root": root,
        "prev_size": prev_size,
        "prev_root": prev_root,
        "key_id": kid.hex(),
        "timestamp": issued_at,
    }
