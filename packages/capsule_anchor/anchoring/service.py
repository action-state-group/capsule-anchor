"""AnchorerService — countersign tenant roots + a real CT transparency log.

A tenant periodically computes a Merkle root over their (encrypted)
commitment chain and calls ``anchor``; the service:

  1. countersigns ``(tenant_id, root_hash, seq_range, anchored_at)`` with the
     authority key (reused from the attestation subsystem — one signing root),
     producing a ``CountersignedRoot``;
  2. appends a ``TransparencyLogEntry`` to an APPEND-ONLY log. Each entry
     carries ``prev_log_hash`` (chained to its predecessor's tree head) and a
     ``log_signature`` over the new tree head — the original hash-chain that
     existing monitors verify, preserved unchanged;
  3. folds the entry into a **real RFC 6962 (Certificate Transparency) Merkle
     tree** over the log leaves and can emit a **Signed Tree Head (STH)**,
     **inclusion proofs** (a leaf under an STH) and **consistency proofs**
     (between two STHs) — making the anchor auditable by any CT monitor;
  4. returns an ``AnchorReceipt`` with the countersignature, ``log_index`` and
     ``location``.

Two distinct Merkle worlds live in this codebase, deliberately:

  * the TENANT ledger tree — odd-node-promotion semantics
    (``default_crypto.merkle_root``), used for ``inclusion_proof`` over tenant
    leaves so any compatible engine and auditor compute identical roots;
  * the AUTHORITY CT log tree — strict RFC 6962 (``anchoring.ct``), used for
    the STH / log inclusion / consistency proofs an external monitor relies on.

DURABILITY (additive): ``AnchorerService(db_path=None)`` keeps the EXACT prior
in-memory behaviour; passing a path persists the log + countersigned roots to a
stdlib ``sqlite3`` file that rehydrates on reopen.

KEY CUSTODY (additive): pass ``key_provider`` to sign STHs / countersignatures
through the custody seam; if ``None`` we fall back to the in-process attestor
key, staying decoupled from the parallel key-custody subsystem.
"""

from __future__ import annotations

import collections.abc
import hashlib
import json
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime

import cbor2
from pydantic import BaseModel

from capsule_anchor.attestation.service import AttestorService
from capsule_anchor.contracts.protocols import CryptoCore, KeyProvider
from capsule_anchor.contracts.types import (
    AnchorReceipt,
    CountersignedRoot,
    MerkleProof,
    Signature,
    TransparencyLogEntry,
)

from . import ct
from .store import InMemoryLogStore, SqliteLogStore
from .tsa import TsaError, timestamp_root_hash, tsa_enabled

# Coordinate scheme for the (scaffold) public log location.
_LOG_LOCATION_PREFIX = "as-transparency-log://entry/"
_LOG_KIND_ROOT = "countersigned_root"
# Maximum accepted COSE statement size (bytes). Large enough for any realistic
# Signed Statement; small enough to bound memory/log impact from abuse.
MAX_STATEMENT_BYTES = 64 * 1024  # 64 KB
# SCITT Signed-Statement registration entries (Transparency Service, RFC9162
# CT log). Their CT leaf preimage is ``bytes.fromhex(entry_hash)`` -- the SAME
# 32-byte value returned to the caller as the entry identifier (NOT the
# canonical-JSON entry record used by other kinds) -- see ``ct_leaf_payload``
# / ``compute_entry_hash`` / ``register_signed_statement``.
_LOG_KIND_SCITT = "scitt_statement"


# --- COSE / SCITT receipt wire constants (RFC9052 + draft-cose-merkle-*) -----
#
# This block assembles a COSE_Sign1 (CBOR tag 18) "COSE Receipt" BY HAND with
# cbor2 + the authority's Ed25519 signing primitive. It mirrors the wire format
# of the generic ``scitt-cose`` library (and is what the open verifier's
# ``verify_scitt_receipt`` consumes); once ``scitt-cose`` is published this
# should consolidate onto that library rather than re-encoding here.
#
# Wire shape produced (draft-ietf-cose-merkle-tree-proofs-18):
#   COSE_Sign1 = Tag(18, [protected_bstr, unprotected_map, payload, signature])
#   protected map (then bstr-wrapped) = {1: -8, 395: 1}
#       1   = alg  -> -8  (EdDSA / Ed25519)
#       395 = vds  ->  1  (RFC9162_SHA256 verifiable-data-structure)
#   unprotected map = {396: {-1: [inclusion_bstr]}}
#       396 = vdp (verifiable-data-proofs); key -1 = inclusion-proofs array
#       inclusion_bstr = cbor(  [tree_size, leaf_index, [<audit-path 32B bstrs>]] )
#   payload  = nil  (DETACHED; the CT root is the external_aad-free Sig payload)
#   signature = Ed25519 over Sig_structure ["Signature1", protected, b"", root]
_COSE_ALG_LABEL = 1          # protected: algorithm
_COSE_ALG_EDDSA = -8         # EdDSA (Ed25519)
_COSE_VDS_LABEL = 395        # protected: verifiable-data-structure (vds)
_COSE_VDS_RFC9162_SHA256 = 1
_COSE_VDP_LABEL = 396        # unprotected: verifiable-data-proofs (vdp)
_COSE_VDP_INCLUSION_KEY = -1  # vdp map key for the inclusion-proofs array
_COSE_SIGN1_TAG = 18


def build_cose_receipt(
    *,
    tree_size: int,
    leaf_index: int,
    audit_path: list[bytes],
    root: bytes,
    sign: callable,
) -> bytes:
    """Assemble a SCITT COSE Receipt (COSE_Sign1, tag 18) -- ~the scitt-cose shape.

    Args:
      tree_size:  RFC6962 tree size the inclusion proof is against.
      leaf_index: 0-based index of the registered statement's leaf.
      audit_path: ordered RFC6962 sibling hashes, each RAW 32 bytes.
      root:       CT Merkle root, RAW 32 bytes -- the DETACHED signed payload.
      sign:       callable(bytes) -> bytes producing a raw Ed25519 signature over
                  the COSE Sig_structure (the authority key).

    Returns the tagged COSE_Sign1 CBOR bytes. See the module-level wire spec.
    """
    protected = {_COSE_ALG_LABEL: _COSE_ALG_EDDSA, _COSE_VDS_LABEL: _COSE_VDS_RFC9162_SHA256}
    protected_bstr = cbor2.dumps(protected)

    inclusion_bstr = cbor2.dumps([tree_size, leaf_index, list(audit_path)])
    unprotected = {_COSE_VDP_LABEL: {_COSE_VDP_INCLUSION_KEY: [inclusion_bstr]}}

    # RFC9052 sec 4.4 Sig_structure for COSE_Sign1: detached payload is the root.
    sig_structure = cbor2.dumps(["Signature1", protected_bstr, b"", root])
    signature = sign(sig_structure)

    # Detached payload => payload field is nil in the COSE_Sign1 array.
    cose_sign1 = cbor2.CBORTag(
        _COSE_SIGN1_TAG, [protected_bstr, unprotected, None, signature]
    )
    return cbor2.dumps(cose_sign1)


# --- entry_hash derivation (entry-identity-second-rule-sweep, Option 1) -----
#
# ``entry_hash`` is the dedup/idempotency key for ``register_signed_statement``
# AND -- per the documented interop contract -- the hex a verifier recomputes
# the RFC6962 CT leaf from (``SHA256(0x00 || bytes.fromhex(entry_hash))``, see
# ``ct_leaf_payload``'s SCITT case). Those two roles are the SAME stored field
# in this codebase (``TransparencyLogEntry.payload_hash``), so fixing the
# entry-identifier necessarily moves the leaf preimage with it -- they cannot
# be split without breaking offline verification for one of the two roles.
#
# Hashing the FULL COSE_Sign1 envelope (signature bytes included) is not a
# function of the signing act: for any valid ECDSA ``(r, s)``, ``(r, n-s)``
# also verifies (SEC1 v2.0 SS4.1.3), so a malleated twin of one act used to
# register as a second, distinct entry (and a second, distinct leaf). The fix
# hashes the RFC9052 SS4.4 ``Sig_structure`` instead (excludes the signature
# field), when the submitted bytes are a well-formed COSE_Sign1 with an
# embedded (non-detached) payload -- exactly the shape a real Signed Statement
# submission has. Bytes that are not a parseable COSE_Sign1 (e.g. the
# ``/v1/digest`` surface's raw digest bytes, which were never a signed
# structure) keep hashing the legacy full bytes -- there is no signature to be
# malleable, and no behavior change for that surface. Historical leaves
# (append-only, immutable) keep whatever preimage they were minted with; only
# NEW registrations of a parseable COSE_Sign1 move to the new scheme.
ENTRY_HASH_SCHEME_SIG_STRUCTURE = "sig_structure"
ENTRY_HASH_SCHEME_LEGACY = "legacy"


def _decode_cose_sign1(data: bytes) -> tuple[bytes, dict, bytes | None, bytes] | None:
    """Best-effort COSE_Sign1 (CBOR tag 18) decode. Returns ``None`` on anything
    that isn't a well-formed 4-element Sign1 array -- never raises."""
    try:
        tagged = cbor2.loads(data)
    except Exception:  # noqa: BLE001 - untrusted input, any decode failure -> None
        return None
    if not isinstance(tagged, cbor2.CBORTag) or tagged.tag != _COSE_SIGN1_TAG:
        return None
    arr = tagged.value
    # cbor2 decodes CBOR arrays as list or tuple depending on nesting context,
    # and CBOR maps as dict or its internal frozendict -- accept both shapes.
    if not (isinstance(arr, (list, tuple)) and len(arr) == 4):
        return None
    protected_bstr, unprotected, payload, signature = arr
    if not isinstance(protected_bstr, bytes) or not isinstance(signature, bytes):
        return None
    if not isinstance(unprotected, collections.abc.Mapping):
        return None
    if payload is not None and not isinstance(payload, bytes):
        return None
    return protected_bstr, dict(unprotected), payload, signature


def _legacy_entry_hash(statement_bytes: bytes) -> str:
    return hashlib.sha256(statement_bytes).hexdigest()


def _entry_hash_preimage(statement_bytes: bytes) -> tuple[bytes, str]:
    """Return ``(preimage_bytes, scheme)``. ``entry_hash = SHA256(preimage_bytes).hex()``,
    and ``preimage_bytes`` is exactly what gets appended as the CT leaf's
    payload_hash input for this entry -- see the module comment above.
    """
    decoded = _decode_cose_sign1(statement_bytes)
    if decoded is not None:
        protected_bstr, _unprotected, payload, _signature = decoded
        if payload is not None:
            sig_structure = cbor2.dumps(["Signature1", protected_bstr, b"", payload])
            return sig_structure, ENTRY_HASH_SCHEME_SIG_STRUCTURE
    return statement_bytes, ENTRY_HASH_SCHEME_LEGACY


def compute_entry_hash(statement_bytes: bytes) -> tuple[str, str]:
    """Return ``(entry_hash_hex, scheme)`` for a submitted statement.

    Preferred scheme is ``sig_structure`` (malleability-immune). Falls back to
    ``legacy`` (full-envelope digest -- the pre-migration behavior, unchanged)
    when ``statement_bytes`` doesn't decode as a COSE_Sign1 with an embedded
    payload.
    """
    preimage, scheme = _entry_hash_preimage(statement_bytes)
    return hashlib.sha256(preimage).hexdigest(), scheme


# --- checkpoint witness surface (mmr-checkpoint artifact type) --------------
#
# A checkpoint capsule is just a Signed Statement -- the SCITT registration
# path anchors it with zero extra code. What this adds is WITNESS behavior:
# recognizing the checkpoint automatically from its (signed) payload, then
# checking it extends the log's own last-witnessed state before co-signing.
_ARTIFACT_TYPE_MMR_CHECKPOINT = "mmr-checkpoint"
_CHECKPOINT_REQUIRED_FIELDS = (
    "log_id",
    "key_id",
    "mmr_root",
    "mmr_size",
    "prev_size",
    "timestamp",
)


class CheckpointPayloadError(ValueError):
    """A statement self-declared ``artifact_type: mmr-checkpoint`` but its
    payload doesn't match the accepted shape. This is a caller error (400),
    not a silent pass-through -- a statement that CLAIMS to be a checkpoint
    and isn't well-formed must not register as an opaque, unwitnessed one."""


class RollbackError(RuntimeError):
    """A checkpoint is inconsistent with the log's last witnessed checkpoint
    (non-monotonic size, or doesn't chain from it). Registration MUST be
    refused before any log append / countersignature -- never co-sign a
    rollback or fork."""


def parse_checkpoint_payload(payload: bytes | None) -> dict | None:
    """Return the checkpoint witness fields if ``payload`` is a self-declared
    ``mmr-checkpoint`` submission, else ``None`` (unknown/other type -- the
    caller registers it exactly as before, with no witness behavior).

    Raises ``CheckpointPayloadError`` only when ``artifact_type`` explicitly
    claims ``mmr-checkpoint`` but the required fields are missing or malformed.
    """
    if payload is None:
        return None
    try:
        obj = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(obj, dict) or obj.get("artifact_type") != _ARTIFACT_TYPE_MMR_CHECKPOINT:
        return None

    missing = [k for k in _CHECKPOINT_REQUIRED_FIELDS if k not in obj]
    if missing:
        raise CheckpointPayloadError(
            f"mmr-checkpoint payload missing required field(s): {missing}"
        )

    log_id, key_id, mmr_root, mmr_size, prev_size, timestamp = (
        obj["log_id"],
        obj["key_id"],
        obj["mmr_root"],
        obj["mmr_size"],
        obj["prev_size"],
        obj["timestamp"],
    )
    if not isinstance(log_id, str) or not log_id:
        raise CheckpointPayloadError("log_id must be a non-empty string")
    if not isinstance(key_id, str) or not key_id:
        raise CheckpointPayloadError("key_id must be a non-empty string")
    if (
        not isinstance(mmr_root, str)
        or len(mmr_root) != 64
        or not all(c in "0123456789abcdefABCDEF" for c in mmr_root)
    ):
        raise CheckpointPayloadError("mmr_root must be a 64-char hex string (32 bytes)")
    if isinstance(mmr_size, bool) or not isinstance(mmr_size, int) or mmr_size <= 0:
        raise CheckpointPayloadError("mmr_size must be a positive integer")
    if isinstance(prev_size, bool) or not isinstance(prev_size, int) or prev_size < 0:
        raise CheckpointPayloadError("prev_size must be a non-negative integer")
    if not isinstance(timestamp, str) or not timestamp:
        raise CheckpointPayloadError("timestamp must be a non-empty string")
    if prev_size >= mmr_size:
        raise CheckpointPayloadError("prev_size must be strictly less than mmr_size")

    return {
        "log_id": log_id,
        "key_id": key_id,
        "mmr_root": mmr_root.lower(),
        "mmr_size": mmr_size,
        "prev_size": prev_size,
        "timestamp": timestamp,
    }


# --- checkpoint-only witness surface (POST /v1/checkpoint, stateless) -------
#
# A SEPARATE, stricter surface from the ``mmr-checkpoint`` recognition above:
# where ``register_signed_statement_full`` accepts any Signed Statement and
# only *optionally* notices a checkpoint, this route accepts the CLL
# (Checkpointed Local Log, draft-mih-scitt-checkpointed-local-log)
# ``CheckpointRecord`` wire shape directly -- {v, kind, log_id, mmr_size,
# root, prev_size, prev_root, key_id, timestamp, signature} -- and refuses
# anything else outright. It additionally verifies the checkpoint's own
# Ed25519 signature server-side before ever counter-signing -- something the
# ``mmr-checkpoint`` payload path above does not do.
#
# STATELESS by construction: registration is dispatched as a bare digest
# (see ``AnchorerService.witness_checkpoint``), which never decodes as a
# COSE_Sign1, so it can never trigger ``_check_checkpoint_consistency`` --
# no per-``log_id`` state is read or written here. See
# ``AnchorerService.witness_checkpoint`` for the stage-2 seam.
_CHECKPOINT_RECORD_FIELDS = (
    "v",
    "kind",
    "log_id",
    "mmr_size",
    "root",
    "prev_size",
    "prev_root",
    "key_id",
    "timestamp",
)


class NotACheckpointError(ValueError):
    """The submitted artifact is not a well-formed CLL checkpoint record
    (draft-mih-scitt-checkpointed-local-log): a required field is missing,
    ``kind`` isn't ``"mmr_checkpoint"``, or a field is malformed. Raised
    BEFORE any signature check or log write -- this surface registers
    checkpoints only, nothing else."""


class CheckpointSignatureError(ValueError):
    """A structurally well-formed checkpoint whose ``signature`` does not
    verify as an Ed25519 signature by ``key_id`` (the raw public key, hex)
    over the checkpoint's own signing body. Never counter-signed."""


def _checkpoint_signing_body(cp: dict) -> bytes:
    """Canonical bytes a checkpoint's ``signature`` covers -- MUST match
    ``capsule_emit.checkpoint.emit.CheckpointRecord.signing_body()`` byte
    for byte (sorted-key, compact-separator JSON) or every signature this
    surface receives fails to verify."""
    return _canonical({k: cp[k] for k in _CHECKPOINT_RECORD_FIELDS})


def _checkpoint_digest(cp: dict) -> str:
    """64-char hex sha256 of the signing body -- what gets registered with
    the CT log, mirroring ``CheckpointRecord.digest()``."""
    return hashlib.sha256(_checkpoint_signing_body(cp)).hexdigest()


@dataclass
class StatementRegistration:
    """Full result of registering a Signed Statement -- superset of the
    ``(receipt, entry_hash, leaf_index, tree_size)`` tuple ``register_signed_statement``
    returns for backward compatibility."""

    receipt: bytes
    entry_hash: str
    leaf_index: int
    tree_size: int
    entry_hash_scheme: str
    checkpoint_witness: dict | None = field(default=None)


def _now() -> datetime:
    return datetime.now(UTC)


def _canonical(obj: dict) -> bytes:
    """Deterministic JSON encoding for anything we sign/hash.

    Sorted keys + compact separators so the tenant, authority, and any external
    monitor recompute byte-identical payloads.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def countersign_payload(
    tenant_id: str, root_hash: str, seq_range: tuple[int, int], attested_at: datetime
) -> bytes:
    """Canonical bytes the authority signs to countersign a root.

    Exported so relying parties / monitors can reconstruct exactly what was
    signed and verify it against the authority public key.
    """
    return _canonical(
        {
            "tenant_id": tenant_id,
            "root_hash": root_hash,
            "seq_from": seq_range[0],
            "seq_to": seq_range[1],
            "attested_at": attested_at.isoformat(),
        }
    )


def tree_head_payload(log_index: int, payload_hash: str, prev_log_hash: str | None) -> bytes:
    """Canonical bytes the log signs for the hash-chain head at ``log_index``.

    The tree head folds the new leaf's ``payload_hash`` into the previous head
    hash -- the original append-only chain. ``log_signature`` is taken over this.
    PRESERVED unchanged for backward compatibility with existing monitors.
    """
    return _canonical(
        {
            "log_index": log_index,
            "payload_hash": payload_hash,
            "prev_log_hash": prev_log_hash,
        }
    )


def ct_leaf_payload(entry: TransparencyLogEntry) -> bytes:
    """Canonical leaf bytes a log entry contributes to the RFC6962 CT tree.

    Deterministic over the entry's stable, content-free fields so any external
    monitor that pulls ``transparency_log()`` recomputes byte-identical CT leaf
    hashes (and thus the same STH root). Exported for that reason.

    SCITT EXCEPTION (interop contract): for ``scitt_statement`` entries the CT
    leaf preimage is the RAW 32-byte ``SHA256(statement_bytes)`` (i.e.
    ``bytes.fromhex(entry.payload_hash)``), NOT this JSON record. Combined with
    ``ct.leaf_hash`` (which prepends the RFC6962 ``0x00`` prefix) this yields the
    Merkle leaf ``SHA256(0x00 || SHA256(statement_bytes))`` -- the exact leaf the
    the open verifier (``verify_scitt_receipt`` / ``scitt-cose``) recomputes.
    """
    if entry.kind == _LOG_KIND_SCITT:
        return bytes.fromhex(entry.payload_hash)
    return _canonical(
        {
            "log_index": entry.log_index,
            "kind": entry.kind,
            "payload_hash": entry.payload_hash,
            "prev_log_hash": entry.prev_log_hash,
            "logged_at": entry.logged_at.isoformat(),
        }
    )


def ct_leaf_hash(entry: TransparencyLogEntry) -> str:
    """RFC6962 leaf hash for a transparency-log entry."""
    return ct.leaf_hash(ct_leaf_payload(entry))


def sth_payload(tree_size: int, root_hash: str, timestamp: datetime) -> bytes:
    """Canonical bytes the authority signs for a Signed Tree Head (RFC6962).

    Exported so a monitor reconstructs exactly what was signed and verifies the
    STH signature against the authority public key.
    """
    return _canonical(
        {
            "tree_size": tree_size,
            "root_hash": root_hash,
            "timestamp": timestamp.isoformat(),
        }
    )


class SignedTreeHead(BaseModel):
    """RFC6962 Signed Tree Head over the CT log of transparency-log entries.

    ``tree_size`` leaves hash (under RFC6962 domain separation) to ``root_hash``;
    ``signature`` is the authority's signature over ``sth_payload(...)``. A
    monitor stores successive STHs and demands a consistency proof between them.
    """

    tree_size: int
    root_hash: str
    timestamp: datetime
    signature: Signature


class InclusionProof(BaseModel):
    """RFC6962 inclusion proof: ``leaf_index`` is under an STH of ``tree_size``."""

    leaf_index: int
    tree_size: int
    leaf_hash: str
    audit_path: list[str]
    root_hash: str


class ConsistencyProof(BaseModel):
    """RFC6962 consistency proof between tree sizes ``first`` and ``second``."""

    first_size: int
    second_size: int
    first_root: str
    second_root: str
    proof: list[str]


class AnchorerService:
    """Countersign tenant roots and maintain a real CT transparency log.

    Satisfies the ``AnchorerService`` protocol. Reuses the attestation
    subsystem's authority key (one signing root for countersignatures, log
    hash-chain tree heads, AND CT signed tree heads).
    """

    def __init__(
        self,
        attestor: AttestorService | None = None,
        db_path: str | None = None,
        key_provider: KeyProvider | None = None,
        store=None,
    ) -> None:
        # If a key_provider is given (and no explicit attestor), build the
        # attestor against the custody seam; otherwise the in-process key.
        if attestor is not None:
            self._attestor = attestor
        else:
            self._attestor = AttestorService(key_provider=key_provider)
        self._crypto: CryptoCore = self._attestor.crypto
        self._lock = threading.RLock()

        # Append-only public log store, in priority order:
        #   1. ``store`` injected directly (PostgresLogStore from the app factory
        #      when CAPSULE_ANCHOR_DATABASE_URL is set) → use it verbatim.
        #   2. ``db_path`` → durable SQLite file (local dev / testing).
        #   3. neither → InMemoryLogStore (local/CI default).
        self._db_path = db_path
        if store is not None:
            self._store = store
        elif db_path is None:
            self._store = InMemoryLogStore()
        else:
            self._store = SqliteLogStore(db_path)

    # --- AnchorerService protocol ------------------------------------------
    def anchor(
        self,
        tenant_id: str,
        root_hash: str,
        seq_range: tuple[int, int],
        *,
        capsule_id: str | None = None,
    ) -> AnchorReceipt:
        """Countersign ``root_hash`` and append it to the transparency log."""
        attested_at = _now()
        seq_range = (int(seq_range[0]), int(seq_range[1]))

        # 1. Countersign with the authority key.
        cs_payload = countersign_payload(tenant_id, root_hash, seq_range, attested_at)
        countersignature = self._attestor.attest(cs_payload)

        countersigned = CountersignedRoot(
            tenant_id=tenant_id,
            root_hash=root_hash,
            seq_range=seq_range,
            attested_at=attested_at,
            countersignature=countersignature,
        )

        with self._lock:
            # 2. Append to the append-only log under the lock so the chain and
            #    log_index assignment are atomic.
            entry = self._append_log(_LOG_KIND_ROOT, cs_payload, attested_at)
            self._store.put_root(countersigned)
            # Phase 3: bind log entry to a capsule_id when supplied, so the
            # verify CLI can ask "where was capsule <id> anchored?".
            if capsule_id is not None:
                self._store.put_capsule_id(entry.log_index, capsule_id)

        # 3. Optional RFC3161 TSA signature over the root hash (Phase 3.5).
        #    Opt-in via CAPSULE_ANCHOR_TSA_ENABLED=1; default OFF. Any failure
        #    is logged-but-tolerated — TSA outages must not block anchoring.
        tsa_signature: bytes | None = None
        tsa_token_b64: str | None = None
        if tsa_enabled():
            try:
                tsa_signature = timestamp_root_hash(root_hash)
                import base64 as _b64
                tsa_token_b64 = _b64.b64encode(tsa_signature).decode("ascii")
            except TsaError:
                # Soft-fail: the AS countersignature is the primary proof.
                tsa_signature = None
                tsa_token_b64 = None

        # 4. Build the receipt.
        return AnchorReceipt(
            root_hash=root_hash,
            tenant_id=tenant_id,
            anchored_at=attested_at,
            location=f"{_LOG_LOCATION_PREFIX}{entry.log_index}",
            log_index=entry.log_index,
            countersignature=countersignature,
            proof={
                "kind": _LOG_KIND_ROOT,
                "payload_hash": entry.payload_hash,
                "prev_log_hash": entry.prev_log_hash,
                "seq_from": seq_range[0],
                "seq_to": seq_range[1],
            },
            tsa_signature=tsa_signature,
            tsa_token_b64=tsa_token_b64,
        )

    def get_countersigned_root(
        self, tenant_id: str, root_hash: str
    ) -> CountersignedRoot | None:
        with self._lock:
            return self._store.get_root(tenant_id, root_hash)

    def transparency_log(self, after_index: int = 0) -> list[TransparencyLogEntry]:
        """Return log entries with ``log_index >= after_index`` (monitor feed)."""
        with self._lock:
            return self._store.entries_after(after_index)

    def transparency_log_for_capsule(
        self, capsule_id: str
    ) -> list[TransparencyLogEntry]:
        """Return log entries bound to ``capsule_id`` (Phase 3 verify-CLI feed)."""
        with self._lock:
            return self._store.entries_for_capsule(capsule_id)

    def get_capsule_id(self, log_index: int) -> str | None:
        """Look up the capsule_id (if any) bound to ``log_index``."""
        with self._lock:
            return self._store.get_capsule_id(log_index)

    # --- append-only log internals -----------------------------------------
    def _append_log(
        self, kind: str, signed_payload: bytes, logged_at: datetime
    ) -> TransparencyLogEntry:
        """Append one entry, chaining its tree head to the prior head.

        Caller holds ``self._lock``.
        """
        log_index = self._store.size()
        payload_hash = self._crypto.sha256(signed_payload)
        prev_log_hash = self._head_hash() if log_index > 0 else None

        log_signature = self._attestor.attest(
            tree_head_payload(log_index, payload_hash, prev_log_hash)
        )
        entry = TransparencyLogEntry(
            log_index=log_index,
            logged_at=logged_at,
            kind=kind,
            payload_hash=payload_hash,
            log_signature=log_signature,
            prev_log_hash=prev_log_hash,
        )
        self._store.append_entry(entry)
        return entry

    def _entry_head_hash(self, entry: TransparencyLogEntry) -> str:
        """The tree-head hash for ``entry`` (folds leaf into prior head)."""
        return self._crypto.sha256(
            tree_head_payload(entry.log_index, entry.payload_hash, entry.prev_log_hash)
        )

    def _head_hash(self) -> str:
        return self._entry_head_hash(self._store.all_entries()[-1])

    # --- audit / verification helpers (hash chain) -------------------------
    def verify_log(self, entries: list[TransparencyLogEntry] | None = None) -> bool:
        """Verify the append-only chain integrity of the (or a) log slice.

        Checks, for every entry: indices are contiguous from 0, each
        ``prev_log_hash`` equals the recomputed prior tree head, and each
        ``log_signature`` verifies under the authority key. Any tamper with a
        past ``payload_hash`` or ``prev_log_hash`` breaks this -- the property
        an external monitor relies on (trust-model doc, DigiNotar mitigation).
        """
        log = entries if entries is not None else self.transparency_log()
        prev_head: str | None = None
        for i, entry in enumerate(log):
            if entry.log_index != i:
                return False
            if entry.prev_log_hash != prev_head:
                return False
            head_payload = tree_head_payload(
                entry.log_index, entry.payload_hash, entry.prev_log_hash
            )
            if not self._attestor.verify(head_payload, entry.log_signature):
                return False
            prev_head = self._crypto.sha256(head_payload)
        return True

    def verify_countersignature(self, countersigned: CountersignedRoot) -> bool:
        """Verify a ``CountersignedRoot`` against the authority public key."""
        payload = countersign_payload(
            countersigned.tenant_id,
            countersigned.root_hash,
            tuple(countersigned.seq_range),
            countersigned.attested_at,
        )
        return self._attestor.verify(payload, countersigned.countersignature)

    # --- RFC6962 CT log: signed tree head ----------------------------------
    def _ct_leaves(self, entries: list[TransparencyLogEntry] | None = None) -> list[str]:
        """RFC6962 leaf hashes for the current log (or a supplied slice)."""
        log = entries if entries is not None else self.transparency_log()
        return [ct_leaf_hash(e) for e in log]

    def ct_root(self, tree_size: int | None = None) -> str:
        """RFC6962 Merkle Tree Hash of the first ``tree_size`` log leaves."""
        with self._lock:
            leaves = self._ct_leaves()
            if tree_size is None:
                tree_size = len(leaves)
            if tree_size < 0 or tree_size > len(leaves):
                raise ValueError("tree_size out of range")
            return ct.merkle_tree_hash(leaves[:tree_size])

    def _sign_and_persist_sth(self) -> SignedTreeHead:
        """Sign the current STH and persist it to the store.

        Caller must hold ``self._lock`` (it is an RLock so re-entrant calls are safe).
        Persisting the STH means a restart returns the last-known head from the DB
        rather than an empty/stale value, and GET /anchor/sth is stable across calls
        within the same tree state instead of producing a fresh timestamp each time.
        """
        tree_size = self._store.size()
        root_hash = ct.merkle_tree_hash(self._ct_leaves()[:tree_size])
        timestamp = _now()
        signature = self._attestor.attest(sth_payload(tree_size, root_hash, timestamp))
        sth = SignedTreeHead(
            tree_size=tree_size,
            root_hash=root_hash,
            timestamp=timestamp,
            signature=signature,
        )
        self._store.put_sth(sth.model_dump_json())
        return sth

    def get_sth(self) -> SignedTreeHead:
        """Return the latest persisted Signed Tree Head (RFC6962).

        Returns the stored STH when it is current (tree_size matches the log).
        Re-signs and persists a new STH when the log has grown since the last
        signing — ensuring the head ALWAYS reflects the full log on read.

        A monitor pins this STH, fetches new entries, then demands a
        consistency proof to a later STH — so the authority cannot rewrite or
        fork history without detection.
        """
        with self._lock:
            stored_json = self._store.get_latest_sth()
            if stored_json is not None:
                stored = SignedTreeHead.model_validate_json(stored_json)
                if stored.tree_size >= self._store.size():
                    return stored
            return self._sign_and_persist_sth()

    def refresh_sth(self) -> SignedTreeHead:
        """Force-sign a fresh STH and persist it.

        Called by the background periodic refresh task so the STH advances
        even during idle periods when no new entries are being registered.
        A monitor can detect a log that went dark by comparing the STH
        timestamp to the Maximum Merge Delay threshold.
        """
        with self._lock:
            return self._sign_and_persist_sth()

    @staticmethod
    def is_sth_stale(
        sth: SignedTreeHead,
        current_log_size: int,
        *,
        max_age_seconds: float = 86400.0,
    ) -> bool:
        """Return True when ``sth`` is detectably stale.

        A head is stale when:
        * its tree_size is smaller than the current log (entries were appended
          after the last signing and the head has not yet caught up), OR
        * its timestamp is older than ``max_age_seconds`` (the MMD has elapsed
          without a fresh signing, indicating the log may have gone dark).

        Both directions are meaningful: tree_size staleness catches the defect
        class (head not advancing with the log); timestamp staleness catches a
        transparency service that stops publishing without removing entries.
        """
        if sth.tree_size < current_log_size:
            return True
        age = (datetime.now(UTC) - sth.timestamp).total_seconds()
        return age > max_age_seconds

    def verify_sth(self, sth: SignedTreeHead) -> bool:
        """Verify an STH signature against the authority public key."""
        return self._attestor.verify(
            sth_payload(sth.tree_size, sth.root_hash, sth.timestamp), sth.signature
        )

    # --- RFC6962 CT log: inclusion proof -----------------------------------
    def inclusion_proof_ct(
        self, leaf_index: int, tree_size: int | None = None
    ) -> InclusionProof:
        """Build an RFC6962 inclusion proof for log entry ``leaf_index``.

        Proves the entry is under the CT root of a tree of ``tree_size`` log
        entries (default: the whole log). Distinct from ``inclusion_proof`` over
        TENANT ledger leaves.
        """
        with self._lock:
            leaves = self._ct_leaves()
            if tree_size is None:
                tree_size = len(leaves)
            if not (0 <= leaf_index < tree_size <= len(leaves)):
                raise IndexError("leaf_index / tree_size out of range")
            sub = leaves[:tree_size]
            audit_path = ct.inclusion_audit_path(leaf_index, sub)
            return InclusionProof(
                leaf_index=leaf_index,
                tree_size=tree_size,
                leaf_hash=sub[leaf_index],
                audit_path=audit_path,
                root_hash=ct.merkle_tree_hash(sub),
            )

    def verify_inclusion(
        self,
        proof: MerkleProof | InclusionProof,
        anchored_root_hash: str | None = None,
    ) -> bool:
        """Verify an inclusion proof. Polymorphic over proof type.

        * ``MerkleProof`` (TENANT ledger, engine-compatible Merkle semantics) -- the original
          behaviour, preserved: verify the proof and, if ``anchored_root_hash``
          is given, bind it to that exact anchored root.
        * ``InclusionProof`` (RFC6962 CT LOG) -- monitor-side: recompute the CT
          root from leaf + audit path; if ``anchored_root_hash`` is given, bind
          to that STH root (rejecting a valid proof under a *different* tree).
        """
        if isinstance(proof, InclusionProof):
            ok = ct.verify_inclusion_path(
                proof.leaf_hash,
                proof.leaf_index,
                proof.tree_size,
                proof.audit_path,
                proof.root_hash,
            )
            if not ok:
                return False
            return not (anchored_root_hash is not None and proof.root_hash != anchored_root_hash)
        # Tenant-ledger MerkleProof (original surface).
        return self.verify_inclusion_ledger(proof, anchored_root_hash)

    # --- RFC6962 CT log: consistency proof ---------------------------------
    def consistency_proof(self, old_size: int, new_size: int) -> ConsistencyProof:
        """Build an RFC6962 consistency proof between two tree sizes.

        Proves the size-``new_size`` log is an append-only superset of the
        size-``old_size`` log -- the core anti-fork / anti-backdate guarantee.
        """
        with self._lock:
            leaves = self._ct_leaves()
            if not (0 <= old_size <= new_size <= len(leaves)):
                raise ValueError("require 0 <= old_size <= new_size <= log size")
            first_root = ct.merkle_tree_hash(leaves[:old_size])
            second_root = ct.merkle_tree_hash(leaves[:new_size])
            if old_size == 0 or old_size == new_size:
                proof: list[str] = []
            else:
                proof = ct.consistency_proof(old_size, new_size, leaves)
            return ConsistencyProof(
                first_size=old_size,
                second_size=new_size,
                first_root=first_root,
                second_root=second_root,
                proof=proof,
            )

    @staticmethod
    def verify_consistency(proof: ConsistencyProof) -> bool:
        """Monitor-side: verify an RFC6962 consistency proof.

        Confirms ``first_root`` (size ``first_size``) is a verifiable prefix of
        ``second_root`` (size ``second_size``). A forked / tampered log fails.
        """
        return ct.verify_consistency_proof(
            proof.first_size,
            proof.second_size,
            proof.first_root,
            proof.second_root,
            proof.proof,
        )

    # --- SCITT: register Signed Statement, issue COSE Receipt --------------
    def register_signed_statement(
        self, statement_bytes: bytes
    ) -> tuple[bytes, str, int, int]:
        """SCITT registration: append a Signed Statement, return a COSE Receipt.

        Thin wrapper over ``register_signed_statement_full`` preserving the
        original 4-tuple return shape for existing callers. Use
        ``register_signed_statement_full`` for the entry-hash scheme and
        checkpoint-witness metadata.

        Returns ``(receipt_bytes, entry_hash_hex, leaf_index, tree_size)``.
        Raises ``ValueError`` if ``statement_bytes`` exceeds ``MAX_STATEMENT_BYTES``,
        ``CheckpointPayloadError`` if the statement self-declares a malformed
        checkpoint, ``RollbackError`` if it's a checkpoint inconsistent with the
        log's last witnessed checkpoint for its ``log_id``.
        """
        result = self.register_signed_statement_full(statement_bytes)
        return result.receipt, result.entry_hash, result.leaf_index, result.tree_size

    def register_signed_statement_full(self, statement_bytes: bytes) -> StatementRegistration:
        """SCITT registration with full metadata (entry-hash scheme, checkpoint witness).

        The argument is a SCITT Signed Statement = a COSE_Sign1 (CBOR) blob; we
        treat it as opaque bytes for anchoring purposes -- the CT-log ENTRY hash
        is (by default) the malleability-immune Sig_structure digest (see
        ``compute_entry_hash``), or the legacy full-envelope digest when the
        bytes aren't a parseable COSE_Sign1. We append that entry hash to the
        SAME RFC6962 CT log (``ct.py`` adds the ``0x00`` leaf prefix; see
        ``ct_leaf_payload`` for the SCITT leaf-preimage exception) and return a
        COSE Receipt (COSE_Sign1, tag 18) carrying an inclusion proof to the
        current CT root, signed by the authority Ed25519 key.

        Idempotent: a second submission of the same signing act (including a
        signature-malleated twin, or bytes registered before the entry_hash
        migration under the legacy scheme -- the dual-lookup window) returns
        the cached ORIGINAL receipt without appending a duplicate log entry.

        A statement that self-declares ``artifact_type: mmr-checkpoint`` in its
        payload additionally runs the checkpoint witness check (monotonic size +
        chain-linkage vs. the log's last witnessed checkpoint for that ``log_id``)
        BEFORE being appended -- a rollback/fork raises ``RollbackError`` and is
        never co-signed. Any other type registers exactly as before.
        """
        if len(statement_bytes) > MAX_STATEMENT_BYTES:
            raise ValueError(
                f"statement too large: {len(statement_bytes)} bytes "
                f"(max {MAX_STATEMENT_BYTES})"
            )
        preimage_bytes, scheme = _entry_hash_preimage(statement_bytes)
        entry_hash = hashlib.sha256(preimage_bytes).hexdigest()
        legacy_hash = (
            entry_hash if scheme == ENTRY_HASH_SCHEME_LEGACY else _legacy_entry_hash(statement_bytes)
        )

        checkpoint_fields: dict | None = None
        if scheme == ENTRY_HASH_SCHEME_SIG_STRUCTURE:
            decoded = _decode_cose_sign1(statement_bytes)
            assert decoded is not None  # scheme==sig_structure implies a decode
            _protected_bstr, _unprotected, payload, _signature = decoded
            checkpoint_fields = parse_checkpoint_payload(payload)  # may raise CheckpointPayloadError

        logged_at = _now()
        with self._lock:
            # Atomic dedup + append. The get_statement check MUST be inside the
            # same lock as the append: otherwise two concurrent submissions of
            # the same NEW statement both see "not present" and both append,
            # landing ONE statement at TWO CT leaves (observed in the wild:
            # a doubly-submitted capsule occupied leaves 180 AND 181). Holding
            # the lock across check → append → persist makes registration
            # exactly-once per entry_hash.
            cached = self._store.get_statement(entry_hash)
            cache_scheme = scheme
            if cached is None and entry_hash != legacy_hash:
                # Dual-lookup window: bytes registered BEFORE the entry_hash
                # migration are keyed under the legacy (full-envelope) scheme.
                cached = self._store.get_statement(legacy_hash)
                cache_scheme = ENTRY_HASH_SCHEME_LEGACY
            if cached is not None:
                receipt_bytes, leaf_index, tree_size = cached
                returned_hash = legacy_hash if cache_scheme == ENTRY_HASH_SCHEME_LEGACY else entry_hash
                witness_info = None
                if checkpoint_fields is not None:
                    witness_info = {**checkpoint_fields, "status": "already-registered"}
                return StatementRegistration(
                    receipt=receipt_bytes,
                    entry_hash=returned_hash,
                    leaf_index=leaf_index,
                    tree_size=tree_size,
                    entry_hash_scheme=cache_scheme,
                    checkpoint_witness=witness_info,
                )

            # Not cached: a genuinely new signing act. If it's a checkpoint,
            # validate it against the log's last witnessed state BEFORE any
            # append/countersignature -- never co-sign a rollback or fork.
            witness_status: str | None = None
            if checkpoint_fields is not None:
                witness_status = self._check_checkpoint_consistency(checkpoint_fields)

            # 1. Append to the SAME append-only CT log; the entry's payload_hash
            #    IS the SCITT entry hash, and (per ct_leaf_payload) its CT leaf
            #    preimage is the raw 32 bytes of that hash. Build the inclusion
            #    proof + current root under the same lock so the returned
            #    leaf_index/tree_size match the receipt exactly.
            # Feed the SAME bytes we hashed for entry_hash into the leaf
            # commitment -- entry_hash IS the CT leaf preimage hex (see the
            # entry_hash derivation comment above), so they must never diverge.
            entry = self._append_log(_LOG_KIND_SCITT, preimage_bytes, logged_at)
            leaf_index = entry.log_index
            leaves = self._ct_leaves()
            tree_size = len(leaves)
            audit_hex = ct.inclusion_audit_path(leaf_index, leaves)
            root_hex = ct.merkle_tree_hash(leaves)

            audit_path = [bytes.fromhex(h) for h in audit_hex]
            root = bytes.fromhex(root_hex)

            # 2. Assemble + sign the COSE Receipt (detached root payload).
            receipt = build_cose_receipt(
                tree_size=tree_size,
                leaf_index=leaf_index,
                audit_path=audit_path,
                root=root,
                sign=lambda payload: bytes.fromhex(self._attestor.attest(payload).signature),
            )

            # 3. Persist for idempotent dedup (still INSERT OR IGNORE as
            #    defence-in-depth across processes / durable backends), keyed
            #    under the (preferred) entry_hash computed above.
            self._store.put_statement(entry_hash, receipt, leaf_index, tree_size)

            # 4. Advance the persisted STH to cover the new entry.
            #    This keeps GET /anchor/sth always current after any registration;
            #    the background refresh task also handles the idle-log case.
            self._sign_and_persist_sth()

            # 5. Commit the checkpoint witness state (only after a successful
            #    append/countersign -- a rejected/failed registration must not
            #    move the witness's notion of "last checkpoint seen" forward).
            if checkpoint_fields is not None:
                self._store.put_checkpoint_witness(
                    checkpoint_fields["log_id"],
                    mmr_size=checkpoint_fields["mmr_size"],
                    mmr_root=checkpoint_fields["mmr_root"],
                    key_id=checkpoint_fields["key_id"],
                    timestamp=checkpoint_fields["timestamp"],
                )

        witness_info = (
            {**checkpoint_fields, "status": witness_status} if checkpoint_fields is not None else None
        )
        return StatementRegistration(
            receipt=receipt,
            entry_hash=entry_hash,
            leaf_index=leaf_index,
            tree_size=tree_size,
            entry_hash_scheme=scheme,
            checkpoint_witness=witness_info,
        )

    def _check_checkpoint_consistency(self, cp: dict) -> str:
        """Validate ``cp`` against the log's last witnessed checkpoint for
        ``cp['log_id']``. Returns ``"first-seen"`` (nothing to be consistent
        with -- honestly graded, no continuity implied) or ``"witnessed"``.
        Raises ``RollbackError`` -- caller must not append/countersign on that
        path. Caller holds ``self._lock``.
        """
        prev = self._store.get_checkpoint_witness(cp["log_id"])
        if prev is None:
            return "first-seen"
        # Peak-consistency, given the accepted wire shape (no prev_root is
        # transmitted): the new checkpoint's prev_size must chain exactly from
        # the size we last witnessed, and mmr_size must strictly increase.
        # This is the strongest check available without re-deriving peaks
        # ourselves -- it rejects both a rollback (mmr_size not increasing)
        # and a fork/gap (prev_size pointing anywhere other than our last
        # witnessed state).
        if cp["prev_size"] != prev["mmr_size"] or cp["mmr_size"] <= prev["mmr_size"]:
            raise RollbackError(
                f"checkpoint for log_id={cp['log_id']!r} does not extend the last "
                f"witnessed checkpoint (witnessed mmr_size={prev['mmr_size']}, "
                f"submitted prev_size={cp['prev_size']}, mmr_size={cp['mmr_size']}) "
                "-- refusing to co-sign a rollback or fork"
            )
        return "witnessed"

    def witness_checkpoint(self, cp: dict) -> StatementRegistration:
        """Stateless checkpoint-only registration for ``POST /checkpoints``.

        ``cp`` is the output of ``checkpoint_cose.parse_and_verify_checkpoint_cose``
        (already structurally validated, with its COSE_Sign1 signature
        already independently verified by the caller) -- this method does
        not re-check either, it only registers.

        Dispatches as a bare digest (``bytes.fromhex(_checkpoint_digest(cp))``)
        through the SAME CT-log append/dedup/counter-sign path as
        ``POST /v1/digest``, so the digest bytes never decode as a
        COSE_Sign1 and ``register_signed_statement_full`` never runs
        ``_check_checkpoint_consistency`` -- STAGE 1 is deliberately
        stateless: no per-``log_id`` continuity, no rollback/fork check, no
        MMR math. That is what makes this route's guarantee "this exact
        checkpoint existed and was seen at this time", not "this stream
        wasn't rewritten" -- the latter is a stage-2 claim.

        STAGE-2 SEAM: ``cp`` already carries ``log_id``, ``mmr_size``,
        ``prev_size``, and ``root`` (== the existing ``mmr_root`` key
        elsewhere, just renamed) -- exactly the shape
        ``_check_checkpoint_consistency`` and ``_store.put_checkpoint_witness``
        already accept for the ``mmr-checkpoint`` payload path above. A
        stage-2 upgrade adds per-``log_id`` state to THIS route by calling
        those two (consistency check before the append, state commit after a
        successful one) -- additive, not a rewrite of this method or its
        storage/keying choices.
        """
        digest_hex = _checkpoint_digest(cp)
        return self.register_signed_statement_full(bytes.fromhex(digest_hex))

    def get_registered_statement(
        self, entry_hash: str
    ) -> tuple[bytes, int, int] | None:
        """Read-only lookup of a registered statement by its CT entry hash.

        Returns ``(receipt_bytes, leaf_index, tree_size)`` if a statement with
        ``entry_hash`` was previously registered, else ``None``. Purely a read —
        NEVER appends to the log (contrast ``register_signed_statement``, which
        registers on a miss). Backs the ``GET /v1/inclusion/{capsule_id}``
        resolve route so an unknown capsule_id yields a 404, not a new entry.
        """
        return self._store.get_statement(entry_hash)

    # --- inclusion proofs (TENANT ledger tree) -----------------------------
    def inclusion_proof(self, leaf_hashes: list[str], index: int) -> MerkleProof:
        """Build a Merkle inclusion proof for ``leaf_hashes[index]``.

        Over the TENANT ledger tree (engine-compatible Merkle semantics), NOT the CT log tree.
        A relying party uses this to prove a specific (encrypted) leaf is under
        a root the authority has anchored -- WITHOUT the authority ever seeing
        the leaf's plaintext. ``proof.root_hash`` should equal an anchored root.
        """
        return self._crypto.merkle_proof(leaf_hashes, index)

    def verify_inclusion_ledger(
        self, proof: MerkleProof, anchored_root_hash: str | None = None
    ) -> bool:
        """Verify a TENANT-ledger Merkle inclusion proof (engine-compatible Merkle semantics).

        If ``anchored_root_hash`` is given, also bind the proof to that exact
        root (so a valid proof under a *different* tree is rejected).
        """
        if not self._crypto.verify_merkle_proof(proof):
            return False
        return not (anchored_root_hash is not None and proof.root_hash != anchored_root_hash)

    # --- accessors ---------------------------------------------------------
    def authority_pubkey(self) -> bytes:
        return self._attestor.authority_pubkey()

    @property
    def attestor(self) -> AttestorService:
        return self._attestor
