# SPDX-License-Identifier: Apache-2.0
"""JSON ``CheckpointRecord`` acceptance for ENROLLED checkpoint submitters
whose own pipeline mints the CLL checkpoint as deterministic JSON + a bare
Ed25519 signature, not the [cll-checkpoint-cose-wire] COSE_Sign1 envelope
(``checkpoint_cose.py``).

This is NARROWER than the retired plain-JSON path this witness used to run
(see ``git log --grep 'verify COSE-wire CLL checkpoints on /checkpoints, not
JSON'`` -- that surface trusted a self-asserted ``key_id`` for ANY ``log_id``
and was retired for exactly that reason). This module reopens JSON
acceptance ONLY for a ``log_id`` that is BOTH enrolled in the submitter
allowlist AND has DECLARED ``wire_form: json-ed25519`` there
(``submitters.py``) -- every other ``log_id`` gets a named rejection here,
never a fallback to trusting whatever key the JSON body itself claims. The
signature is always verified against the entry's PINNED ``pubkey``, never
against the submitted ``key_id`` field (which is carried through to the
returned record unmodified -- it is part of the signed body, so it cannot be
forged independent of holding the pinned private key, but it is never used
to SELECT the verification key).

Field NAMES are read via the entry's ``field_map`` (``our canonical name ->
submitter's JSON key``, config-driven, defaulting to the identity mapping --
see ``submitters.py``) so a submitter using different JSON key names never
needs a code change here, and this module never guesses at what a
submitter's field is called.

Returns the SAME 9-field + ``grade`` dict shape ``checkpoint_cose.
parse_and_verify_checkpoint_cose`` returns, so ``router.py`` can feed either
straight into the unchanged ``AnchorerService.witness_checkpoint`` /
``_checkpoint_digest`` path. Unlike the COSE path, a ``json-ed25519``
checkpoint's ``root``/``prev_root`` are the submitter's OWN opaque
commitment (e.g. a bagged MMR root computed by THEIR accumulator) -- this
module never attempts to reconstruct or cross-check them against our
peak-list fold (``checkpoint_cose._root_from_peaks``); that would be
comparing two different commitment schemes as if they were one (see
``submitters.py``'s ``accumulator``/grade docstring and
``cross_witness_conformance.checker.check_checkpoint_wire``, which keeps the
same discipline on the read side).
"""
from __future__ import annotations

import json

from .service import CheckpointSignatureError, NotACheckpointError, _checkpoint_digest
from .submitters import (
    _JSON_CHECKPOINT_ALL_FIELDS,
    _JSON_CHECKPOINT_SIGNATURE_FIELD,
    _JSON_CHECKPOINT_SIGNING_FIELDS,
    WIRE_FORM_JSON_ED25519,
    SubmitterAllowlist,
    SubmitterEntry,
)

#: HTTP Content-Type a caller declares to route ``POST /checkpoints`` here
#: instead of the (default, unchanged) COSE_Sign1 path -- see ``router.py``.
CLL_CHECKPOINT_JSON_CONTENT_TYPE = "application/cll-checkpoint+json"

_HEX_DIGITS = set("0123456789abcdefABCDEF")


def _is_hex_of_len(s: object, n_bytes: int) -> bool:
    return isinstance(s, str) and len(s) == n_bytes * 2 and all(c in _HEX_DIGITS for c in s)


def _extract_log_id(obj: dict, allowlist: SubmitterAllowlist) -> tuple[str, SubmitterEntry]:
    """Read the submitted ``log_id`` just far enough to resolve WHICH
    entry's ``field_map`` to read every other field through -- mirrors
    ``checkpoint_cose._peek_unauthenticated_issuer``: this is a peek before
    verification, never trusted for anything beyond picking an entry, and
    the checkpoint is refused outright (not silently accepted open) if it
    doesn't resolve to an enrolled ``json-ed25519`` entry.

    Since ``field_map`` is entry-specific we cannot know a submitter's
    ``log_id`` KEY before knowing the entry -- so this scans every
    ``json-ed25519`` entry's declared ``log_id`` source key. In practice
    there is one enrolled JSON submitter at a time; this stays correct for
    more.
    """
    for entry in allowlist.entries_by_wire_form(WIRE_FORM_JSON_ED25519):
        key = entry.field_map["log_id"]
        if key in obj and obj[key] == entry.log_id:
            return entry.log_id, entry
    raise NotACheckpointError(
        "json checkpoint's log_id does not resolve to any enrolled json-ed25519 submitter "
        "-- json form is only accepted for an enrolled submitter that declares wire_form: "
        "json-ed25519 (see submitters.py); every other log_id must use the COSE_Sign1 wire"
    )


def parse_and_verify_checkpoint_json(json_bytes: bytes, *, allowlist: SubmitterAllowlist) -> dict:
    """Decode + independently verify a JSON CLL ``CheckpointRecord``,
    ENROLLED-submitter-only. See the module docstring for the security model.

    Order of checks (mirrors ``checkpoint_cose.parse_and_verify_checkpoint_cose``):

    1. Valid JSON object -- ``NotACheckpointError`` (400).
    2. ``log_id`` resolves to an enrolled ``json-ed25519`` entry --
       ``NotACheckpointError`` (400) otherwise. This is the checkpoint-only /
       enrolled-only gate: a non-enrolled or cose-declared ``log_id`` is
       refused here, before any signature check.
    3. Every required field present (via the entry's ``field_map``) and
       structurally valid -- ``NotACheckpointError`` (400).
    4. Ed25519 signature verified against the entry's PINNED ``pubkey``
       (never the submitted ``key_id``) over ``_checkpoint_digest`` of the
       9-field signing body -- ``CheckpointSignatureError`` (401) on
       failure, never counter-signed.
    """
    try:
        obj = json.loads(json_bytes)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise NotACheckpointError(f"checkpoint submission is not valid JSON: {exc}") from exc
    if not isinstance(obj, dict):
        raise NotACheckpointError("json checkpoint submission must be a JSON object")

    _, entry = _extract_log_id(obj, allowlist)
    fm = entry.field_map

    missing = [our_key for our_key in _JSON_CHECKPOINT_ALL_FIELDS if fm[our_key] not in obj]
    if missing:
        their_names = [fm[k] for k in missing]
        raise NotACheckpointError(
            f"json checkpoint missing required field(s) {their_names} "
            f"(mapped from {missing} via this submitter's declared field_map)"
        )

    raw = {our_key: obj[fm[our_key]] for our_key in _JSON_CHECKPOINT_ALL_FIELDS}

    v, kind, log_id, mmr_size, root, prev_size, prev_root, key_id, timestamp, signature = (
        raw["v"],
        raw["kind"],
        raw["log_id"],
        raw["mmr_size"],
        raw["root"],
        raw["prev_size"],
        raw["prev_root"],
        raw["key_id"],
        raw["timestamp"],
        raw[_JSON_CHECKPOINT_SIGNATURE_FIELD],
    )

    if isinstance(v, bool) or not isinstance(v, int) or v < 1:
        raise NotACheckpointError("v must be a positive integer")
    if kind != "mmr_checkpoint":
        raise NotACheckpointError(f"kind must be 'mmr_checkpoint', got {kind!r}")
    if log_id != entry.log_id:
        # Defensive only: _extract_log_id already matched this exact value
        # via the same field_map/key -- a mismatch here means something
        # upstream (the object) changed between the peek and this re-read,
        # which cannot happen for a plain dict, but stay explicit.
        raise NotACheckpointError(f"log_id {log_id!r} does not match resolved submitter {entry.log_id!r}")
    if not isinstance(key_id, str) or not key_id:
        raise NotACheckpointError("key_id must be a non-empty string")
    if not _is_hex_of_len(root, 32):
        raise NotACheckpointError("root must be a 64-char hex string (32 bytes)")
    if isinstance(mmr_size, bool) or not isinstance(mmr_size, int) or mmr_size <= 0:
        raise NotACheckpointError("mmr_size must be a positive integer")
    if isinstance(prev_size, bool) or not isinstance(prev_size, int) or prev_size < 0:
        raise NotACheckpointError("prev_size must be a non-negative integer")
    if prev_size >= mmr_size:
        raise NotACheckpointError(f"prev_size ({prev_size}) must be strictly less than mmr_size ({mmr_size})")
    if prev_size == 0:
        if prev_root not in ("",) and not _is_hex_of_len(prev_root, 32):
            raise NotACheckpointError("prev_root must be empty (first checkpoint) or 64-char hex")
    elif not _is_hex_of_len(prev_root, 32):
        raise NotACheckpointError("prev_root must be a 64-char hex string when prev_size > 0")
    if not isinstance(timestamp, str) or not timestamp:
        raise NotACheckpointError("timestamp must be a non-empty string")
    if not isinstance(signature, str) or not signature:
        raise NotACheckpointError("signature must be a non-empty string")
    try:
        signature_bytes = bytes.fromhex(signature)
    except ValueError as exc:
        raise NotACheckpointError(f"signature is not valid hex: {exc}") from exc

    cp = {
        "v": v,
        "kind": kind,
        "log_id": log_id,
        "mmr_size": mmr_size,
        "root": root.lower(),
        "prev_size": prev_size,
        "prev_root": prev_root.lower() if prev_root else "",
        "key_id": key_id,
        "timestamp": timestamp,
    }
    assert set(cp) == set(_JSON_CHECKPOINT_SIGNING_FIELDS)  # keep in lockstep with service._CHECKPOINT_RECORD_FIELDS

    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    digest = _checkpoint_digest(cp)
    try:
        Ed25519PublicKey.from_public_bytes(entry.pubkey).verify(signature_bytes, digest.encode("ascii"))
    except InvalidSignature as exc:
        raise CheckpointSignatureError(
            "json checkpoint signature does not verify under its pinned enrolled key"
        ) from exc

    cp["grade"] = entry.grade
    return cp
