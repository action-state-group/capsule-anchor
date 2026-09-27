# SPDX-License-Identifier: Apache-2.0
"""Verify a bundle's ``countersignatures[]`` entries and resolve the bundle's
countersignature state -- the derived word a verifier renders, never re-rolled
into a score. Companion to ``signer.py``: ``signer.py`` PRODUCES a
``countersignatures[]`` entry, this verifies one (or the absence of one) and
resolves it back into a state.

Each ``countersign/v1`` entry is verified before anything it says is used
(:func:`verify_entry`):

1. ``over`` must equal the bundle digest, recomputed from the bundle itself;
2. ``signature`` must verify under ``signer.key_id`` over the signing input
   ``UTF8(JCS({"over", "signer", "statement", "type"}))`` -- a rewritten
   ``signer.id`` fails it as surely as a rewritten result
   (``signer.countersign_signing_input``);
3. independence is computed here, by comparing ``signer.key_id`` with the
   producer keys the caller supplies. The entry's own ``independent`` member
   is never read.

Per-entry states:
  invalid               -- ``over`` differs, or the signature fails (or is
                           malformed). Nothing the entry says is used.
  unverified            -- an entry of a type this module does not verify
  self-countersigned    -- valid, and the signer key is one of the producer's
  unresolved signer      -- valid, independent, and the signer key_id is not
                           in the supplied directory
  countersigned          -- valid, independent, and the signer key_id resolves
                           in the supplied directory

Bundle-level states add two for a bundle with no entries at all:
  self-attested        -- the bundle's own checkpoint carries no independently
                           authenticated (witness-signed COSE) evidence
  witnessed             -- the bundle's checkpoint DOES carry independently
                           authenticated evidence
                           (``bundle.verification.interval_coverage`` passes
                           with no ``checkpoint_unverified`` finding -- the
                           free, permissive-policy grade)

Directory resolution is BY ``signer.key_id`` (a full 64-hex Ed25519 public
key), never by ``signer.id`` -- matching ``capsule-cli``'s Go verifier
(``resolveSigner`` matches a directory row's ``key_ids[]``).
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from capsule_anchor.countersign.bundle import Bundle, compute_bundle_digest
from capsule_anchor.countersign.signer import COUNTERSIGN_ENTRY_TYPE, countersign_signing_input

_KEY_HEX = re.compile(r"[0-9a-f]{64}")
_SIGNATURE_HEX = re.compile(r"[0-9a-f]{128}")

# Best-outcome ranking across every entry in countersignatures[] -- matches
# the Go verifier's all-entries semantics: a real, independent, resolved
# countersignature always wins, even if an invalid, self-countersigned or
# unresolved entry sits elsewhere in the list. A bundle whose every entry is
# invalid resolves to "invalid", never to the no-entry states.
_ENTRY_RANK = {
    "invalid": 0,
    "unverified": 1,
    "self-countersigned": 2,
    "unresolved signer": 3,
    "countersigned": 4,
}


def _signature_valid(entry: dict, digest: str) -> bool:
    signer = entry.get("signer")
    key_id = signer.get("key_id") if isinstance(signer, dict) else None
    signature = entry.get("signature")
    if not isinstance(key_id, str) or not _KEY_HEX.fullmatch(key_id):
        return False
    if not isinstance(signature, str) or not _SIGNATURE_HEX.fullmatch(signature):
        return False
    if entry.get("over") != digest or "statement" not in entry:
        return False
    try:
        message = countersign_signing_input(
            entry["over"], signer, entry["statement"], entry.get("type") or COUNTERSIGN_ENTRY_TYPE
        )
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_id)).verify(bytes.fromhex(signature), message)
    except (InvalidSignature, TypeError, ValueError):
        return False
    return True


def verify_entry(
    bundle: Bundle,
    entry: dict,
    *,
    producer_key_ids: Iterable[str],
    directory: dict[str, dict] | None = None,
) -> str:
    """Verify one ``countersignatures[]`` entry against ``bundle`` and return
    its state (see the module docstring). ``producer_key_ids`` are the
    producer's own keys (64-hex Ed25519 public keys) the caller trusts; the
    v2 bundle carries no producer identity of its own. ``directory`` maps a
    resolvable signer ``key_id`` to its directory row."""
    if not isinstance(entry, dict):
        return "invalid"
    entry_type = entry.get("type")
    if entry_type is not None and entry_type != COUNTERSIGN_ENTRY_TYPE:
        return "unverified"
    if not _signature_valid(entry, compute_bundle_digest(bundle)):
        return "invalid"
    key_id = entry["signer"]["key_id"]
    if key_id in {k.lower() for k in producer_key_ids}:
        return "self-countersigned"
    if key_id not in {k.lower() for k in (directory or {})}:
        return "unresolved signer"
    return "countersigned"


def _witnessed(bundle: Bundle) -> bool:
    interval = bundle.verification.interval_coverage
    return interval.status == "pass" and "checkpoint_unverified" not in interval.findings


def resolve_entry_state(
    bundle: Bundle,
    countersignatures: list[dict],
    *,
    producer_key_ids: Iterable[str],
    directory: dict[str, dict] | None = None,
) -> str:
    """``countersignatures`` is the bundle's own ``countersignatures[]``
    list (possibly empty -- an entry can be removed without touching the
    rest of the bundle). Every entry is verified with :func:`verify_entry`
    and the best outcome wins -- a genuine independent countersignature is
    never hidden behind another entry, and an entry that fails verification
    never counts for anything.

    ``producer_key_ids`` are the producer's keys the caller trusts. It is
    required: independence is always computed here, never read off the wire. ``directory``
    maps a resolvable signer ``key_id`` (hex) to its public
    countersigner-directory row; absent/None means nothing resolves.
    """
    if not countersignatures:
        return "witnessed" if _witnessed(bundle) else "self-attested"
    producer_key_ids = list(producer_key_ids)
    states = (
        verify_entry(bundle, entry, producer_key_ids=producer_key_ids, directory=directory)
        for entry in countersignatures
    )
    return max(states, key=lambda state: _ENTRY_RANK[state])
