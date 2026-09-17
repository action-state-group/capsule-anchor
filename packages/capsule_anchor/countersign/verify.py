# SPDX-License-Identifier: Apache-2.0
"""Resolve a bundle's countersignature state -- the derived word a verifier
renders, never re-rolled into a score. Companion to ``signer.py``:
``signer.py`` PRODUCES a ``countersignatures[]`` entry, this resolves one
(or the absence of one) back into a state.

Five states:
  self-attested        -- no countersignature entry, and the bundle's own
                           checkpoint carries no independently authenticated
                           (witness-signed COSE) evidence
  witnessed             -- no countersignatures[] entry, but the bundle's
                           checkpoint DOES carry independently authenticated
                           evidence (``bundle.verification.interval_coverage``
                           passes with no ``checkpoint_unverified`` finding --
                           the free, permissive-policy grade)
  self-countersigned    -- a countersignatures[] entry exists and its
                           signer key equals the requester's own key
                           (``independent: false``)
  unresolved signer      -- a countersignatures[] entry exists, is
                           independent, but its signer key_id is not present
                           in the supplied directory
  countersigned          -- a countersignatures[] entry exists, is
                           independent, and its signer key_id resolves in
                           the supplied directory

Directory resolution is BY ``signer.key_id`` (a full 64-hex Ed25519 public
key), never by ``signer.id`` -- matching ``capsule-cli``'s Go verifier
(``resolveSigner`` matches a directory row's ``key_ids[]``), reconciled here
per [countersign-whole-bundle-shape]: this module previously resolved by
``signer.id``, a divergence from the Go side that a real cross-implementation
directory lookup would have silently mismatched.
"""

from __future__ import annotations

from capsule_anchor.countersign.bundle import Bundle

# Best-outcome ranking across every entry in countersignatures[] -- matches
# the Go verifier's all-entries semantics (countersign.go's `rank` map): a
# real, independent, resolved countersignature always wins, even if a
# self-countersigned or unresolved entry sits later in the list.
_ENTRY_RANK = {"self-countersigned": 0, "unresolved signer": 1, "countersigned": 2}


def _entry_state(entry: dict, directory: dict[str, dict]) -> str:
    if entry.get("independent") is False:
        return "self-countersigned"
    key_id = entry.get("signer", {}).get("key_id")
    if key_id not in directory:
        return "unresolved signer"
    return "countersigned"


def _witnessed(bundle: Bundle) -> bool:
    interval = bundle.verification.interval_coverage
    return interval.status == "pass" and "checkpoint_unverified" not in interval.findings


def resolve_entry_state(
    bundle: Bundle,
    countersignatures: list[dict],
    *,
    directory: dict[str, dict] | None = None,
) -> str:
    """``countersignatures`` is the bundle's own ``countersignatures[]``
    list (possibly empty -- an entry can be removed without touching the
    rest of the bundle). ``directory`` maps a resolvable signer ``key_id``
    (hex) to its public countersigner-directory row; absent/None means
    nothing resolves.

    Every entry is considered, never just the last one -- a genuine
    independent countersignature must never be hidden behind a later
    self-countersigned (or unresolved) entry.
    """
    directory = directory or {}
    if not countersignatures:
        return "witnessed" if _witnessed(bundle) else "self-attested"
    states = (_entry_state(entry, directory) for entry in countersignatures)
    return max(states, key=lambda state: _ENTRY_RANK[state])
