"""resolve_entry_state: a required case: entry removed -> bundle
renders witnessed; unknown signer -> unresolved signer -- plus the other two
states."""

from __future__ import annotations

from capsule_anchor.countersign.bundle import Bundle
from capsule_anchor.countersign.verify import resolve_entry_state

from .conftest import base_bundle_raw


def _bundle_with_receipts(producer_key, has_receipts: bool) -> Bundle:
    raw = base_bundle_raw(producer_key)
    if has_receipts:
        raw["checkpoints"] = [
            {"log_id": "x", "key_id": "k", "mmr_size": 1, "prev_size": 0, "mmr_root": "a" * 64, "timestamp": "2026-09-01T00:00:00+00:00"}
        ]
        raw["receipts"] = [
            {"checkpoint_index": 0, "witness_id": "did:web:witness.example", "grade": "mmr-verified", "receipt_b64": "AAAA"}
        ]
    return Bundle.model_validate(raw)


def test_entry_removed_but_witness_receipts_present_renders_witnessed(producer_key):
    """Brief item 8: entry removed -> bundle renders witnessed."""
    bundle = _bundle_with_receipts(producer_key, has_receipts=True)
    state = resolve_entry_state(bundle, countersignatures=[], directory={})
    assert state == "witnessed"


def test_no_entry_and_no_receipts_renders_self_attested(producer_key):
    bundle = _bundle_with_receipts(producer_key, has_receipts=False)
    state = resolve_entry_state(bundle, countersignatures=[], directory={})
    assert state == "self-attested"


def test_unresolved_signer_when_not_in_directory(producer_key):
    """Brief item 8: unknown signer -> unresolved signer."""
    bundle = _bundle_with_receipts(producer_key, has_receipts=True)
    entry = {"signer": {"id": "did:web:stranger.example", "key_id": "abc"}, "independent": True}
    state = resolve_entry_state(bundle, countersignatures=[entry], directory={"did:web:known.example": {}})
    assert state == "unresolved signer"


def test_countersigned_when_signer_resolves_in_directory(producer_key):
    bundle = _bundle_with_receipts(producer_key, has_receipts=True)
    entry = {"signer": {"id": "did:web:known.example", "key_id": "abc"}, "independent": True}
    state = resolve_entry_state(bundle, countersignatures=[entry], directory={"did:web:known.example": {"name": "Example"}})
    assert state == "countersigned"


def test_self_countersigned_when_not_independent(producer_key):
    bundle = _bundle_with_receipts(producer_key, has_receipts=True)
    entry = {"signer": {"id": "did:web:same-operator.example", "key_id": "abc"}, "independent": False}
    state = resolve_entry_state(bundle, countersignatures=[entry], directory={})
    assert state == "self-countersigned"


def test_real_countersign_not_hidden_behind_a_later_self_countersign(producer_key):
    """A genuine, independent, resolved countersignature must never be
    hidden by a self-countersigned entry that comes after it -- every entry
    is considered, not just the last one."""
    bundle = _bundle_with_receipts(producer_key, has_receipts=True)
    real = {"signer": {"id": "did:web:known.example", "key_id": "abc"}, "independent": True}
    self_entry = {"signer": {"id": "did:web:same-operator.example", "key_id": "def"}, "independent": False}
    state = resolve_entry_state(
        bundle,
        countersignatures=[real, self_entry],
        directory={"did:web:known.example": {"name": "Example"}},
    )
    assert state == "countersigned"


def test_self_countersign_first_then_real_still_resolves_countersigned(producer_key):
    """Order must not matter -- the best outcome wins regardless of position."""
    bundle = _bundle_with_receipts(producer_key, has_receipts=True)
    self_entry = {"signer": {"id": "did:web:same-operator.example", "key_id": "def"}, "independent": False}
    real = {"signer": {"id": "did:web:known.example", "key_id": "abc"}, "independent": True}
    state = resolve_entry_state(
        bundle,
        countersignatures=[self_entry, real],
        directory={"did:web:known.example": {"name": "Example"}},
    )
    assert state == "countersigned"
