"""resolve_entry_state: a required case: entry removed but the checkpoint is
independently authenticated -> bundle renders witnessed; unknown signer ->
unresolved signer -- plus the other three states. Directory resolution is by
``signer.key_id`` (full 64-hex), matching ``capsule-cli``'s Go verifier --
reconciled here (this module previously
resolved by ``signer.id``, a real cross-implementation divergence)."""

from __future__ import annotations

from capsule_anchor.countersign.bundle import parse_bundle
from capsule_anchor.countersign.verify import resolve_entry_state

from .conftest import base_bundle_raw


def test_entry_removed_but_checkpoint_authenticated_renders_witnessed():
    """Brief item 8, adapted: entry removed -> bundle renders witnessed --
    now keyed off the bundle's own independently-authenticated (COSE-signed)
    checkpoint rather than a removed ad-hoc ``receipts[]`` field."""
    bundle = parse_bundle(base_bundle_raw(authenticated_checkpoint=True))
    state = resolve_entry_state(bundle, countersignatures=[], directory={})
    assert state == "witnessed"


def test_no_entry_and_unauthenticated_checkpoint_renders_self_attested():
    bundle = parse_bundle(base_bundle_raw(authenticated_checkpoint=False))
    state = resolve_entry_state(bundle, countersignatures=[], directory={})
    assert state == "self-attested"


def test_unresolved_signer_when_key_id_not_in_directory():
    """Brief item 8: unknown signer -> unresolved signer."""
    bundle = parse_bundle(base_bundle_raw(authenticated_checkpoint=True))
    entry = {"signer": {"id": "did:web:stranger.example", "key_id": "abc"}, "independent": True}
    state = resolve_entry_state(bundle, countersignatures=[entry], directory={"known-key-id": {}})
    assert state == "unresolved signer"


def test_countersigned_when_signer_key_id_resolves_in_directory():
    bundle = parse_bundle(base_bundle_raw(authenticated_checkpoint=True))
    entry = {"signer": {"id": "did:web:known.example", "key_id": "abc"}, "independent": True}
    state = resolve_entry_state(bundle, countersignatures=[entry], directory={"abc": {"name": "Example"}})
    assert state == "countersigned"


def test_directory_resolves_by_key_id_not_by_signer_id():
    """The reconciliation itself: a directory row keyed by ``signer.id``
    (the OLD, divergent convention) must NOT resolve an entry -- only a row
    keyed by ``signer.key_id`` does."""
    bundle = parse_bundle(base_bundle_raw(authenticated_checkpoint=True))
    entry = {"signer": {"id": "did:web:known.example", "key_id": "abc"}, "independent": True}
    state = resolve_entry_state(
        bundle, countersignatures=[entry], directory={"did:web:known.example": {"name": "Example"}}
    )
    assert state == "unresolved signer"


def test_self_countersigned_when_not_independent():
    bundle = parse_bundle(base_bundle_raw(authenticated_checkpoint=True))
    entry = {"signer": {"id": "did:web:same-operator.example", "key_id": "abc"}, "independent": False}
    state = resolve_entry_state(bundle, countersignatures=[entry], directory={})
    assert state == "self-countersigned"


def test_real_countersign_not_hidden_behind_a_later_self_countersign():
    """A genuine, independent, resolved countersignature must never be
    hidden by a self-countersigned entry that comes after it -- every entry
    is considered, not just the last one."""
    bundle = parse_bundle(base_bundle_raw(authenticated_checkpoint=True))
    real = {"signer": {"id": "did:web:known.example", "key_id": "abc"}, "independent": True}
    self_entry = {"signer": {"id": "did:web:same-operator.example", "key_id": "def"}, "independent": False}
    state = resolve_entry_state(
        bundle,
        countersignatures=[real, self_entry],
        directory={"abc": {"name": "Example"}},
    )
    assert state == "countersigned"


def test_self_countersign_first_then_real_still_resolves_countersigned():
    """Order must not matter -- the best outcome wins regardless of position."""
    bundle = parse_bundle(base_bundle_raw(authenticated_checkpoint=True))
    self_entry = {"signer": {"id": "did:web:same-operator.example", "key_id": "def"}, "independent": False}
    real = {"signer": {"id": "did:web:known.example", "key_id": "abc"}, "independent": True}
    state = resolve_entry_state(
        bundle,
        countersignatures=[self_entry, real],
        directory={"abc": {"name": "Example"}},
    )
    assert state == "countersigned"
