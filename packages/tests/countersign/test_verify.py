"""verify_entry / resolve_entry_state: every entry is verified (``over``
recomputed, signature over the countersign/v1 signing input) before it counts
for anything, and independence is computed from the caller's producer keys,
never read from the entry. Directory resolution is by ``signer.key_id``
(full 64-hex), matching ``capsule-cli``'s Go verifier."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from capsule_anchor.countersign.bundle import Bundle, parse_bundle
from capsule_anchor.countersign.signer import COUNTERSIGN_ENTRY_TYPE, countersign_signing_input
from capsule_anchor.countersign.verify import resolve_entry_state, verify_entry

from .conftest import base_bundle_raw

VECTOR = json.loads((Path(__file__).parent / "vectors" / "countersign-v1.json").read_text())

STATEMENT = {
    "checks": [{"name": "cadence", "result": "established"}, {"name": "range membership", "result": "failed"}],
    "recomputed_at": "2026-09-27T00:00:00Z",
    "scope": {"closure_depth": 2, "ledger_id": "ledger:test"},
}


def _key() -> tuple[Ed25519PrivateKey, str]:
    private = Ed25519PrivateKey.generate()
    return private, private.public_key().public_bytes_raw().hex()


def _entry(bundle: Bundle, private: Ed25519PrivateKey, key_id: str, **wire) -> dict:
    entry = {
        "type": COUNTERSIGN_ENTRY_TYPE,
        "signer": {"id": "did:web:countersign.example", "key_id": key_id},
        "over": bundle.digest,
        "statement": copy.deepcopy(STATEMENT),
    }
    entry["signature"] = private.sign(
        countersign_signing_input(entry["over"], entry["signer"], entry["statement"], entry["type"])
    ).hex()
    entry.update(wire)
    return entry


@pytest.fixture()
def bundle() -> Bundle:
    return parse_bundle(base_bundle_raw(authenticated_checkpoint=True))


def test_entry_removed_but_checkpoint_authenticated_renders_witnessed(bundle):
    assert resolve_entry_state(bundle, countersignatures=[], producer_key_ids=[], directory={}) == "witnessed"


def test_no_entry_and_unauthenticated_checkpoint_renders_self_attested():
    bundle = parse_bundle(base_bundle_raw(authenticated_checkpoint=False))
    assert resolve_entry_state(bundle, countersignatures=[], producer_key_ids=[], directory={}) == "self-attested"


def test_unresolved_signer_when_key_id_not_in_directory(bundle):
    private, key_id = _key()
    entry = _entry(bundle, private, key_id)
    state = resolve_entry_state(bundle, [entry], producer_key_ids=[], directory={"cd" * 32: {}})
    assert state == "unresolved signer"


def test_countersigned_when_signer_key_id_resolves_in_directory(bundle):
    private, key_id = _key()
    entry = _entry(bundle, private, key_id)
    state = resolve_entry_state(bundle, [entry], producer_key_ids=[], directory={key_id: {"name": "Example"}})
    assert state == "countersigned"


def test_directory_resolves_by_key_id_not_by_signer_id(bundle):
    """A directory row keyed by ``signer.id`` must NOT resolve an entry --
    only a row keyed by ``signer.key_id`` does."""
    private, key_id = _key()
    entry = _entry(bundle, private, key_id)
    state = resolve_entry_state(
        bundle, [entry], producer_key_ids=[], directory={"did:web:countersign.example": {"name": "Example"}}
    )
    assert state == "unresolved signer"


def test_self_countersigned_is_computed_from_producer_keys_not_the_wire(bundle):
    """The wire claims ``independent: true``; the signer key is the
    producer's own. The verifier's own comparison wins."""
    private, key_id = _key()
    entry = _entry(bundle, private, key_id, independent=True)
    state = resolve_entry_state(bundle, [entry], producer_key_ids=[key_id], directory={key_id: {"name": "Example"}})
    assert state == "self-countersigned"


def test_wire_independent_false_is_ignored(bundle):
    private, key_id = _key()
    entry = _entry(bundle, private, key_id, independent=False)
    state = resolve_entry_state(bundle, [entry], producer_key_ids=[], directory={key_id: {"name": "Example"}})
    assert state == "countersigned"


@pytest.mark.parametrize("order", ["real-first", "self-first"])
def test_real_countersign_not_hidden_behind_a_self_countersign(bundle, order):
    """Every entry is considered; the best outcome wins regardless of position."""
    real_private, real_key = _key()
    self_private, self_key = _key()
    real = _entry(bundle, real_private, real_key)
    self_entry = _entry(bundle, self_private, self_key)
    entries = [real, self_entry] if order == "real-first" else [self_entry, real]
    state = resolve_entry_state(bundle, entries, producer_key_ids=[self_key], directory={real_key: {"name": "Example"}})
    assert state == "countersigned"


def test_forged_entry_with_a_directory_key_is_invalid_not_countersigned(bundle):
    """An entry nobody signed -- a directory key_id, a garbage signature, and
    the wire claiming ``independent: true`` -- must never resolve."""
    key_id = "ab" * 32
    forged = {
        "type": "countersign/v1",
        "signer": {"id": "did:web:known.example", "key_id": key_id},
        "over": bundle.digest,
        "statement": {"checks": [{"name": "cadence", "result": "established"}]},
        "signature": "00" * 64,
        "independent": True,
    }
    state = resolve_entry_state(bundle, [forged], producer_key_ids=[], directory={key_id: {"name": "Example"}})
    assert state == "invalid"


def test_rewritten_result_is_invalid(bundle):
    private, key_id = _key()
    entry = _entry(bundle, private, key_id)
    entry["statement"]["checks"][1]["result"] = "established"
    assert verify_entry(bundle, entry, producer_key_ids=[], directory={key_id: {}}) == "invalid"


def test_over_for_another_bundle_is_invalid(bundle):
    other = parse_bundle(base_bundle_raw(2, authenticated_checkpoint=True))
    private, key_id = _key()
    entry = _entry(other, private, key_id)
    assert entry["over"] != bundle.digest
    assert verify_entry(bundle, entry, producer_key_ids=[], directory={key_id: {}}) == "invalid"


def test_uppercase_hex_is_invalid(bundle):
    private, key_id = _key()
    entry = _entry(bundle, private, key_id)
    entry["signature"] = entry["signature"].upper()
    assert verify_entry(bundle, entry, producer_key_ids=[], directory={key_id: {}}) == "invalid"


def test_unknown_type_is_unverified(bundle):
    private, key_id = _key()
    entry = _entry(bundle, private, key_id, type="cose-sign1")
    assert verify_entry(bundle, entry, producer_key_ids=[], directory={key_id: {}}) == "unverified"


def test_a_valid_entry_wins_over_an_invalid_one(bundle):
    private, key_id = _key()
    good = _entry(bundle, private, key_id)
    bad = copy.deepcopy(good)
    bad["statement"]["checks"][0]["result"] = "failed"
    state = resolve_entry_state(bundle, [bad, good], producer_key_ids=[], directory={key_id: {}})
    assert state == "countersigned"


def _vector_bundle() -> Bundle:
    return Bundle(raw=VECTOR["bundle"], digest=VECTOR["bundle_digest"])


def _vector_directory() -> dict:
    return {k: row for row in VECTOR["directory"]["countersigners"] for k in row["key_ids"]}


def test_golden_vector_entry_is_countersigned():
    state = verify_entry(
        _vector_bundle(),
        VECTOR["entry"],
        producer_key_ids=[VECTOR["producer_public_key_hex"]],
        directory=_vector_directory(),
    )
    assert state == "countersigned"


@pytest.mark.parametrize("case", VECTOR["negative"], ids=lambda c: c["name"])
def test_golden_vector_negatives(case):
    state = verify_entry(
        _vector_bundle(),
        case["entry"],
        producer_key_ids=[VECTOR["producer_public_key_hex"]],
        directory=_vector_directory(),
    )
    # This function does not check receipts; a receipt-only negative stays valid.
    assert state == ("invalid" if case["expect"]["signature"] == "invalid" else "countersigned")


def test_spoofed_signer_id_is_invalid(bundle):
    """``signer`` is inside the signing input: an entry whose ``signer.id``
    is rewritten after signing (to borrow another countersigner's name)
    fails its signature."""
    private, key_id = _key()
    entry = _entry(bundle, private, key_id)
    entry["signer"]["id"] = "did:web:someone-else.example"
    assert verify_entry(bundle, entry, producer_key_ids=[], directory={key_id: {}}) == "invalid"
