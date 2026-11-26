"""accept_bundle: parse, withheld-payload enforcement (``none``, or
``selected`` disclosing nothing), digest binding, and the
registration-policy issuer check -- the key checked against is always the
one THIS instance's issuer allowlist pins for the requester id, never one a
caller supplies. Each negative case is a mutant of ``valid_bundle_raw`` -- the
fixture must accept cleanly (asserted first) so a broken mutant can't hide
behind a fixture that never worked."""

from __future__ import annotations

import copy
import json
import pathlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from capsule_anchor.countersign.bundle import Bundle, BundleRefused, accept_bundle, parse_bundle
from capsule_anchor.countersign.issuers import IssuerAllowlist

from .conftest import TEST_LEDGER_ID, sign_submission


DC = frozenset({"declared_count"})


def _accept(raw, issuer_allowlist, requester_key, disclosable_kinds=DC):
    rid, rkey, rsig = sign_submission(raw, requester_key)
    return accept_bundle(
        raw,
        issuer_allowlist,
        requester_id=rid,
        requester_key_hex=rkey,
        requester_signature_hex=rsig,
        disclosable_kinds=disclosable_kinds,
    )


def test_valid_bundle_is_accepted(valid_bundle_raw, issuer_allowlist, requester_key):
    bundle = _accept(valid_bundle_raw, issuer_allowlist, requester_key)
    assert isinstance(bundle, Bundle)
    assert bundle.completeness["payloads_mode"] == "none"


def test_payloads_present_is_refused(valid_bundle_raw, issuer_allowlist, requester_key):
    """A required case: any payload present -> refused."""
    mutated = copy.deepcopy(valid_bundle_raw)
    mutated["completeness"]["payloads_mode"] = "all"

    with pytest.raises(BundleRefused, match="payloads present"):
        parse_bundle(mutated)
    with pytest.raises(BundleRefused, match="payloads present"):
        _accept(mutated, issuer_allowlist, requester_key)


def test_payloads_present_mutant_red_then_green(valid_bundle_raw, issuer_allowlist, requester_key):
    """The mutant check: flip the condition, confirm the check actually
    flips to failure, then restore and re-verify green."""

    # RED: mutate payloads_mode to "all" -- must raise.
    red = copy.deepcopy(valid_bundle_raw)
    red["completeness"]["payloads_mode"] = "all"
    with pytest.raises(BundleRefused):
        _accept(red, issuer_allowlist, requester_key)
    # GREEN: restore -- must accept.
    _accept(valid_bundle_raw, issuer_allowlist, requester_key)


def test_disclosure_naming_no_record_is_refused(valid_bundle_raw, issuer_allowlist, requester_key):
    """A disclosures overlay may only name records in the bundle."""

    mutated = copy.deepcopy(valid_bundle_raw)
    mutated["disclosures"] = {"nope": {"agent_input": {}}}
    with pytest.raises(BundleRefused, match="not a record"):
        _accept(mutated, issuer_allowlist, requester_key)


def test_bad_bundle_version_or_kind_is_refused(valid_bundle_raw, issuer_allowlist, requester_key):
    mutated = copy.deepcopy(valid_bundle_raw)
    mutated["bundle_version"] = "1"
    with pytest.raises(BundleRefused, match="v2 Evidence Bundle"):
        _accept(mutated, issuer_allowlist, requester_key)

    mutated = copy.deepcopy(valid_bundle_raw)
    mutated["bundle_kind"] = "evidence-bundle/v1"
    with pytest.raises(BundleRefused, match="v2 Evidence Bundle"):
        _accept(mutated, issuer_allowlist, requester_key)


def test_missing_root_is_refused(valid_bundle_raw, issuer_allowlist, requester_key):
    mutated = copy.deepcopy(valid_bundle_raw)
    del mutated["root"]
    with pytest.raises(BundleRefused, match="root"):
        _accept(mutated, issuer_allowlist, requester_key)


def test_content_tampered_after_signing_is_refused(valid_bundle_raw, issuer_allowlist, requester_key):
    """A requester's signature is over the digest at signing time -- if the
    bundle content changes afterward (even a field the requester didn't
    touch), the freshly recomputed digest no longer matches what was signed
    and the signature fails to verify. There is no separate 'declared vs
    recomputed digest' step: the v2 bundle carries no digest field of its
    own, so every acceptance recomputes it fresh."""

    rid, rkey, rsig = sign_submission(valid_bundle_raw, requester_key)
    tampered = copy.deepcopy(valid_bundle_raw)
    tampered["completeness"]["closure_depth"] = 99
    with pytest.raises(BundleRefused, match="does not verify"):
        accept_bundle(tampered, issuer_allowlist, requester_id=rid, requester_key_hex=rkey, requester_signature_hex=rsig)


def test_tampered_signature_is_refused(valid_bundle_raw, issuer_allowlist, requester_key):
    rid, rkey, _ = sign_submission(valid_bundle_raw, requester_key)
    with pytest.raises(BundleRefused, match="does not verify"):
        accept_bundle(
            valid_bundle_raw, issuer_allowlist, requester_id=rid, requester_key_hex=rkey, requester_signature_hex="ff" * 64
        )


def test_unenrolled_issuer_is_refused(valid_bundle_raw, requester_key):
    """A requester id this instance's registration policy has never
    enrolled is refused -- there is no self-asserted-key fallback on this
    surface."""
    empty = IssuerAllowlist()
    with pytest.raises(BundleRefused, match="not enrolled"):
        _accept(valid_bundle_raw, empty, requester_key)


def test_issuer_pinned_to_a_different_key_is_refused(valid_bundle_raw, requester_key):
    """The allowlist enrolls TEST_LEDGER_ID, but under a key that is NOT the
    one that actually signed the submission -- refused on key mismatch,
    never falling back to whatever the requester claims."""
    other_pub = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    mismatched = IssuerAllowlist.from_list([{"ledger_id": TEST_LEDGER_ID, "pubkey_hex": other_pub.hex()}])
    with pytest.raises(BundleRefused, match="does not match the key"):
        _accept(valid_bundle_raw, mismatched, requester_key)


def test_malformed_bundle_shape_is_refused():
    with pytest.raises(BundleRefused):
        parse_bundle({"not": "a bundle"})
    with pytest.raises(BundleRefused):
        parse_bundle("not even a dict")  # type: ignore[arg-type]


# --- opt-in disclosure of declared_count payloads (capsule-engine#160, ruling (b)) ---


def test_declared_count_disclosure_is_accepted(issuer_allowlist, requester_key):
    from .conftest import declared_count_bundle_raw

    raw, cid = declared_count_bundle_raw()
    bundle = _accept(raw, issuer_allowlist, requester_key)
    assert bundle.raw["disclosures"][cid]["agent_input"] == {"declared_count": 2}
    assert bundle.completeness["payloads_mode"] == "none"


def test_empty_disclosures_overlay_is_accepted(valid_bundle_raw, issuer_allowlist, requester_key):
    mutated = copy.deepcopy(valid_bundle_raw)
    mutated["disclosures"] = {}
    _accept(mutated, issuer_allowlist, requester_key)


def test_disclosure_digest_mismatch_is_refused(issuer_allowlist, requester_key):
    from .conftest import declared_count_bundle_raw

    raw, cid = declared_count_bundle_raw()
    raw["disclosures"][cid]["agent_input"] = {"declared_count": 3}
    with pytest.raises(BundleRefused, match="does not match"):
        _accept(raw, issuer_allowlist, requester_key)


def test_disclosure_of_another_kind_is_refused(issuer_allowlist, requester_key):
    """Only declared_count payloads may be disclosed: a ``decide`` record's
    payload is refused even when it matches its sealed digest."""
    from .conftest import bundle_with_records, make_capsule

    payload = {"anything": 1}
    records = [make_capsule(1, "decide", agent_input=payload)]
    raw = bundle_with_records(records)
    raw["disclosures"] = {records[0]["capsule_id"]: {"agent_input": payload}}
    with pytest.raises(BundleRefused, match="only"):
        _accept(raw, issuer_allowlist, requester_key)


def test_disclosure_of_other_member_or_unknown_record_is_refused(issuer_allowlist, requester_key):
    from .conftest import declared_count_bundle_raw

    raw, cid = declared_count_bundle_raw()
    mutated = copy.deepcopy(raw)
    mutated["disclosures"][cid]["agent_output"] = {"x": 1}
    with pytest.raises(BundleRefused, match="exactly"):
        _accept(mutated, issuer_allowlist, requester_key)

    mutated = copy.deepcopy(raw)
    mutated["disclosures"]["deadbeef"] = {"agent_input": {}}
    with pytest.raises(BundleRefused, match="not a record"):
        _accept(mutated, issuer_allowlist, requester_key)

    mutated = copy.deepcopy(raw)
    mutated["disclosures"] = []
    with pytest.raises(BundleRefused, match="object"):
        _accept(mutated, issuer_allowlist, requester_key)


def test_disclosure_with_payloads_mode_all_is_still_refused(issuer_allowlist, requester_key):
    from .conftest import declared_count_bundle_raw

    raw, _ = declared_count_bundle_raw()
    raw["completeness"]["payloads_mode"] = "all"
    with pytest.raises(BundleRefused, match="payloads present"):
        _accept(raw, issuer_allowlist, requester_key)


@pytest.mark.parametrize("bad", [[], {}, 7])
def test_malformed_record_ids_and_kinds_are_refused_not_a_crash(
    bad, valid_bundle_raw, issuer_allowlist, requester_key
):
    """An unhashable or non-string capsule_id / action_type must be a clean
    BundleRefused, never a TypeError (which the router would answer with 500)."""
    mutated = copy.deepcopy(valid_bundle_raw)
    mutated["disclosures"] = {}
    mutated["records"].append({"capsule_id": bad})
    _accept(mutated, issuer_allowlist, requester_key)  # unnamed malformed record is ignored here

    mutated = copy.deepcopy(valid_bundle_raw)
    cid = mutated["records"][0]["capsule_id"]
    mutated["records"][0]["action_type"] = bad
    mutated["disclosures"] = {cid: {"agent_input": {}}}
    with pytest.raises(BundleRefused, match="only"):
        _accept(mutated, issuer_allowlist, requester_key)


def test_no_configured_kinds_refuses_any_disclosure(issuer_allowlist, requester_key):
    """Default deployment: no disclosable kinds are configured, so even a
    matching declared_count disclosure is refused."""
    from .conftest import declared_count_bundle_raw

    raw, _ = declared_count_bundle_raw()
    with pytest.raises(BundleRefused, match="only"):
        _accept(raw, issuer_allowlist, requester_key, disclosable_kinds=frozenset())
    # and no overlay at all is unaffected
    from .conftest import base_bundle_raw

    _accept(base_bundle_raw(), issuer_allowlist, requester_key, disclosable_kinds=frozenset())


# --- payloads_mode "selected": the withheld form a producer with records writes ---

_VECTORS = pathlib.Path(__file__).parent / "vectors"


def _capsulectl_withheld() -> dict:
    """capsulectl's real ``deal report --withheld`` bundle (evidencebook
    63f2d61; vectors/capsulectl-deal-withheld.md says how it was written)."""
    return json.loads((_VECTORS / "capsulectl-deal-withheld.json").read_text())


def test_capsulectl_withheld_bundle_is_accepted(issuer_allowlist, requester_key):
    raw = _capsulectl_withheld()
    assert raw["completeness"]["payloads_mode"] == "selected"
    assert "disclosures" not in raw
    bundle = _accept(raw, issuer_allowlist, requester_key)
    assert bundle.verification.graph_closure.status == "pass"
    assert bundle.verification.per_record_membership.status == "pass"


def test_selected_fixture_bundle_without_disclosures_is_accepted(valid_bundle_raw, issuer_allowlist, requester_key):
    raw = copy.deepcopy(valid_bundle_raw)
    raw["completeness"]["payloads_mode"] = "selected"
    _accept(raw, issuer_allowlist, requester_key)


@pytest.mark.parametrize("mode", ["all", "partial", "NONE", "", None, [], {}, ["selected"], True, 0])
def test_any_other_payloads_mode_is_refused(mode, issuer_allowlist, requester_key):
    raw = _capsulectl_withheld()
    raw["completeness"]["payloads_mode"] = mode
    with pytest.raises(BundleRefused, match="payloads present"):
        _accept(raw, issuer_allowlist, requester_key)


def test_missing_payloads_mode_is_refused(issuer_allowlist, requester_key):
    raw = _capsulectl_withheld()
    del raw["completeness"]["payloads_mode"]
    with pytest.raises(BundleRefused, match="payloads present"):
        _accept(raw, issuer_allowlist, requester_key)


@pytest.mark.parametrize(
    "member, value",
    [
        ("disclosures", {}),
        ("disclosure_record", "00" * 32),
        ("payloads", {"any": "member outside the v2 core"}),
    ],
)
def test_selected_with_a_disclosure_member_is_refused(member, value, issuer_allowlist, requester_key):
    """Even an empty overlay: a selected bundle discloses nothing here."""
    raw = _capsulectl_withheld()
    raw[member] = value
    with pytest.raises(BundleRefused, match="may disclose nothing"):
        _accept(raw, issuer_allowlist, requester_key, disclosable_kinds=frozenset({"fyi"}))


def test_selected_with_a_matching_disclosable_overlay_is_refused(issuer_allowlist, requester_key):
    """The opt-in agent_input overlay that ``none`` admits is refused under
    ``selected``, even for a disclosable kind whose digest matches."""
    from .conftest import declared_count_bundle_raw

    raw, _ = declared_count_bundle_raw()
    raw["completeness"]["payloads_mode"] = "selected"
    with pytest.raises(BundleRefused, match="may disclose nothing"):
        _accept(raw, issuer_allowlist, requester_key)


def test_selected_with_a_composed_member_bundle_is_refused(valid_bundle_raw, issuer_allowlist, requester_key):
    """composed/v1 nests whole member bundles, disclosures included."""
    raw = _capsulectl_withheld()
    child = copy.deepcopy(valid_bundle_raw)
    child["disclosures"] = {child["root"]: {"agent_input": {"secret": "x"}}}
    raw["extensions"]["composed/v1"] = {"members": [{"id": "m1", "outcome": "artifact", "bundle": child}]}
    with pytest.raises(BundleRefused, match="composed/v1"):
        _accept(raw, issuer_allowlist, requester_key)


def test_selected_with_non_object_extensions_is_refused(issuer_allowlist, requester_key):
    raw = _capsulectl_withheld()
    raw["extensions"] = ["producer-key/v1"]
    with pytest.raises(BundleRefused, match="extensions must be an object"):
        _accept(raw, issuer_allowlist, requester_key)
