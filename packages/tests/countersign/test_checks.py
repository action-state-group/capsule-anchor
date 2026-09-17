"""The five generic checks, recomputed over the canonical v2 Evidence
Bundle. Three of the five ([countersign-whole-bundle-shape]) always read
``not present`` for a v2 bundle -- the wire simply carries no checkpoint
history, no attestation window, and no per-record signer-key field for them
to operate on. ``range_membership`` delegates to the neutral library's real
CLL #13 range-proof / per-record inclusion-proof recompute, with mutant
checks on its negative (failed) path. ``profile_conformance`` is unchanged
in spirit, keyed on ``action_type`` (the real AAC Capsule field) instead of
the ad-hoc model's invented ``kind``.
"""

from __future__ import annotations

import copy

from capsule_anchor.countersign.bundle import parse_bundle
from capsule_anchor.countersign.checks import (
    cadence,
    chain_consistency,
    key_hygiene,
    profile_conformance,
    range_membership,
)
from capsule_anchor.countersign.policy import NullPolicyModule

from .conftest import bundle_with_records, make_capsule


def _bundle(raw: dict):
    return parse_bundle(raw)


# --- chain_consistency -- always not present for a v2 bundle -----------------


def test_chain_consistency_always_not_present(valid_bundle_raw):
    result = chain_consistency(_bundle(valid_bundle_raw))
    assert result.result == "not present"


# --- range_membership ---------------------------------------------------------


def test_range_membership_not_present_with_no_records():
    raw = {
        "bundle_version": "2",
        "bundle_kind": "evidence-bundle/v2",
        "root": "a" * 64,
        "records": [],
        "completeness": {"closure_depth": 2, "records_mode": "complete", "payloads_mode": "none", "missing": []},
    }
    result = range_membership(_bundle(raw))
    assert result.result == "not present"


def test_range_membership_not_checked_with_no_completeness_evidence():
    capsule = make_capsule(1)
    raw = {
        "bundle_version": "2",
        "bundle_kind": "evidence-bundle/v2",
        "root": capsule["capsule_id"],
        "records": [capsule],
        "completeness": {"closure_depth": 2, "records_mode": "complete", "payloads_mode": "none", "missing": []},
    }
    result = range_membership(_bundle(raw))
    assert result.result == "not checked"


def test_range_membership_inconclusive_when_structurally_sound_but_checkpoint_unauthenticated(valid_bundle_raw):
    """The fixture's checkpoint carries no ``cose`` field (this test suite
    never authenticates one) -- exactly the state a real ``capsulectl``
    -produced bundle is in today. Structurally sound, checkpoint authenticity
    unconfirmed: ``inconclusive``, never a bare ``established``."""
    result = range_membership(_bundle(valid_bundle_raw))
    assert result.result == "inconclusive"
    assert "checkpoint_unverified" in result.detail


def test_range_membership_failed_on_altered_body_digest_mutant_red_then_green(valid_bundle_raw):
    # GREEN first: the un-mutated bundle must reach its normal (inconclusive) verdict.
    assert range_membership(_bundle(valid_bundle_raw)).result == "inconclusive"

    # RED: corrupt an interior body digest -- the range proof can no longer
    # rebuild the committed root, and per-record membership must fail.
    red = copy.deepcopy(valid_bundle_raw)
    red["completeness_certificate"]["body_digests"][0] = "aa" * 32
    result = range_membership(_bundle(red))
    assert result.result == "failed"

    # GREEN again: restore.
    assert range_membership(_bundle(valid_bundle_raw)).result == "inconclusive"


def test_range_membership_failed_when_a_record_is_unbound(valid_bundle_raw):
    """A record present in ``records`` but missing from
    ``completeness_certificate.memberships`` (and not declared missing) is
    an unbound record -- failed, not silently ignored."""
    mutated = copy.deepcopy(valid_bundle_raw)
    extra = make_capsule(9)
    mutated["records"].append(extra)
    result = range_membership(_bundle(mutated))
    assert result.result == "failed"


# --- cadence -- always not present for a v2 bundle ----------------------------


def test_cadence_always_not_present(valid_bundle_raw):
    result = cadence(_bundle(valid_bundle_raw))
    assert result.result == "not present"


# --- key_hygiene -- always not present for a v2 bundle ------------------------


def test_key_hygiene_always_not_present(valid_bundle_raw):
    result = key_hygiene(_bundle(valid_bundle_raw))
    assert result.result == "not present"


# --- profile_conformance --------------------------------------------------------


def test_profile_conformance_not_present_with_no_records():
    raw = {
        "bundle_version": "2",
        "bundle_kind": "evidence-bundle/v2",
        "root": "a" * 64,
        "records": [],
        "completeness": {"closure_depth": 2, "records_mode": "complete", "payloads_mode": "none", "missing": []},
    }
    result = profile_conformance(_bundle(raw), "test/v0", NullPolicyModule())
    assert result.result == "not present"


def test_profile_conformance_not_checked_with_null_module(valid_bundle_raw):
    """The engine's own test double: zero coverage for every action_type."""
    result = profile_conformance(_bundle(valid_bundle_raw), "test/v0", NullPolicyModule())
    assert result.result == "not checked"
    assert "decide" in result.detail


def test_profile_conformance_established_with_full_coverage():
    from capsule_anchor.countersign.results import CheckResult

    class FullCoverageModule:
        def check(self, bundle, profile_id):
            kinds = {r["action_type"] for r in bundle.records}
            return [CheckResult(name=k, result="established", detail="") for k in kinds]

    raw = bundle_with_records([make_capsule(1, action_type="decide"), make_capsule(2, action_type="fyi")])
    result = profile_conformance(_bundle(raw), "test/v0", FullCoverageModule())
    assert result.result == "established"


def test_profile_conformance_inconclusive_with_partial_coverage():
    from capsule_anchor.countersign.results import CheckResult

    class PartialCoverageModule:
        def check(self, bundle, profile_id):
            return [CheckResult(name="decide", result="established", detail="")]

    raw = bundle_with_records([make_capsule(1, action_type="decide"), make_capsule(2, action_type="fyi")])
    result = profile_conformance(_bundle(raw), "test/v0", PartialCoverageModule())
    assert result.result == "inconclusive"
    assert "fyi" in result.detail
