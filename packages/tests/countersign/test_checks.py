"""The five generic checks, each result reachable, with mutant checks on
the negative (failed) paths -- flip the condition, confirm the check
actually flips to failure, then restore and re-verify green."""

from __future__ import annotations

import copy

from capsule_anchor.countersign.bundle import Bundle
from capsule_anchor.countersign.checks import (
    cadence,
    chain_consistency,
    key_hygiene,
    profile_conformance,
    range_membership,
)
from capsule_anchor.countersign.policy import NullPolicyModule

from .conftest import base_bundle_raw


def _bundle(raw: dict) -> Bundle:
    return Bundle.model_validate(raw)


def _checkpoint(log_id="ledger:test-001", key_id="kkkkkkkkkkkkkkkk", mmr_size=1, prev_size=0, root="a" * 64, ts="2026-09-01T00:00:00+00:00"):
    return {
        "log_id": log_id,
        "key_id": key_id,
        "mmr_size": mmr_size,
        "prev_size": prev_size,
        "mmr_root": root,
        "timestamp": ts,
    }


def _record(seq, kind="judgment", digest=None, ts=None, key_id=None, cites=None):
    return {
        "seq": seq,
        "kind": kind,
        "digest": digest or (f"{seq:064x}"),
        "timestamp": ts,
        "signer_key_id": key_id,
        "cites": cites,
    }


# --- chain_consistency ------------------------------------------------------


def test_chain_consistency_not_present_with_no_checkpoints(producer_key):
    raw = base_bundle_raw(producer_key)
    result = chain_consistency(_bundle(raw))
    assert result.result == "not present"


def test_chain_consistency_not_checked_with_one_checkpoint(producer_key):
    raw = base_bundle_raw(producer_key)
    raw["checkpoints"] = [_checkpoint(mmr_size=5, prev_size=0)]
    result = chain_consistency(_bundle(raw))
    assert result.result == "not checked"


def test_chain_consistency_established_when_chained(producer_key):
    raw = base_bundle_raw(producer_key)
    raw["checkpoints"] = [
        _checkpoint(mmr_size=5, prev_size=0),
        _checkpoint(mmr_size=9, prev_size=5),
        _checkpoint(mmr_size=14, prev_size=9),
    ]
    result = chain_consistency(_bundle(raw))
    assert result.result == "established"


def test_chain_consistency_failed_on_fork_mutant_red_then_green(producer_key):
    raw = base_bundle_raw(producer_key)
    good = [
        _checkpoint(mmr_size=5, prev_size=0),
        _checkpoint(mmr_size=9, prev_size=5),
    ]
    # GREEN first: the un-mutated chain must establish.
    raw["checkpoints"] = good
    assert chain_consistency(_bundle(raw)).result == "established"

    # RED: mutate the second checkpoint's prev_size off the first's mmr_size.
    broken = copy.deepcopy(good)
    broken[1]["prev_size"] = 6  # should be 5
    raw["checkpoints"] = broken
    result = chain_consistency(_bundle(raw))
    assert result.result == "failed"

    # RED: mutate mmr_size to not strictly increase (rollback).
    rollback = copy.deepcopy(good)
    rollback[1]["mmr_size"] = 5
    raw["checkpoints"] = rollback
    assert chain_consistency(_bundle(raw)).result == "failed"

    # GREEN again: restore.
    raw["checkpoints"] = good
    assert chain_consistency(_bundle(raw)).result == "established"


# --- range_membership --------------------------------------------------------


def test_range_membership_not_present_with_no_records(producer_key):
    raw = base_bundle_raw(producer_key)
    result = range_membership(_bundle(raw))
    assert result.result == "not present"


def test_range_membership_not_checked_with_no_checkpoints(producer_key):
    raw = base_bundle_raw(producer_key)
    raw["records"] = [_record(0), _record(1)]
    result = range_membership(_bundle(raw))
    assert result.result == "not checked"


def test_range_membership_established_contiguous(producer_key):
    raw = base_bundle_raw(producer_key)
    raw["records"] = [_record(0), _record(1), _record(2)]
    raw["checkpoints"] = [_checkpoint(mmr_size=3, prev_size=0)]
    result = range_membership(_bundle(raw))
    assert result.result == "established"


def test_range_membership_failed_on_gap_mutant_red_then_green(producer_key):
    raw = base_bundle_raw(producer_key)
    good_records = [_record(0), _record(1), _record(2)]
    raw["records"] = good_records
    raw["checkpoints"] = [_checkpoint(mmr_size=3, prev_size=0)]
    assert range_membership(_bundle(raw)).result == "established"

    # RED: drop the interior record (seq=1) -- a gap.
    raw["records"] = [_record(0), _record(2)]
    result = range_membership(_bundle(raw))
    assert result.result == "failed"
    assert "missing" in result.detail

    # RED: duplicate a sequence position.
    raw["records"] = [_record(0), _record(1), _record(1), _record(2)]
    result = range_membership(_bundle(raw))
    assert result.result == "failed"
    assert "duplicate" in result.detail

    # GREEN again.
    raw["records"] = good_records
    assert range_membership(_bundle(raw)).result == "established"


def test_range_membership_failed_outside_tip(producer_key):
    raw = base_bundle_raw(producer_key)
    raw["records"] = [_record(0), _record(1), _record(5)]
    raw["checkpoints"] = [_checkpoint(mmr_size=3, prev_size=0)]
    result = range_membership(_bundle(raw))
    assert result.result == "failed"


# --- cadence ------------------------------------------------------------------


def test_cadence_not_present_with_no_dated_records(producer_key):
    raw = base_bundle_raw(producer_key)
    result = cadence(_bundle(raw))
    assert result.result == "not present"


def test_cadence_established_when_spread_across_window(producer_key):
    raw = base_bundle_raw(producer_key)
    raw["period"] = {"from": "2026-09-01T00:00:00+00:00", "to": "2026-09-08T00:00:00+00:00"}
    raw["records"] = [
        _record(0, ts="2026-09-01T06:00:00+00:00"),
        _record(1, ts="2026-09-04T00:00:00+00:00"),
        _record(2, ts="2026-09-07T23:00:00+00:00"),
    ]
    result = cadence(_bundle(raw))
    assert result.result == "established"


def test_cadence_failed_when_batched_at_close_mutant_red_then_green(producer_key):
    raw = base_bundle_raw(producer_key)
    raw["period"] = {"from": "2026-09-01T00:00:00+00:00", "to": "2026-09-08T00:00:00+00:00"}
    spread = [
        _record(0, ts="2026-09-01T06:00:00+00:00"),
        _record(1, ts="2026-09-04T00:00:00+00:00"),
        _record(2, ts="2026-09-07T23:00:00+00:00"),
    ]
    raw["records"] = spread
    assert cadence(_bundle(raw)).result == "established"

    # RED: all judgments in the last hour of a
    # multi-day window.
    batched = [
        _record(0, ts="2026-09-07T23:00:00+00:00"),
        _record(1, ts="2026-09-07T23:20:00+00:00"),
        _record(2, ts="2026-09-07T23:59:00+00:00"),
    ]
    raw["records"] = batched
    result = cadence(_bundle(raw))
    assert result.result == "failed"

    # GREEN again.
    raw["records"] = spread
    assert cadence(_bundle(raw)).result == "established"


# --- key_hygiene ---------------------------------------------------------------


def test_key_hygiene_not_present_with_no_keyed_records(producer_key):
    raw = base_bundle_raw(producer_key)
    result = key_hygiene(_bundle(raw))
    assert result.result == "not present"


def test_key_hygiene_established_with_matching_rotation(producer_key):
    raw = base_bundle_raw(producer_key)
    raw["records"] = [
        _record(0, key_id="key-a"),
        _record(1, key_id="key-a"),
        _record(2, key_id="key-b"),
    ]
    raw["rotations"] = [{"seq": 2, "old_key_id": "key-a", "new_key_id": "key-b"}]
    result = key_hygiene(_bundle(raw))
    assert result.result == "established"


def test_key_hygiene_failed_on_unrotated_key_change_mutant_red_then_green(producer_key):
    raw = base_bundle_raw(producer_key)
    records = [
        _record(0, key_id="key-a"),
        _record(1, key_id="key-a"),
        _record(2, key_id="key-b"),
    ]
    rotations = [{"seq": 2, "old_key_id": "key-a", "new_key_id": "key-b"}]

    raw["records"] = records
    raw["rotations"] = rotations
    assert key_hygiene(_bundle(raw)).result == "established"

    # RED: drop the rotation record -- the key change is now unexplained.
    raw["rotations"] = []
    result = key_hygiene(_bundle(raw))
    assert result.result == "failed"

    # GREEN again.
    raw["rotations"] = rotations
    assert key_hygiene(_bundle(raw)).result == "established"


# --- profile_conformance --------------------------------------------------------


def test_profile_conformance_not_present_with_no_records(producer_key):
    raw = base_bundle_raw(producer_key)
    result = profile_conformance(_bundle(raw), NullPolicyModule())
    assert result.result == "not present"


def test_profile_conformance_not_checked_with_null_module(producer_key):
    """The engine's own test double: zero coverage for every kind."""
    raw = base_bundle_raw(producer_key)
    raw["records"] = [_record(0, kind="judgment"), _record(1, kind="method_freeze")]
    result = profile_conformance(_bundle(raw), NullPolicyModule())
    assert result.result == "not checked"


def test_profile_conformance_established_with_full_coverage(producer_key):
    from capsule_anchor.countersign.results import CheckResult

    class FullCoverageModule:
        def check(self, bundle, profile):
            kinds = {r.kind for r in bundle.records}
            return [CheckResult(name=k, result="established", detail="") for k in kinds]

    raw = base_bundle_raw(producer_key)
    raw["records"] = [_record(0, kind="judgment"), _record(1, kind="method_freeze")]
    result = profile_conformance(_bundle(raw), FullCoverageModule())
    assert result.result == "established"


def test_profile_conformance_inconclusive_with_partial_coverage(producer_key):
    from capsule_anchor.countersign.results import CheckResult

    class PartialCoverageModule:
        def check(self, bundle, profile):
            return [CheckResult(name="judgment", result="established", detail="")]

    raw = base_bundle_raw(producer_key)
    raw["records"] = [_record(0, kind="judgment"), _record(1, kind="method_freeze")]
    result = profile_conformance(_bundle(raw), PartialCoverageModule())
    assert result.result == "inconclusive"
    assert "method_freeze" in result.detail
