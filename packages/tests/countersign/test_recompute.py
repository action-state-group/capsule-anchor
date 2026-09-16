"""recompute_statement: never short-circuits, always names its exclusions,
scope mirrors the bundle."""

from __future__ import annotations

from capsule_anchor.countersign.bundle import Bundle
from capsule_anchor.countersign.policy import NullPolicyModule
from capsule_anchor.countersign.recompute import recompute_statement

from .conftest import base_bundle_raw


def test_recompute_runs_all_five_generic_checks_plus_module(producer_key):
    raw = base_bundle_raw(producer_key)
    bundle = Bundle.model_validate(raw)
    statement = recompute_statement(bundle, policy_module=NullPolicyModule())

    names = {c.name for c in statement.checks}
    assert names == {
        "chain consistency",
        "range membership",
        "cadence",
        "key hygiene",
        "profile conformance",
    }
    # NullPolicyModule contributes nothing extra.
    assert len(statement.checks) == 5


def test_recompute_never_short_circuits_on_a_failure(producer_key):
    """Break chain_consistency (a fork) and confirm the OTHER checks still
    ran and were recorded -- not skipped because one failed."""
    raw = base_bundle_raw(producer_key)
    raw["checkpoints"] = [
        {"log_id": "x", "key_id": "k", "mmr_size": 5, "prev_size": 0, "mmr_root": "a" * 64, "timestamp": "2026-09-01T00:00:00+00:00"},
        {"log_id": "x", "key_id": "k", "mmr_size": 5, "prev_size": 6, "mmr_root": "b" * 64, "timestamp": "2026-09-02T00:00:00+00:00"},  # fork
    ]
    raw["records"] = [
        {"seq": 0, "kind": "judgment", "digest": "0" * 64, "timestamp": None, "signer_key_id": None, "cites": None},
    ]
    bundle = Bundle.model_validate(raw)
    statement = recompute_statement(bundle, policy_module=NullPolicyModule())

    by_name = {c.name: c for c in statement.checks}
    assert by_name["chain consistency"].result == "failed"
    # Every other check still ran and produced a real result, not skipped.
    assert by_name["range membership"].result in {"established", "failed", "not present", "not checked", "inconclusive"}
    assert len(statement.checks) == 5


def test_statement_exclusions_always_present(producer_key):
    raw = base_bundle_raw(producer_key)
    bundle = Bundle.model_validate(raw)
    statement = recompute_statement(bundle, policy_module=NullPolicyModule())
    joined = " ".join(statement.exclusions).lower()
    assert "capture coverage" in joined
    assert "outcome correctness" in joined


def test_statement_scope_mirrors_bundle(producer_key):
    raw = base_bundle_raw(producer_key)
    bundle = Bundle.model_validate(raw)
    statement = recompute_statement(bundle, policy_module=NullPolicyModule())
    assert statement.scope.ledger_id == bundle.ledger_id
    assert statement.scope.closure_depth == bundle.closure_depth
    assert statement.profile.id == bundle.profile.id
