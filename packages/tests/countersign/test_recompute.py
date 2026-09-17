"""recompute_statement: never short-circuits, always names its exclusions,
scope mirrors the request (``ledger_id``/``profile_id`` are request-layer
values now, never bundle fields -- the v2 Evidence Bundle carries neither an
issuer identity nor a profile object of its own)."""

from __future__ import annotations

import copy

from capsule_anchor.countersign.bundle import parse_bundle
from capsule_anchor.countersign.policy import NullPolicyModule
from capsule_anchor.countersign.recompute import recompute_statement


def test_recompute_runs_all_five_generic_checks_plus_module(valid_bundle_raw):
    bundle = parse_bundle(valid_bundle_raw)
    statement = recompute_statement(bundle, policy_module=NullPolicyModule(), ledger_id="ledger:test-001", profile_id="test/v0")

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


def test_recompute_never_short_circuits_on_a_failure(valid_bundle_raw):
    """Corrupt an interior body digest (a real recompute failure -- see
    ``checks.range_membership``) and confirm the OTHER checks still ran and
    were recorded -- not skipped because one failed."""
    mutated = copy.deepcopy(valid_bundle_raw)
    mutated["completeness_certificate"]["body_digests"][0] = "aa" * 32
    bundle = parse_bundle(mutated)
    statement = recompute_statement(bundle, policy_module=NullPolicyModule(), ledger_id="ledger:test-001", profile_id="test/v0")

    by_name = {c.name: c for c in statement.checks}
    assert by_name["range membership"].result == "failed"
    # Every other check still ran and produced a real result, not skipped.
    assert by_name["chain consistency"].result == "not present"
    assert by_name["cadence"].result == "not present"
    assert by_name["key hygiene"].result == "not present"
    assert len(statement.checks) == 5


def test_statement_exclusions_always_present(valid_bundle_raw):
    bundle = parse_bundle(valid_bundle_raw)
    statement = recompute_statement(bundle, policy_module=NullPolicyModule(), ledger_id="ledger:test-001", profile_id="test/v0")
    joined = " ".join(statement.exclusions).lower()
    assert "capture coverage" in joined
    assert "outcome correctness" in joined


def test_statement_scope_mirrors_request_not_bundle(valid_bundle_raw):
    bundle = parse_bundle(valid_bundle_raw)
    statement = recompute_statement(
        bundle, policy_module=NullPolicyModule(), ledger_id="ledger:some-requester", profile_id="test/v0"
    )
    assert statement.scope.ledger_id == "ledger:some-requester"
    assert statement.scope.closure_depth == bundle.closure_depth


def test_statement_carries_no_profile_field_on_the_wire(valid_bundle_raw):
    """[countersign-whole-bundle-shape]: capsulectl's Go CountersignStatement
    struct has no profile field, and the real request path decodes with
    DisallowUnknownFields() -- an extra field here is a hard decode failure
    for a genuine capsulectl client. Never re-add one."""
    bundle = parse_bundle(valid_bundle_raw)
    statement = recompute_statement(
        bundle, policy_module=NullPolicyModule(), ledger_id="ledger:some-requester", profile_id="test/v0"
    )
    assert "profile" not in statement.model_dump(mode="json")


def test_wire_dict_strips_fields_capsule_cli_has_no_struct_field_for(valid_bundle_raw):
    """[countersign-whole-bundle-shape], found by the live request-path round
    trip: capsulectl's Go CountersignStatement/CountersignCheck structs are
    {checks:[{name,result}], recomputed_at, scope} only -- no exclusions, no
    per-check detail, no profile. The real request path's strict decode
    (DisallowUnknownFields) rejects any of them. All three remain
    first-class fields on the internal Statement/CheckResult
    (recompute_statement's own return value keeps them) -- only the
    wire/signing projection (wire_dict) strips them."""
    bundle = parse_bundle(valid_bundle_raw)
    statement = recompute_statement(
        bundle, policy_module=NullPolicyModule(), ledger_id="ledger:some-requester", profile_id="test/v0"
    )
    # Internally, every check still carries its detail, and exclusions stand.
    assert all(c.detail for c in statement.checks)
    assert statement.exclusions

    wire = statement.wire_dict()
    assert set(wire) == {"checks", "recomputed_at", "scope"}
    for check in wire["checks"]:
        assert set(check) == {"name", "result"}

    # canonical_bytes() signs the WIRE projection -- what's signed matches
    # what's shown, byte for byte.
    import json

    assert statement.canonical_bytes() == json.dumps(
        wire, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
