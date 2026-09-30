# SPDX-License-Identifier: Apache-2.0
"""Consistency-proof policy for ``POST /checkpoints``
(``CAPSULE_ANCHOR_REQUIRE_CONSISTENCY_PROOF`` = off | warn | enforce).

After a NATIVE CLL log's first accepted checkpoint, every later checkpoint
for that ``log_id`` is expected to carry a ``consistency_proof``:

* ``off``: a proof-less later checkpoint is registered, as before.
* ``warn`` (default): registered, but the refusal ``enforce`` would make is
  logged and counted per ``log_id``.
* ``enforce``: refused with 409, ``code: consistency_proof_required``.

Foreign accumulators (enrolled ``accumulator: foreign``, COSE or JSON wire)
are never subject to the policy: this witness cannot verify their
accumulator, so they send no proof and stay ``countersigned-observed``.
"""
from __future__ import annotations

import json
import logging

import pytest
from capsule_anchor.anchoring.router import configure_submitters, get_service
from capsule_anchor.anchoring.service import (
    CONSISTENCY_PROOF_POLICY_WARN,
    CONTINUITY_GRADE_FIRST_SEEN,
    CONTINUITY_GRADE_REGISTERED,
    CONTINUITY_GRADE_WITNESSED,
    DEFAULT_CONSISTENCY_PROOF_POLICY,
    AnchorerService,
)
from capsule_anchor.anchoring.submitters import (
    ACCUMULATOR_FOREIGN,
    ACCUMULATOR_NATIVE_MMR,
    GRADE_COUNTERSIGNED_OBSERVED,
    GRADE_MMR_VERIFIED,
    WIRE_FORM_COSE_SIGN1,
    WIRE_FORM_JSON_ED25519,
    SubmitterAllowlist,
)
from capsule_anchor.app import create_app
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from tests.test_checkpoint_continuity import _Log, _post_checkpoint, _proof_claim
from tests.test_checkpoint_json import _checkpoint as _json_checkpoint
from tests.test_checkpoint_witness import _build_statement
from tests.test_checkpoint_witness import _checkpoint as _legacy_checkpoint
from tests.test_checkpoint_witness import _register as _legacy_register

_ENV = "CAPSULE_ANCHOR_REQUIRE_CONSISTENCY_PROOF"
_JSON_CONTENT_TYPE = "application/cll-checkpoint+json"


@pytest.fixture()
def key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def _client(monkeypatch, policy: str | None) -> TestClient:
    if policy is None:
        monkeypatch.delenv(_ENV, raising=False)
    else:
        monkeypatch.setenv(_ENV, policy)
    return TestClient(create_app())


def _first_then_proofless(client: TestClient, key: Ed25519PrivateKey, log: _Log):
    """Accept a first checkpoint, then submit a clean extension WITHOUT a
    consistency_proof. Returns the second submission's (status, body)."""
    size1 = log.grow_leaves(2)
    status1, body1 = _post_checkpoint(
        client, log.checkpoint_cose(key, size=size1, prev_size=0, issued_at="2026-09-30T00:00:00Z")
    )
    assert status1 == 200, body1
    assert body1["continuity_grade"] == CONTINUITY_GRADE_FIRST_SEEN
    size2 = log.grow_leaves(2)
    return _post_checkpoint(
        client, log.checkpoint_cose(key, size=size2, prev_size=size1, issued_at="2026-09-30T00:05:00Z")
    )


# --- config ------------------------------------------------------------------


def test_default_policy_is_warn(monkeypatch):
    assert DEFAULT_CONSISTENCY_PROOF_POLICY == CONSISTENCY_PROOF_POLICY_WARN
    _client(monkeypatch, None)
    assert get_service().consistency_proof_policy == "warn"


def test_malformed_policy_fails_startup_closed(monkeypatch):
    monkeypatch.setenv(_ENV, "strict")
    with pytest.raises(RuntimeError, match=_ENV):
        create_app()


def test_service_rejects_unknown_policy():
    with pytest.raises(ValueError, match="consistency_proof_policy"):
        AnchorerService(consistency_proof_policy="strict")


# --- off -----------------------------------------------------------------------


def test_off_registers_proofless_checkpoint_without_counting(monkeypatch, key, caplog):
    client = _client(monkeypatch, "off")
    with caplog.at_level(logging.WARNING, logger="capsule_anchor"):
        status, body = _first_then_proofless(client, key, _Log("policy-off"))
    assert status == 200, body
    assert body["continuity_grade"] == CONTINUITY_GRADE_REGISTERED
    assert get_service().consistency_proof_would_refuse == {}
    assert "would-refuse" not in caplog.text


# --- warn ----------------------------------------------------------------------


def test_warn_registers_but_logs_and_counts_per_log_id(monkeypatch, key, caplog):
    client = _client(monkeypatch, "warn")
    log_a, log_b = _Log("policy-warn-A"), _Log("policy-warn-B")
    with caplog.at_level(logging.WARNING, logger="capsule_anchor"):
        status, body = _first_then_proofless(client, key, log_a)
        assert status == 200, body
        assert body["continuity_grade"] == CONTINUITY_GRADE_REGISTERED
        status, body = _first_then_proofless(client, key, log_b)
        assert status == 200, body
        # A second proof-less checkpoint on log A. The witness's chain tip
        # did not advance for the "registered" grade, so it still extends
        # the first accepted checkpoint.
        size3 = log_a.grow_leaves(2)
        status, body = _post_checkpoint(
            client,
            log_a.checkpoint_cose(key, size=size3, prev_size=3, issued_at="2026-09-30T00:10:00Z"),
        )
        assert status == 200, body
    assert get_service().consistency_proof_would_refuse == {"policy-warn-A": 2, "policy-warn-B": 1}
    assert caplog.text.count("consistency_proof_required would-refuse") == 3


def test_warn_does_not_count_a_checkpoint_that_carries_a_proof(monkeypatch, key):
    client = _client(monkeypatch, "warn")
    log = _Log("policy-warn-proof")
    size1 = log.grow_leaves(2)
    _post_checkpoint(client, log.checkpoint_cose(key, size=size1, prev_size=0, issued_at="2026-09-30T00:00:00Z"))
    size2 = log.grow_leaves(2)
    status, body = _post_checkpoint(
        client,
        log.checkpoint_cose(
            key, size=size2, prev_size=size1, issued_at="2026-09-30T00:05:00Z",
            consistency_proof=_proof_claim(log.proof(size1, size2)),
        ),
    )
    assert status == 200, body
    assert body["continuity_grade"] == CONTINUITY_GRADE_WITNESSED
    assert get_service().consistency_proof_would_refuse == {}


# --- enforce -------------------------------------------------------------------


def test_enforce_refuses_proofless_later_checkpoint_with_named_error(monkeypatch, key):
    client = _client(monkeypatch, "enforce")
    status, body = _first_then_proofless(client, key, _Log("policy-enforce"))
    assert status == 409, body
    detail = body["detail"]
    assert detail["code"] == "consistency_proof_required"
    assert detail["last_accepted_mmr_size"] == 3
    assert "consistency_proof" in detail["error"]
    assert "NEW log_id" in detail["error"]


def test_enforce_first_checkpoint_needs_no_proof(monkeypatch, key):
    client = _client(monkeypatch, "enforce")
    log = _Log("policy-enforce-first")
    size1 = log.grow_leaves(2)
    status, body = _post_checkpoint(
        client, log.checkpoint_cose(key, size=size1, prev_size=0, issued_at="2026-09-30T00:00:00Z")
    )
    assert status == 200, body
    assert body["continuity_grade"] == CONTINUITY_GRADE_FIRST_SEEN


def test_enforce_accepts_checkpoint_with_valid_proof(monkeypatch, key):
    client = _client(monkeypatch, "enforce")
    log = _Log("policy-enforce-proof")
    size1 = log.grow_leaves(2)
    _post_checkpoint(client, log.checkpoint_cose(key, size=size1, prev_size=0, issued_at="2026-09-30T00:00:00Z"))
    size2 = log.grow_leaves(2)
    status, body = _post_checkpoint(
        client,
        log.checkpoint_cose(
            key, size=size2, prev_size=size1, issued_at="2026-09-30T00:05:00Z",
            consistency_proof=_proof_claim(log.proof(size1, size2)),
        ),
    )
    assert status == 200, body
    assert body["continuity_grade"] == CONTINUITY_GRADE_WITNESSED


def test_enforce_idempotent_resubmission_of_first_checkpoint_still_accepted(monkeypatch, key):
    """Resubmitting an already-accepted checkpoint returns its original stamp;
    it is not a new checkpoint, so the policy does not apply."""
    client = _client(monkeypatch, "enforce")
    log = _Log("policy-enforce-resubmit")
    size1 = log.grow_leaves(2)
    cose1 = log.checkpoint_cose(key, size=size1, prev_size=0, issued_at="2026-09-30T00:00:00Z")
    status1, body1 = _post_checkpoint(client, cose1)
    status2, body2 = _post_checkpoint(client, cose1)
    assert status1 == status2 == 200
    assert body2["receipt_b64"] == body1["receipt_b64"]


# --- the reset case ---------------------------------------------------------------


def test_enforce_node_that_lost_state_must_start_a_new_log_id(monkeypatch, key):
    """A node that lost its local log state restarts its log from empty. Its
    new first checkpoint (prev_size 0) reuses the old log_id: the witness
    already holds a checkpoint for that log_id, so the node cannot prove
    continuity and is refused, and the message tells it to start a new
    log_id. The same node under a NEW log_id is accepted as first-seen."""
    client = _client(monkeypatch, "enforce")
    old = _Log("policy-reset-node")
    size1 = old.grow_leaves(4)
    status, body = _post_checkpoint(
        client, old.checkpoint_cose(key, size=size1, prev_size=0, issued_at="2026-09-30T00:00:00Z")
    )
    assert status == 200, body

    # State lost: a fresh, empty log under the SAME log_id.
    restarted = _Log("policy-reset-node")
    rsize = restarted.grow_leaves(1)
    status, body = _post_checkpoint(
        client, restarted.checkpoint_cose(key, size=rsize, prev_size=0, issued_at="2026-09-30T01:00:00Z")
    )
    assert status == 409, body
    detail = body["detail"]
    assert detail["code"] == "consistency_proof_required"
    assert "lost its local log state" in detail["error"]
    assert "must start a NEW log_id" in detail["error"]
    assert detail["last_accepted_mmr_size"] == size1

    # The same node, now under a new log_id: accepted as first-seen.
    fresh = _Log("policy-reset-node-2")
    fsize = fresh.grow_leaves(1)
    status, body = _post_checkpoint(
        client, fresh.checkpoint_cose(key, size=fsize, prev_size=0, issued_at="2026-09-30T01:00:00Z")
    )
    assert status == 200, body
    assert body["continuity_grade"] == CONTINUITY_GRADE_FIRST_SEEN


def test_warn_counts_the_reset_case(monkeypatch, key):
    client = _client(monkeypatch, "warn")
    old = _Log("policy-reset-warn")
    size1 = old.grow_leaves(4)
    _post_checkpoint(client, old.checkpoint_cose(key, size=size1, prev_size=0, issued_at="2026-09-30T00:00:00Z"))
    restarted = _Log("policy-reset-warn")
    rsize = restarted.grow_leaves(1)
    status, body = _post_checkpoint(
        client, restarted.checkpoint_cose(key, size=rsize, prev_size=0, issued_at="2026-09-30T01:00:00Z")
    )
    assert status == 200, body
    assert get_service().consistency_proof_would_refuse == {"policy-reset-warn": 1}


# --- foreign accumulators are exempt --------------------------------------------------


def _enroll(log_id: str, key: Ed25519PrivateKey, wire_form: str, accumulator: str) -> None:
    configure_submitters(
        SubmitterAllowlist.from_list(
            [
                {
                    "log_id": log_id,
                    "pubkey_hex": key.public_key().public_bytes_raw().hex(),
                    "accumulator": accumulator,
                    "wire_form": wire_form,
                }
            ]
        )
    )


def _enroll_foreign(log_id: str, key: Ed25519PrivateKey, wire_form: str) -> None:
    _enroll(log_id, key, wire_form, ACCUMULATOR_FOREIGN)


def test_enforce_exempts_foreign_accumulator_cose_wire(monkeypatch, key):
    client = _client(monkeypatch, "enforce")
    _enroll_foreign("foreign-cose/v1", key, WIRE_FORM_COSE_SIGN1)
    status, body = _first_then_proofless(client, key, _Log("foreign-cose/v1"))
    assert status == 200, body
    assert body["grade"] == GRADE_COUNTERSIGNED_OBSERVED
    assert body["continuity_grade"] == CONTINUITY_GRADE_REGISTERED


def test_enforce_exempts_foreign_accumulator_json_wire(monkeypatch, key):
    client = _client(monkeypatch, "enforce")
    _enroll_foreign("foreign-json/v1", key, WIRE_FORM_JSON_ED25519)
    headers = {"Content-Type": _JSON_CONTENT_TYPE}
    cp1 = _json_checkpoint(key, log_id="foreign-json/v1", mmr_size=1)
    resp1 = client.post("/checkpoints", content=json.dumps(cp1).encode(), headers=headers)
    assert resp1.status_code == 200, resp1.json()
    cp2 = _json_checkpoint(key, log_id="foreign-json/v1", mmr_size=3, prev_size=1, root="c" * 64)
    resp2 = client.post("/checkpoints", content=json.dumps(cp2).encode(), headers=headers)
    assert resp2.status_code == 200, resp2.json()
    assert resp2.json()["grade"] == GRADE_COUNTERSIGNED_OBSERVED
    assert get_service().consistency_proof_would_refuse == {}


def test_enforce_exempts_an_enrolled_native_mmr_json_submitter(monkeypatch, key):
    """The JSON wire form carries no consistency_proof, so a native_mmr
    submitter enrolled with it is never refused for the proof's absence."""
    client = _client(monkeypatch, "enforce")
    _enroll("native-json/v1", key, WIRE_FORM_JSON_ED25519, ACCUMULATOR_NATIVE_MMR)
    headers = {"Content-Type": _JSON_CONTENT_TYPE}
    cp1 = _json_checkpoint(key, log_id="native-json/v1", mmr_size=1)
    resp1 = client.post("/checkpoints", content=json.dumps(cp1).encode(), headers=headers)
    assert resp1.status_code == 200, resp1.json()
    cp2 = _json_checkpoint(key, log_id="native-json/v1", mmr_size=3, prev_size=1, root="c" * 64)
    resp2 = client.post("/checkpoints", content=json.dumps(cp2).encode(), headers=headers)
    assert resp2.status_code == 200, resp2.json()
    assert resp2.json()["grade"] == GRADE_MMR_VERIFIED
    assert resp2.json()["continuity_grade"] == CONTINUITY_GRADE_REGISTERED


# --- the mmr-checkpoint statement path on /transparency/register-statement ---------


def _legacy_first_then_second(client, key, log_id):
    s1, b1 = _legacy_register(client, _build_statement(_legacy_checkpoint(log_id, mmr_size=100, prev_size=0), key))
    assert s1 == 200, b1
    assert b1["checkpoint_witness"]["status"] == "first-seen"
    return _legacy_register(client, _build_statement(_legacy_checkpoint(log_id, mmr_size=250, prev_size=100), key))


def test_legacy_path_enforce_refuses_a_later_checkpoint_and_points_to_checkpoints(monkeypatch, key):
    client = _client(monkeypatch, "enforce")
    status, body = _legacy_first_then_second(client, key, "legacy-enforce")
    assert status == 409, body
    detail = body["detail"]
    assert detail["code"] == "consistency_proof_required"
    assert detail["last_accepted_mmr_size"] == 100
    assert "POST /checkpoints" in detail["error"]
    assert "NEW log_id" in detail["error"]


def test_legacy_path_warn_registers_but_logs_and_counts(monkeypatch, key, caplog):
    client = _client(monkeypatch, "warn")
    with caplog.at_level(logging.WARNING, logger="capsule_anchor"):
        status, body = _legacy_first_then_second(client, key, "legacy-warn")
    assert status == 200, body
    assert body["checkpoint_witness"]["status"] == "witnessed"
    assert get_service().consistency_proof_would_refuse == {"legacy-warn": 1}
    assert "consistency_proof_required would-refuse" in caplog.text


def test_legacy_path_off_registers_without_counting(monkeypatch, key):
    client = _client(monkeypatch, "off")
    status, body = _legacy_first_then_second(client, key, "legacy-off")
    assert status == 200, body
    assert get_service().consistency_proof_would_refuse == {}


def test_legacy_path_enforce_first_checkpoint_and_resubmission_accepted(monkeypatch, key):
    client = _client(monkeypatch, "enforce")
    stmt = _build_statement(_legacy_checkpoint("legacy-first", mmr_size=100, prev_size=0), key)
    s1, b1 = _legacy_register(client, stmt)
    s2, b2 = _legacy_register(client, stmt)
    assert s1 == s2 == 200
    assert b2["receipt_b64"] == b1["receipt_b64"]


def test_enforce_closes_the_bypass_through_the_legacy_path(monkeypatch, key):
    """A native log's proof-less checkpoint refused on POST /checkpoints must
    not register through the mmr-checkpoint statement path instead: both
    share the per-log_id tip."""
    client = _client(monkeypatch, "enforce")
    log = _Log("bypass-log")
    size1 = log.grow_leaves(2)
    status, body = _post_checkpoint(
        client, log.checkpoint_cose(key, size=size1, prev_size=0, issued_at="2026-09-30T00:00:00Z")
    )
    assert status == 200, body
    size2 = log.grow_leaves(2)
    status, body = _post_checkpoint(
        client, log.checkpoint_cose(key, size=size2, prev_size=size1, issued_at="2026-09-30T00:05:00Z")
    )
    assert status == 409, body

    legacy = _legacy_checkpoint(
        "bypass-log", mmr_size=size2, prev_size=size1, mmr_root=log.root_at(size2).hex()
    )
    status, body = _legacy_register(client, _build_statement(legacy, key))
    assert status == 409, body
    assert body["detail"]["code"] == "consistency_proof_required"
