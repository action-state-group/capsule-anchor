"""Tests for the checkpoint-only witness surface on POST /v1/checkpoint.

STAGE 1 of the CLL (Checkpointed Local Log,
draft-mih-scitt-checkpointed-local-log) checkpoint witness: a SEPARATE,
stricter surface from the ``mmr-checkpoint`` artifact_type recognition on
``/transparency/register-statement`` (see ``test_checkpoint_witness.py``).

This surface:
  * accepts the CLL ``CheckpointRecord`` wire shape verbatim (not wrapped in
    a COSE_Sign1) and refuses anything else with a named error (400);
  * verifies the checkpoint's own Ed25519 signature server-side before ever
    counter-signing -- 401 on failure, never appended/counter-signed;
  * is STATELESS: no per-log_id monotonicity/rollback/chain-linkage check,
    no MMR math -- existence-and-time evidence for one checkpoint only.
"""
from __future__ import annotations

import hashlib
import json

import pytest
from capsule_anchor.app import create_app
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient


def _signing_body(cp: dict) -> bytes:
    fields = (
        "v",
        "kind",
        "log_id",
        "mmr_size",
        "root",
        "prev_size",
        "prev_root",
        "key_id",
        "timestamp",
    )
    body = {k: cp[k] for k in fields}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def _digest(cp: dict) -> str:
    return hashlib.sha256(_signing_body(cp)).hexdigest()


def _checkpoint(
    key: Ed25519PrivateKey,
    *,
    log_id: str,
    mmr_size: int,
    prev_size: int,
    root: str | None = None,
    prev_root: str = "",
    key_id: str | None = None,
    timestamp: str = "2026-08-26T00:00:00Z",
    kind: str = "mmr_checkpoint",
    v: int = 1,
) -> dict:
    cp = {
        "v": v,
        "kind": kind,
        "log_id": log_id,
        "mmr_size": mmr_size,
        "root": root or ("a" * 64),
        "prev_size": prev_size,
        "prev_root": prev_root,
        "key_id": key_id or key.public_key().public_bytes_raw().hex(),
        "timestamp": timestamp,
    }
    digest = _digest(cp)
    cp["signature"] = key.sign(digest.encode("ascii")).hex()
    return cp


@pytest.fixture()
def key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture()
def client():
    return TestClient(create_app())


def _register(client: TestClient, cp: dict) -> tuple[int, dict]:
    resp = client.post("/v1/checkpoint", json=cp)
    return resp.status_code, (resp.json() if resp.content else {})


# --- accepted path -----------------------------------------------------------


def test_checkpoint_accepted_returns_stamp(client, key):
    cp = _checkpoint(key, log_id="log-A", mmr_size=100, prev_size=0)
    status, body = _register(client, cp)
    assert status == 200, body
    assert body["entry_hash"] == hashlib.sha256(bytes.fromhex(_digest(cp))).hexdigest()
    assert body["entry_hash_scheme"] == "legacy"
    assert body["leaf_index"] == 0
    assert body["tree_size"] == 1
    assert body["receipt_b64"]


def test_resubmitting_the_same_checkpoint_is_idempotent(client, key):
    cp = _checkpoint(key, log_id="log-B", mmr_size=50, prev_size=0)
    s1, b1 = _register(client, cp)
    s2, b2 = _register(client, cp)
    assert s1 == s2 == 200
    assert b1["entry_hash"] == b2["entry_hash"]
    assert b1["leaf_index"] == b2["leaf_index"]


# --- checkpoint-only gate: reject non-checkpoint artifacts --------------------


def test_bare_digest_artifact_refused_with_named_error(client):
    """A plain capsule digest (the /v1/digest shape) is not a checkpoint."""
    status, body = _register(client, {"capsule_id": "b" * 64})
    assert status == 400
    assert "checkpoint" in body["detail"].lower()


def test_missing_required_field_refused_400(client, key):
    cp = _checkpoint(key, log_id="log-C", mmr_size=10, prev_size=0)
    del cp["mmr_size"]
    status, body = _register(client, cp)
    assert status == 400
    assert "mmr_size" in body["detail"]


def test_wrong_kind_refused_400(client, key):
    cp = _checkpoint(key, log_id="log-D", mmr_size=10, prev_size=0, kind="offer_terms")
    status, body = _register(client, cp)
    assert status == 400
    assert "kind" in body["detail"].lower()


def test_malformed_root_refused_400(client, key):
    cp = _checkpoint(key, log_id="log-E", mmr_size=10, prev_size=0, root="not-hex")
    status, body = _register(client, cp)
    assert status == 400


def test_prev_size_not_less_than_mmr_size_refused_400(client, key):
    cp = _checkpoint(key, log_id="log-F", mmr_size=10, prev_size=10)
    status, body = _register(client, cp)
    assert status == 400


def test_non_object_body_refused_400(client):
    status, body = _register(client, ["not", "an", "object"])
    assert status in (400, 422)


# --- signature verification ---------------------------------------------------


def test_invalid_signature_refused_401_and_never_countersigned(client, key):
    cp = _checkpoint(key, log_id="log-G", mmr_size=100, prev_size=0)
    cp["mmr_size"] = 999  # tamper after signing
    sth_before = client.get("/anchor/sth")
    status, body = _register(client, cp)
    assert status == 401, body
    assert "signature" in body["detail"].lower()
    # nothing appended: STH still empty (log was untouched by the refusal)
    sth_after = client.get("/anchor/sth")
    assert sth_before.status_code == sth_after.status_code == 503


def test_signature_by_wrong_key_refused_401(client, key):
    other_key = Ed25519PrivateKey.generate()
    cp = _checkpoint(key, log_id="log-H", mmr_size=10, prev_size=0)
    # key_id claims a DIFFERENT key than the one that actually signed
    cp["key_id"] = other_key.public_key().public_bytes_raw().hex()
    status, body = _register(client, cp)
    assert status == 401, body


def test_malformed_key_id_refused_401_not_500(client, key):
    cp = _checkpoint(key, log_id="log-I", mmr_size=10, prev_size=0, key_id="not-a-valid-pubkey")
    status, body = _register(client, cp)
    assert status == 401, body


# --- statelessness: no MMR math, no per-log_id continuity check --------------


def test_stateless_no_rollback_check_across_same_log_id(client, key):
    """Unlike /transparency/register-statement's mmr-checkpoint path, this
    surface does NOT track per-log_id state -- a checkpoint that would be a
    rollback/fork against a prior one for the SAME log_id is still accepted
    (each checkpoint is judged only on its own signature), because stage 1
    is stateless by design."""
    cp1 = _checkpoint(key, log_id="log-J", mmr_size=100, prev_size=0)
    s1, b1 = _register(client, cp1)
    assert s1 == 200, b1

    # A "rollback" shape (mmr_size smaller than the previous submission for
    # the same log_id) — would 409 on the stateful surface, but this route
    # never consults or stores per-log_id state.
    cp2 = _checkpoint(key, log_id="log-J", mmr_size=50, prev_size=0, timestamp="2026-08-26T00:05:00Z")
    s2, b2 = _register(client, cp2)
    assert s2 == 200, b2
    assert b2["leaf_index"] != b1["leaf_index"]


def test_two_valid_checkpoints_get_distinct_leaves(client, key):
    cp1 = _checkpoint(key, log_id="log-K", mmr_size=10, prev_size=0)
    cp2 = _checkpoint(
        key,
        log_id="log-K",
        mmr_size=20,
        prev_size=10,
        prev_root="b" * 64,
        timestamp="2026-08-26T00:10:00Z",
    )
    s1, b1 = _register(client, cp1)
    s2, b2 = _register(client, cp2)
    assert s1 == s2 == 200
    assert b1["entry_hash"] != b2["entry_hash"]
    assert b1["leaf_index"] != b2["leaf_index"]
