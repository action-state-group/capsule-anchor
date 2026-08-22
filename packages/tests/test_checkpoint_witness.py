"""Tests for the mmr-checkpoint WITNESS surface on POST /transparency/register-statement.

A checkpoint capsule is just a Signed Statement -- the SCITT registration path
anchors it with zero extra code. These tests cover the WITNESS behavior this
task adds: auto-recognizing a self-declared ``artifact_type: mmr-checkpoint``
payload, per-log_id monotonic-size + chain-linkage checking, rollback
rejection (never co-signed), honest first-seen grading, and the bundled
entry_hash Option-1 migration (Sig_structure-based, dual-lookup window).
"""
from __future__ import annotations

import base64
import hashlib
import json

import cbor2
import pytest
from capsule_anchor.anchoring import ct
from capsule_anchor.anchoring.service import AnchorerService
from capsule_anchor.app import create_app
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from fastapi.testclient import TestClient

_COSE_ALG_EDDSA = -8
_COSE_SIGN1_TAG = 18


def _sig_structure(protected_bstr: bytes, payload: bytes) -> bytes:
    return cbor2.dumps(["Signature1", protected_bstr, b"", payload])


def _build_statement(payload_obj: dict, key: Ed25519PrivateKey) -> bytes:
    """Build a real Ed25519-signed COSE_Sign1 over the JSON-encoded payload."""
    protected_bstr = cbor2.dumps({1: _COSE_ALG_EDDSA})
    payload = json.dumps(payload_obj, sort_keys=True, separators=(",", ":")).encode()
    tbs = _sig_structure(protected_bstr, payload)
    signature = key.sign(tbs)
    return cbor2.dumps(cbor2.CBORTag(_COSE_SIGN1_TAG, [protected_bstr, {}, payload, signature]))


def _checkpoint(log_id: str, *, mmr_size: int, prev_size: int, mmr_root: str | None = None,
                 key_id: str = "peer-1", timestamp: str = "2026-08-22T00:00:00Z") -> dict:
    return {
        "artifact_type": "mmr-checkpoint",
        "log_id": log_id,
        "key_id": key_id,
        "mmr_root": mmr_root or ("a" * 64),
        "mmr_size": mmr_size,
        "prev_size": prev_size,
        "timestamp": timestamp,
    }


@pytest.fixture()
def key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture()
def client():
    # Function-scoped (not module-scoped): checkpoint witness state is
    # per-log_id and per-service-instance, and tests use fresh log_ids to
    # stay independent regardless, but a fresh app avoids cross-test log
    # growth affecting leaf_index assertions.
    return TestClient(create_app())


def _register(client: TestClient, statement_bytes: bytes) -> tuple[int, dict]:
    resp = client.post(
        "/transparency/register-statement",
        json={"signed_statement_b64": base64.b64encode(statement_bytes).decode("ascii")},
    )
    return resp.status_code, (resp.json() if resp.status_code != 500 else {})


# --- recognition ------------------------------------------------------------


def test_unknown_type_registers_as_before_no_witness_field(client, key):
    """A statement with no artifact_type (or an unrelated one) is unaffected --
    registers exactly as a plain Signed Statement, checkpoint_witness is None."""
    statement = _build_statement({"hello": "world"}, key)
    status, body = _register(client, statement)
    assert status == 200, body
    assert body["checkpoint_witness"] is None
    assert body["entry_hash_scheme"] == "sig_structure"


def test_other_artifact_type_registers_as_before(client, key):
    statement = _build_statement({"artifact_type": "offer_terms", "x": 1}, key)
    status, body = _register(client, statement)
    assert status == 200, body
    assert body["checkpoint_witness"] is None


# --- first-seen / witnessed chain -------------------------------------------


def test_first_checkpoint_for_unknown_log_id_is_first_seen(client, key):
    """Nothing to be consistent with yet -- honestly graded, no continuity implied."""
    cp = _checkpoint("log-A", mmr_size=100, prev_size=0)
    statement = _build_statement(cp, key)
    status, body = _register(client, statement)
    assert status == 200, body
    w = body["checkpoint_witness"]
    assert w["status"] == "first-seen"
    assert w["log_id"] == "log-A"
    assert w["mmr_size"] == 100


def test_second_checkpoint_that_extends_first_is_witnessed(client, key):
    cp1 = _checkpoint("log-B", mmr_size=100, prev_size=0)
    s1, b1 = _register(client, _build_statement(cp1, key))
    assert s1 == 200, b1
    assert b1["checkpoint_witness"]["status"] == "first-seen"

    cp2 = _checkpoint("log-B", mmr_size=250, prev_size=100)
    s2, b2 = _register(client, _build_statement(cp2, key))
    assert s2 == 200, b2
    assert b2["checkpoint_witness"]["status"] == "witnessed"
    assert b2["leaf_index"] > b1["leaf_index"]


def test_resubmitting_the_same_checkpoint_is_idempotent(client, key):
    cp = _checkpoint("log-C", mmr_size=50, prev_size=0)
    statement = _build_statement(cp, key)
    s1, b1 = _register(client, statement)
    s2, b2 = _register(client, statement)
    assert s1 == s2 == 200
    assert b1["entry_hash"] == b2["entry_hash"]
    assert b1["leaf_index"] == b2["leaf_index"]
    assert b2["checkpoint_witness"]["status"] == "already-registered"


# --- rollback rejection (never co-signed) -----------------------------------


def test_rollback_behind_the_witnessed_tip_rejected(client, key):
    """A (self-consistent) checkpoint that re-derives from an earlier point
    than the log's current witnessed tip -- e.g. a rolled-back/forked log
    replaying stale state -- must be refused, not co-signed, even though the
    checkpoint's own prev_size < mmr_size."""
    cp1 = _checkpoint("log-D", mmr_size=100, prev_size=0)
    s1, b1 = _register(client, _build_statement(cp1, key))
    assert s1 == 200, b1
    cp2 = _checkpoint("log-D", mmr_size=250, prev_size=100)
    s2, b2 = _register(client, _build_statement(cp2, key))
    assert s2 == 200, b2  # witnessed tip is now mmr_size=250

    # sth() before the rollback attempt, to prove the log did NOT grow.
    sth_before = client.get("/anchor/sth").json()

    # Self-consistent (0 < 100) but re-derives from genesis, ignoring the
    # already-witnessed tip at 250 -- a rollback/fork, not a valid extension.
    # A different key_id makes this a genuinely different signing act (not a
    # cache-hit resubmission of cp1).
    cp_rollback = _checkpoint("log-D", mmr_size=100, prev_size=0, key_id="peer-2")
    status, body = _register(client, _build_statement(cp_rollback, key))
    assert status == 409, body
    assert "rollback" in body["detail"].lower() or "extend" in body["detail"].lower()

    sth_after = client.get("/anchor/sth").json()
    assert sth_after["tree_size"] == sth_before["tree_size"], (
        "a rejected rollback must NEVER be co-signed / appended to the log"
    )


def test_rollback_fork_prev_size_mismatch_rejected(client, key):
    """A checkpoint that doesn't chain from the last witnessed state (a fork
    or a skipped checkpoint) must be refused."""
    cp1 = _checkpoint("log-E", mmr_size=100, prev_size=0)
    s1, b1 = _register(client, _build_statement(cp1, key))
    assert s1 == 200, b1

    cp_fork = _checkpoint("log-E", mmr_size=300, prev_size=50)  # doesn't match witnessed 100
    status, body = _register(client, _build_statement(cp_fork, key))
    assert status == 409, body


def test_rollback_check_actually_distinguishes_valid_from_invalid(client, key):
    """Mutation-style control: the SAME log_id chain accepts a valid extension
    but rejects an invalid one built from the same prior state -- proves the
    409 above is caused by the consistency check, not some unrelated failure."""
    cp1 = _checkpoint("log-F", mmr_size=10, prev_size=0)
    s1, _ = _register(client, _build_statement(cp1, key))
    assert s1 == 200

    valid_cp2 = _checkpoint("log-F", mmr_size=20, prev_size=10)
    s2, b2 = _register(client, _build_statement(valid_cp2, key))
    assert s2 == 200, b2
    assert b2["checkpoint_witness"]["status"] == "witnessed"

    invalid_cp2 = _checkpoint("log-F", mmr_size=15, prev_size=0)  # stale prev_size
    s3, b3 = _register(client, _build_statement(invalid_cp2, key))
    assert s3 == 409, b3


# --- malformed self-declared checkpoints ------------------------------------


def test_malformed_checkpoint_missing_field_rejected_400(client, key):
    bad = {"artifact_type": "mmr-checkpoint", "log_id": "log-G", "mmr_size": 10}
    status, body = _register(client, _build_statement(bad, key))
    assert status == 400, body


def test_malformed_checkpoint_bad_mmr_root_rejected_400(client, key):
    cp = _checkpoint("log-H", mmr_size=10, prev_size=0, mmr_root="not-hex")
    status, body = _register(client, _build_statement(cp, key))
    assert status == 400, body


def test_malformed_checkpoint_prev_size_not_less_than_size_rejected_400(client, key):
    cp = _checkpoint("log-I", mmr_size=10, prev_size=10)
    status, body = _register(client, _build_statement(cp, key))
    assert status == 400, body


# --- entry_hash scheme / dual-lookup window ---------------------------------


def test_entry_hash_scheme_sig_structure_for_cose_sign1(client, key):
    statement = _build_statement({"anything": "here"}, key)
    status, body = _register(client, statement)
    assert status == 200
    assert body["entry_hash_scheme"] == "sig_structure"


def test_entry_hash_scheme_legacy_for_v1_digest():
    """The /v1/digest surface's raw digest bytes were never a signed
    structure -- entry_hash_scheme stays legacy, behavior unchanged."""
    client = TestClient(create_app())
    digest = "b" * 64
    resp = client.post("/v1/digest", json={"capsule_id": digest})
    assert resp.status_code == 200
    assert resp.json()["entry_hash_scheme"] == "legacy"
    assert resp.json()["entry_hash"] == hashlib.sha256(bytes.fromhex(digest)).hexdigest()


def test_dual_lookup_window_resolves_pre_migration_entries(key):
    """A statement registered BEFORE the entry_hash migration is keyed under
    the legacy (full-envelope) scheme. Resubmitting the identical bytes AFTER
    the migration must still return the ORIGINAL receipt/leaf -- not append a
    second leaf -- for the length of the deprecation window."""
    svc = AnchorerService()
    statement = _build_statement({"pretend": "pre-migration statement"}, key)

    # Simulate a pre-migration registration: stored under the OLD (legacy,
    # full-envelope) entry_hash, as every entry was before this migration.
    legacy_hash = hashlib.sha256(statement).hexdigest()
    fake_receipt = b"pretend-receipt-bytes"
    svc._store.put_statement(legacy_hash, fake_receipt, leaf_index=0, tree_size=1)

    result = svc.register_signed_statement_full(statement)
    assert result.entry_hash_scheme == "legacy"
    assert result.entry_hash == legacy_hash
    assert result.receipt == fake_receipt, (
        "must return the ORIGINAL pre-migration receipt, not mint a new leaf"
    )
    assert svc.transparency_log() == [], "no new leaf should have been appended"


# --- end-to-end: checkpoint -> receipt -> offline verify --------------------


def test_checkpoint_end_to_end_offline_verify(client, key):
    """Full loop: submit a checkpoint, get a COSE Receipt, and verify it
    OFFLINE -- reconstruct the leaf from the (self-computed) entry_hash, fold
    the audit path, and check the authority's Ed25519 signature over the
    resulting root using only the out-of-band-pinned authority public key.
    Never trusts the receipt's own claims without independently checking them.
    """
    cp = _checkpoint("log-J", mmr_size=42, prev_size=0)
    statement = _build_statement(cp, key)
    status, body = _register(client, statement)
    assert status == 200, body
    assert body["checkpoint_witness"]["status"] == "first-seen"

    receipt_bytes = base64.b64decode(body["receipt_b64"])
    tag = cbor2.loads(receipt_bytes)
    assert tag.tag == 18
    protected_bstr, unprotected, payload, signature = tag.value
    assert payload is None  # detached: the root is the signed payload
    protected = cbor2.loads(protected_bstr)
    assert protected[1] == -8  # EdDSA
    assert protected[395] == 1  # RFC9162_SHA256

    vdp = unprotected[396]
    inclusion_bstr = vdp[-1][0]
    tree_size, leaf_index, audit_path_bytes = cbor2.loads(inclusion_bstr)
    audit_path = [b.hex() for b in audit_path_bytes]

    # Independently source the root for this exact leaf_index/tree_size --
    # NOT read off the receipt -- from the CT monitor route.
    proof_resp = client.get(
        "/anchor/inclusion-proof-ct",
        params={"leaf_index": leaf_index, "tree_size": tree_size},
    )
    assert proof_resp.status_code == 200
    root_hash = proof_resp.json()["root_hash"]

    leaf_hash = ct.leaf_hash(bytes.fromhex(body["entry_hash"]))
    assert ct.verify_inclusion_path(leaf_hash, leaf_index, tree_size, audit_path, root_hash), (
        "audit path must fold the checkpoint's leaf up to the independently-sourced root"
    )

    pubkey_hex = client.get("/anchor/authority-pubkey").json()["pubkey_hex"]
    sig_structure = _sig_structure(protected_bstr, bytes.fromhex(root_hash))
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex)).verify(signature, sig_structure)
    # .verify() raises on failure; reaching here is the offline-verified pass.
