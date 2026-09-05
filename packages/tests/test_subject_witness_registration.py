"""Tests for discovery mechanism 2 (mesh-adjudication-witness-registration):
registering a Signed Statement with a CWT ``subject`` claim, and resolving it
back via ``GET /transparency/statements?subject=<key>``.

The witness never verifies a subject claim (it is a witness, not a judge) --
these tests cover the honest, additive surface: subject-tagged statements get
indexed, subject-less ones don't, and an unknown subject is a legitimate
empty answer, never an error.
"""
from __future__ import annotations

import base64

import pytest
from capsule_anchor.app import create_app
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from scitt_cose.statement import build_signed_statement

_CAPSULE_ID_MEDIA_TYPE = "application/vnd.agent-action-capsule.capsule-id+octet-stream"


@pytest.fixture()
def key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture()
def key_pem(key: Ed25519PrivateKey) -> bytes:
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
    )

    return key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )


@pytest.fixture()
def client():
    return TestClient(create_app())


def _statement(capsule_id_hex: str, *, subject: str, key_pem: bytes, issuer: str = "urn:test:requester") -> bytes:
    """Build a real Signed Statement over a 32-byte capsule_id digest,
    carrying `subject` as the CWT `sub` claim."""
    payload = bytes.fromhex(capsule_id_hex)
    return build_signed_statement(
        payload,
        alg="EdDSA",
        private_key_pem=key_pem,
        issuer=issuer,
        subject=subject,
        content_type=_CAPSULE_ID_MEDIA_TYPE,
    )


def _register_statement(client: TestClient, statement_bytes: bytes) -> dict:
    resp = client.post(
        "/transparency/register-statement",
        json={"signed_statement_b64": base64.b64encode(statement_bytes).decode("ascii")},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def _query_subject(client: TestClient, subject: str) -> dict:
    resp = client.get("/transparency/statements", params={"subject": subject})
    assert resp.status_code == 200, resp.text
    return resp.json()


def _capsule_id_hex(n: int) -> str:
    return format(n, "064x")


def test_register_with_subject_is_queryable_by_subject(client, key_pem):
    capsule_id = _capsule_id_hex(1)
    statement = _statement(capsule_id, subject="node-gcp-key", key_pem=key_pem)
    result = _register_statement(client, statement)
    assert result["subject"] == "node-gcp-key"

    found = _query_subject(client, "node-gcp-key")
    assert found["subject"] == "node-gcp-key"
    assert len(found["entries"]) == 1
    entry = found["entries"][0]
    assert entry["entry_hash"] == result["entry_hash"]
    assert entry["capsule_id_digest"] == capsule_id
    assert entry["receipt_b64"] == result["receipt_b64"]
    assert entry["leaf_index"] == result["leaf_index"]
    assert entry["tree_size"] == result["tree_size"]


def test_two_statements_same_subject_both_returned(client, key_pem):
    # e.g. a "contradicted" adjudication registered under BOTH providers.
    statement_a = _statement(_capsule_id_hex(2), subject="node-shared", key_pem=key_pem, issuer="urn:test:req-a")
    statement_b = _statement(_capsule_id_hex(3), subject="node-shared", key_pem=key_pem, issuer="urn:test:req-b")
    _register_statement(client, statement_a)
    _register_statement(client, statement_b)

    found = _query_subject(client, "node-shared")
    assert {e["capsule_id_digest"] for e in found["entries"]} == {_capsule_id_hex(2), _capsule_id_hex(3)}


def test_subject_less_registration_not_indexed(client):
    # The plain digest surface never carries a CWT subject claim.
    capsule_id = _capsule_id_hex(4)
    resp = client.post("/register", json={"capsule_id": capsule_id})
    assert resp.status_code == 200, resp.text
    assert resp.json()["subject"] is None

    # Nothing was ever indexed for any subject this bare digest could
    # plausibly collide with.
    found = _query_subject(client, capsule_id)
    assert found["entries"] == []


def test_unknown_subject_returns_empty_not_error(client):
    found = _query_subject(client, "nobody-ever-registered-this-subject")
    assert found["subject"] == "nobody-ever-registered-this-subject"
    assert found["entries"] == []


def test_subject_query_never_leaks_into_wrong_subject(client, key_pem):
    statement = _statement(_capsule_id_hex(5), subject="node-a", key_pem=key_pem)
    _register_statement(client, statement)

    found = _query_subject(client, "node-b")
    assert found["entries"] == []


def test_idempotent_resubmission_reports_same_subject_without_duplicate_entries(client, key_pem):
    statement = _statement(_capsule_id_hex(6), subject="node-c", key_pem=key_pem)
    first = _register_statement(client, statement)
    second = _register_statement(client, statement)
    assert first["entry_hash"] == second["entry_hash"]
    assert second["subject"] == "node-c"

    found = _query_subject(client, "node-c")
    assert len(found["entries"]) == 1


def test_garbage_protected_header_never_crashes_registration(client):
    """Mutant guard: a well-formed COSE_Sign1 whose protected header is not
    a parseable CBOR map at all must still register (unindexed), never 500."""
    import cbor2

    protected_bstr = b"\xff\xff\xff"  # not valid CBOR
    payload = bytes.fromhex(_capsule_id_hex(7))
    # A real signature isn't needed -- register-statement never verifies
    # signatures on the generic path (it is a witness, not a judge).
    statement = cbor2.dumps(cbor2.CBORTag(18, [protected_bstr, {}, payload, b"\x00" * 64]))

    resp = client.post(
        "/transparency/register-statement",
        json={"signed_statement_b64": base64.b64encode(statement).decode("ascii")},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["subject"] is None
