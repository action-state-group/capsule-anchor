"""Tests for POST /v1/digest — simple capsule digest registration."""
import base64
import hashlib

import cbor2
import pytest
from fastapi.testclient import TestClient

from capsule_anchor.app import create_app

DIGEST_64 = "a" * 64  # valid 64-hex (32 bytes of 0xaa)
DIGEST_B = bytes.fromhex(DIGEST_64)


@pytest.fixture(scope="module")
def client():
    return TestClient(create_app())


def test_v1_digest_returns_receipt(client):
    resp = client.post("/v1/digest", json={"capsule_id": DIGEST_64})
    assert resp.status_code == 200
    body = resp.json()
    assert set(body.keys()) >= {"receipt_b64", "entry_hash", "leaf_index", "tree_size"}
    assert body["tree_size"] >= 1
    assert body["leaf_index"] >= 0


def test_v1_digest_entry_hash_is_sha256_of_raw_bytes(client):
    """entry_hash must be SHA256(bytes.fromhex(capsule_id)) — deterministic for offline verify."""
    resp = client.post("/v1/digest", json={"capsule_id": DIGEST_64})
    body = resp.json()
    expected = hashlib.sha256(DIGEST_B).hexdigest()
    assert body["entry_hash"] == expected


def test_v1_digest_receipt_is_cose_sign1(client):
    """Receipt must be a COSE_Sign1 (CBOR tag 18) with alg=-8 (EdDSA) and vds=1 (RFC9162)."""
    resp = client.post("/v1/digest", json={"capsule_id": DIGEST_64})
    receipt_raw = base64.b64decode(resp.json()["receipt_b64"])
    tag = cbor2.loads(receipt_raw)
    assert hasattr(tag, "tag") and tag.tag == 18
    protected_bytes, unprotected, payload, sig = tag.value
    assert payload is None  # detached payload
    protected = cbor2.loads(protected_bytes)
    assert protected[1] == -8   # alg = EdDSA
    assert protected[395] == 1  # vds = RFC9162_SHA256
    # Inclusion proof present in unprotected map
    vdp = unprotected.get(396, {})
    assert -1 in vdp and len(vdp[-1]) >= 1


def test_v1_digest_two_calls_different_leaf_indices(client):
    """Each registration gets a unique leaf_index in the append-only log."""
    digest2 = "b" * 64
    r1 = client.post("/v1/digest", json={"capsule_id": DIGEST_64}).json()
    r2 = client.post("/v1/digest", json={"capsule_id": digest2}).json()
    assert r2["leaf_index"] > r1["leaf_index"]
    assert r2["tree_size"] > r1["tree_size"]


def test_v1_digest_invalid_too_short(client):
    resp = client.post("/v1/digest", json={"capsule_id": "abc"})
    assert resp.status_code == 400


def test_v1_digest_invalid_non_hex(client):
    resp = client.post("/v1/digest", json={"capsule_id": "z" * 64})
    assert resp.status_code == 400


def test_v1_digest_invalid_missing_field(client):
    resp = client.post("/v1/digest", json={})
    assert resp.status_code == 422  # pydantic validation


def test_v1_digest_uppercase_hex_accepted(client):
    """Uppercase hex is normalized and accepted."""
    resp = client.post("/v1/digest", json={"capsule_id": DIGEST_64.upper()})
    assert resp.status_code == 200
