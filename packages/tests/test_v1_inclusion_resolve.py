"""Tests for GET /v1/inclusion/{capsule_id} — read-only resolve by capsule_id.

This is the route the A2A boundary-seal ``capsule.resolve`` gate depends on:
capsule_id -> {leaf_index, tree_size, inclusion proof, COSE Receipt}, 200 if the
capsule's statement is in the log, 404 if absent. It MUST be a pure read — an
unknown capsule_id must NOT be registered as a side effect (that would defeat
the negative-case DENY and let a verifier forge presence).
"""
import base64
import hashlib

import cbor2
import pytest
from fastapi.testclient import TestClient

from capsule_anchor.anchoring import ct
from capsule_anchor.app import create_app

CID = "c" * 64  # arbitrary valid 64-hex capsule_id, distinct from other test modules
UNKNOWN_CID = "d1" * 32  # never registered in this app instance


@pytest.fixture(scope="module")
def client():
    return TestClient(create_app())


def _entry_hash(cid: str) -> str:
    return hashlib.sha256(bytes.fromhex(cid)).hexdigest()


def test_resolve_404_when_absent_and_no_side_effect(client):
    """Unknown capsule_id -> 404, and the log MUST NOT grow (pure read).

    Proven via registration-index deltas: two real registrations that bracket
    the 404 resolve must land on consecutive leaf indices — if the resolve had
    registered the unknown id, a leaf would sit between them.
    """
    a = client.post("/v1/digest", json={"capsule_id": "a1" * 32}).json()
    resp = client.get(f"/v1/inclusion/{UNKNOWN_CID}")
    assert resp.status_code == 404
    b = client.post("/v1/digest", json={"capsule_id": "b2" * 32}).json()
    assert b["leaf_index"] == a["leaf_index"] + 1, (
        "resolve of an absent capsule_id registered it — not read-only"
    )


def test_resolve_200_after_registration(client):
    """Register via POST /v1/digest, then resolve returns matching coordinates."""
    reg = client.post("/v1/digest", json={"capsule_id": CID}).json()
    resp = client.get(f"/v1/inclusion/{CID}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["capsule_id"] == CID
    assert body["entry_hash"] == _entry_hash(CID) == reg["entry_hash"]
    assert body["leaf_index"] == reg["leaf_index"]
    # tree_size on the proof is >= the registration tree_size (log may have grown)
    assert body["tree_size"] >= reg["tree_size"]
    assert isinstance(body["audit_path"], list)


def test_resolve_is_idempotent_read(client):
    """Resolving twice returns the same leaf_index and does not append."""
    client.post("/v1/digest", json={"capsule_id": CID})
    first = client.get(f"/v1/inclusion/{CID}").json()
    size_mid = client.get("/anchor/sth").json()["tree_size"]
    second = client.get(f"/v1/inclusion/{CID}").json()
    size_after = client.get("/anchor/sth").json()["tree_size"]
    assert first["leaf_index"] == second["leaf_index"]
    assert size_after == size_mid


def test_resolve_inclusion_proof_folds_to_root(client):
    """The returned RFC6962 audit path must reconstruct the returned root."""
    client.post("/v1/digest", json={"capsule_id": CID})
    body = client.get(f"/v1/inclusion/{CID}").json()
    # leaf_hash must be the RFC6962 leaf of the raw entry_hash bytes.
    expected_leaf = ct.leaf_hash(bytes.fromhex(body["entry_hash"]))
    assert body["leaf_hash"] == expected_leaf
    ok = ct.verify_inclusion_path(
        body["leaf_hash"],
        body["leaf_index"],
        body["tree_size"],
        body["audit_path"],
        body["root_hash"],
    )
    assert ok


def test_resolve_receipt_is_cose_sign1_over_the_root(client):
    """The receipt is the same COSE_Sign1 issued at registration (offline-verifiable)."""
    client.post("/v1/digest", json={"capsule_id": CID})
    body = client.get(f"/v1/inclusion/{CID}").json()
    tag = cbor2.loads(base64.b64decode(body["receipt_b64"]))
    assert getattr(tag, "tag", None) == 18  # COSE_Sign1
    protected = cbor2.loads(tag.value[0])
    assert protected[1] == -8   # EdDSA
    assert protected[395] == 1  # vds = RFC9162_SHA256


def test_resolve_400_malformed(client):
    assert client.get("/v1/inclusion/abc").status_code == 400
    assert client.get(f"/v1/inclusion/{'z' * 64}").status_code == 400


def test_resolve_uppercase_normalized(client):
    client.post("/v1/digest", json={"capsule_id": CID})
    resp = client.get(f"/v1/inclusion/{CID.upper()}")
    assert resp.status_code == 200
    assert resp.json()["capsule_id"] == CID  # normalized to lowercase
