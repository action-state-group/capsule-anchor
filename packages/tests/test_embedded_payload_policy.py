"""The embedded-payload registration policy (payload_policy; RFC 9943 5.1.1, 6.2, 8.2, 8.4).

By default a Signed Statement's embedded payload is stored DETACHED (only its SHA-256 is kept),
unless the statement was made over a hash, whose payload already is a digest and is kept as
submitted. An operator may opt in to keeping embedded payloads up to a cap. Receipts are
unaffected: they cover the statement's Sig_structure, payload included.
"""
from __future__ import annotations

import base64
import hashlib
import json
import sqlite3

import cbor2
import pytest
from capsule_anchor.anchoring.payload_policy import (
    CAPSULE_ID_MEDIA_TYPE,
    FORM_DIGEST,
    FORM_EMBEDDED,
    FORM_SHA256,
    EmbeddedPayloadPolicy,
    policy_from_env,
    stored_payload,
)
from capsule_anchor.anchoring.store import SqliteLogStore
from capsule_anchor.app import create_app
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat
from fastapi.testclient import TestClient
from scitt_cose import verify_receipt
from scitt_cose.statement import build_signed_statement

BODY = json.dumps({"tag": "v9.9.9", "commit": "0" * 40}, separators=(",", ":")).encode()


@pytest.fixture()
def key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def _pem(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


def _embedded(key, payload: bytes, *, subject: str, content_type: str = "application/json") -> bytes:
    return build_signed_statement(
        payload, alg="EdDSA", private_key_pem=_pem(key), issuer="urn:test:issuer",
        subject=subject, content_type=content_type,
    )


def _hash_envelope(key, preimage: bytes, *, subject: str, alg: int = -16, digest: bytes | None = None) -> bytes:
    """RFC 9943 6.2: payload = the digest; protected 258 payload_hash_alg, 259 preimage type."""
    protected = cbor2.dumps({1: -8, 258: alg, 259: "application/json", 15: {1: "urn:test:issuer", 2: subject}})
    payload = hashlib.sha256(preimage).digest() if digest is None else digest
    signature = key.sign(cbor2.dumps(["Signature1", protected, b"", payload]))
    return cbor2.dumps(cbor2.CBORTag(18, [protected, {}, payload, signature]))


def _register(client: TestClient, statement: bytes) -> dict:
    r = client.post("/transparency/register-statement",
                    json={"signed_statement_b64": base64.b64encode(statement).decode()})
    assert r.status_code == 200, r.text
    return r.json()


def _entry(client: TestClient, subject: str) -> dict:
    entries = client.get("/transparency/statements", params={"subject": subject}).json()["entries"]
    assert len(entries) == 1
    return entries[0]


@pytest.fixture()
def client():
    return TestClient(create_app())


# ---- what is kept, by default -------------------------------------------------------------------

def test_an_embedded_payload_is_stored_detached_by_default(client, key):
    _register(client, _embedded(key, BODY, subject="urn:s:a"))
    entry = _entry(client, "urn:s:a")
    assert entry["payload_form"] == FORM_SHA256
    assert entry["capsule_id_digest"] == hashlib.sha256(BODY).hexdigest()
    assert BODY.hex() not in json.dumps(entry)


def test_a_statement_over_a_hash_keeps_its_digest(client, key):
    _register(client, _hash_envelope(key, BODY, subject="urn:s:b"))
    entry = _entry(client, "urn:s:b")
    assert entry["payload_form"] == FORM_DIGEST
    assert entry["capsule_id_digest"] == hashlib.sha256(BODY).hexdigest()


def test_a_capsule_id_payload_keeps_the_capsule_id(client, key):
    capsule_id = hashlib.sha256(b"a capsule").digest()
    _register(client, _embedded(key, capsule_id, subject="urn:s:c", content_type=CAPSULE_ID_MEDIA_TYPE))
    entry = _entry(client, "urn:s:c")
    assert entry["payload_form"] == FORM_DIGEST
    assert entry["capsule_id_digest"] == capsule_id.hex()


@pytest.mark.parametrize("statement_kind", ["bare 32 bytes", "258 with the wrong length", "258 with an unknown alg"])
def test_a_payload_that_only_looks_like_a_digest_is_stored_detached(client, key, statement_kind):
    if statement_kind == "bare 32 bytes":
        payload = b"x" * 32
        statement = _embedded(key, payload, subject="urn:s:d", content_type="application/octet-stream")
    elif statement_kind == "258 with the wrong length":
        payload = b"y" * 33
        statement = _hash_envelope(key, b"", subject="urn:s:d", digest=payload)
    else:
        payload = b"z" * 32
        statement = _hash_envelope(key, b"", subject="urn:s:d", alg=-999, digest=payload)
    _register(client, statement)
    entry = _entry(client, "urn:s:d")
    assert entry["payload_form"] == FORM_SHA256
    assert entry["capsule_id_digest"] == hashlib.sha256(payload).hexdigest()


# ---- the operator's opt-in ----------------------------------------------------------------------

def test_the_opt_in_keeps_embedded_payloads_up_to_the_cap(monkeypatch, key):
    monkeypatch.setenv("CAPSULE_ANCHOR_STORE_EMBEDDED_PAYLOADS", "on")
    monkeypatch.setenv("CAPSULE_ANCHOR_EMBEDDED_PAYLOAD_MAX_BYTES", "100")
    client = TestClient(create_app())
    small, large = b'{"a":1}', b"{" + b'"k":"' + b"v" * 200 + b'"}'
    _register(client, _embedded(key, small, subject="urn:s:small"))
    _register(client, _embedded(key, large, subject="urn:s:large"))
    assert _entry(client, "urn:s:small")["payload_form"] == FORM_EMBEDDED
    assert _entry(client, "urn:s:small")["capsule_id_digest"] == small.hex()
    assert _entry(client, "urn:s:large")["payload_form"] == FORM_SHA256
    assert _entry(client, "urn:s:large")["capsule_id_digest"] == hashlib.sha256(large).hexdigest()


@pytest.mark.parametrize(
    "env",
    [
        {"CAPSULE_ANCHOR_STORE_EMBEDDED_PAYLOADS": "yes"},
        {"CAPSULE_ANCHOR_EMBEDDED_PAYLOAD_MAX_BYTES": "lots"},
        {"CAPSULE_ANCHOR_EMBEDDED_PAYLOAD_MAX_BYTES": "0"},
        {"CAPSULE_ANCHOR_EMBEDDED_PAYLOAD_MAX_BYTES": "70000"},
    ],
)
def test_a_malformed_policy_fails_closed(env):
    with pytest.raises(RuntimeError):
        policy_from_env(env, statement_limit=64 * 1024)


def test_the_default_policy_is_detached():
    assert policy_from_env({}, statement_limit=64 * 1024) == EmbeddedPayloadPolicy(store_embedded=False)
    assert stored_payload({}, None, EmbeddedPayloadPolicy()) == (None, None)


# ---- receipts verify for both kinds -------------------------------------------------------------

def test_receipts_verify_offline_for_a_detached_payload_and_a_statement_over_a_hash(client, key):
    pub = client.get("/anchor/authority-pubkey").json()["pubkey_hex"]
    log_pem = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub)).public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    )
    for statement in (_embedded(key, BODY, subject="urn:s:r1"), _hash_envelope(key, BODY, subject="urn:s:r2")):
        reg = _register(client, statement)
        assert verify_receipt(
            base64.b64decode(reg["receipt_b64"]), leaf_entry_hex=reg["entry_hash"], log_public_key_pem=log_pem
        ).ok
        # A relying party holding the statement binds the receipt to it by itself; with the
        # payload stored detached here, the statement (payload included) comes from its issuer.
        protected, _u, payload, _s = cbor2.loads(statement).value
        sig_structure = cbor2.dumps(["Signature1", protected, b"", payload])
        assert hashlib.sha256(sig_structure).hexdigest() == reg["entry_hash"]


# ---- the published policy -----------------------------------------------------------------------

def test_the_policy_and_privacy_posture_are_published(client):
    policy = client.get("/transparency/registration-policy").json()
    statements = policy["signed_statements"]
    assert statements["store_embedded"] is False
    assert "stored detached" in statements["embedded_payloads"]
    assert statements["resubmission_needs_issuer_payload"] is True
    assert statements["signature_verified_at_registration"] is False
    assert policy["privacy"]["leaves"] == []
    assert policy["privacy"]["telemetry"] == "none"
    assert "258" in policy["recommended_submission"]
    assert client.get("/health").json()["embedded_payloads"] == "detached"


def test_the_published_posture_lists_what_leaves_when_it_is_on(monkeypatch):
    monkeypatch.setenv("CAPSULE_ANCHOR_TSA_ENABLED", "1")
    monkeypatch.setenv("CAPSULE_ANCHOR_STORE_EMBEDDED_PAYLOADS", "on")
    client = TestClient(create_app())
    policy = client.get("/transparency/registration-policy").json()
    assert any("timestamp authority" in item for item in policy["privacy"]["leaves"])
    assert policy["signed_statements"]["embedded_max_bytes"] == 1024
    assert client.get("/health").json()["embedded_payloads"] == "as_submitted_up_to_cap"


# ---- existing rows ------------------------------------------------------------------------------

def test_an_existing_subject_index_gains_the_column_and_keeps_its_rows(tmp_path):
    db = tmp_path / "old.db"
    conn = sqlite3.connect(db)
    conn.execute(
        "CREATE TABLE subject_index (subject TEXT NOT NULL, entry_hash TEXT NOT NULL, "
        "capsule_id_digest TEXT, PRIMARY KEY (subject, entry_hash))"
    )
    conn.execute("INSERT INTO subject_index VALUES ('urn:s:old', 'aa', '7b7d')")
    conn.commit()
    conn.close()
    store = SqliteLogStore(str(db))
    assert store.get_by_subject("urn:s:old") == [("aa", "7b7d", None)]
    store.put_subject_index("urn:s:new", "bb", "cc", FORM_SHA256)
    assert store.get_by_subject("urn:s:new") == [("bb", "cc", FORM_SHA256)]
