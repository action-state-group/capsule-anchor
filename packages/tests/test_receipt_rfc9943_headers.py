"""Every COSE Receipt carries iss, sub and kid (capsule-anchor#103).

RFC 9943 Section 6: "The protected header of a Signed Statement and a Receipt
MUST include the CWT Claims header parameter ... The CWT Claims value MUST
include the Issuer Claim (Claim label 1) and the Subject Claim (Claim label
2)", and "The kid header parameter MUST be present when neither x5t nor
x5chain is present in the protected header." These tests pin the values: iss
is the instance's published DID, sub the registered statement's own subject
(else its entry_hash), kid the authority key's published key_id.
"""

from __future__ import annotations

import base64

import cbor2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat
from fastapi.testclient import TestClient
from scitt_cose.receipt import verify_receipt
from scitt_cose.statement import build_signed_statement

from capsule_anchor.anchoring.service import AnchorerService
from capsule_anchor.app import create_app

_HOST = "witness.agentactioncapsule.org"  # conftest.py's CAPSULE_ANCHOR_PUBLIC_HOST


def _statement(subject: str = "urn:example:artifact:1", payload: bytes = b"\x01" * 32) -> bytes:
    key = Ed25519PrivateKey.generate().private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    return build_signed_statement(
        payload, alg="EdDSA", private_key_pem=key, issuer="urn:example:issuer",
        subject=subject, content_type="application/octet-stream",
    )


def _subjectless_statement() -> bytes:
    """A COSE_Sign1 with an embedded payload and no CWT claims. The witness
    does not verify a statement's signature, so a placeholder one will do."""
    protected = cbor2.dumps({1: -8})
    return cbor2.dumps(cbor2.CBORTag(18, [protected, {}, b"no-subject", b"\x00" * 64]))


def _register(client: TestClient, statement: bytes) -> dict:
    resp = client.post(
        "/transparency/register-statement",
        json={"signed_statement_b64": base64.b64encode(statement).decode()},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def _protected(receipt: bytes) -> dict:
    return dict(cbor2.loads(cbor2.loads(receipt).value[0]))


def test_receipt_carries_iss_sub_kid():
    client = TestClient(create_app())
    key_id = client.get("/health").json()["key_id"]
    body = _register(client, _statement(subject="urn:example:artifact:1"))
    receipt = base64.b64decode(body["receipt_b64"])
    protected = _protected(receipt)

    claims = protected[15]
    assert claims[1] == f"did:web:{_HOST}"
    assert claims[1] == client.get("/.well-known/did.json").json()["id"]
    assert claims[2] == "urn:example:artifact:1"
    assert isinstance(claims[6], int)
    assert protected[4] == key_id.encode("utf-8")
    assert key_id == client.get("/anchor/authority-pubkey").json()["key_id"]

    # Still a receipt scitt-cose verifies, and it surfaces the new headers.
    pub = client.get("/anchor/authority-pubkey").json()["pubkey_hex"]
    log_pem = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub)).public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    )
    res = verify_receipt(receipt, leaf_entry_hex=body["entry_hash"], log_public_key_pem=log_pem)
    assert res.ok, res.errors
    assert res.issuer == f"did:web:{_HOST}"
    assert res.subject == "urn:example:artifact:1"
    assert res.protected_header_ext[4] == key_id.encode("utf-8")


def test_subjectless_statement_receipt_sub_is_entry_hash():
    client = TestClient(create_app())
    body = _register(client, _subjectless_statement())
    claims = _protected(base64.b64decode(body["receipt_b64"]))[15]
    assert claims[2] == body["entry_hash"]


def test_resubmission_returns_the_cached_receipt():
    """The log is append-only: a statement registered again gets the receipt
    it was first given, byte for byte, not a newly signed one."""
    client = TestClient(create_app())
    statement = _statement(subject="urn:example:artifact:again")
    first = _register(client, statement)
    second = _register(client, statement)
    assert second["receipt_b64"] == first["receipt_b64"]
    assert second["entry_hash"] == first["entry_hash"]


def test_bare_service_names_its_issuer_by_key_id():
    """A service built without ``receipt_issuer`` (tests, embedding) claims no
    host: its receipts name the issuer by the authority key's key_id."""
    svc = AnchorerService()
    reg = svc.register_signed_statement_full(_statement())
    protected = _protected(reg.receipt)
    assert protected[15][1] == svc.attestor.key_id
    assert protected[4] == svc.attestor.key_id.encode("utf-8")
