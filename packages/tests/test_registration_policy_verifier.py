"""An outside verifier checks receipts from the published policy alone (capsule-anchor#124).

``GET /transparency/registration-policy`` states the entry and leaf rule, the receipt's
structure, what its signature covers, how to bind its root to a signed tree head, and the
receipt key. The verifier below uses nothing else: it reads the labels and values from the
policy, implements RFC 9162 inclusion and consistency checks itself (not this service's
``ct`` module), and fetches only the public endpoints the policy names.
"""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime

import cbor2
import pytest
from cryptography.exceptions import InvalidSignature
from capsule_anchor.anchoring.service import SignedTreeHead, sth_payload
from capsule_anchor.app import create_app
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from fastapi.testclient import TestClient

# ---- RFC 9162 written from the RFC, independent of capsule_anchor.anchoring.ct -------------------


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _root_from_inclusion(leaf: bytes, leaf_index: int, tree_size: int, path: list[bytes]) -> bytes:
    """RFC 9162 Section 2.1.3.2."""
    assert leaf_index < tree_size
    fn, sn, r = leaf_index, tree_size - 1, leaf
    for p in path:
        assert sn != 0
        if fn & 1 or fn == sn:
            r = _node(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = _node(r, p)
        fn >>= 1
        sn >>= 1
    assert sn == 0
    return r


def _consistent(first: int, second: int, first_hash: bytes, second_hash: bytes, path: list[bytes]) -> bool:
    """RFC 9162 Section 2.1.4.2."""
    if first == second:
        return not path and first_hash == second_hash
    if first & (first - 1) == 0:  # a power of two: the old root starts the path
        path = [first_hash, *path]
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr, sr = _node(c, fr), _node(c, sr)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = _node(sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == first_hash and sr == second_hash


# ---- statements ---------------------------------------------------------------------------------


def _statement(key: Ed25519PrivateKey, payload: bytes, *, detached: bool = False) -> bytes:
    protected = cbor2.dumps({1: -8, 3: "application/json", 15: {1: "urn:test:issuer", 2: "urn:test:subject"}})
    signature = key.sign(cbor2.dumps(["Signature1", protected, b"", payload]))
    return cbor2.dumps(cbor2.CBORTag(18, [protected, {}, None if detached else payload, signature]))


def _register(client: TestClient, statement: bytes) -> dict:
    resp = client.post(
        "/transparency/register-statement",
        json={"signed_statement_b64": base64.b64encode(statement).decode()},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("CAPSULE_ANCHOR_PUBLIC_HOST", "verifier-test.example")
    return TestClient(create_app())


# ---- the verifier -------------------------------------------------------------------------------


def _entry(policy: dict, registered: bytes, scheme: str) -> bytes:
    """The entry, per ``receipts.entry``: one rule per scheme the policy names."""
    assert scheme in policy["receipts"]["entry"]
    if scheme == "sig_structure":
        protected, _unprotected, payload, _signature = cbor2.loads(registered).value
        assert payload is not None
        return hashlib.sha256(cbor2.dumps(["Signature1", protected, b"", payload])).digest()
    return hashlib.sha256(registered).digest()


def _verify_receipt(policy: dict, pub: Ed25519PublicKey, statement: bytes, reg: dict) -> tuple[int, bytes]:
    """Check one receipt by the policy; returns the (tree_size, root) it signs."""
    rules = policy["receipts"]
    vds = rules["verifiable_data_structure"]
    entry = _entry(policy, statement, reg["entry_hash_scheme"])
    assert entry.hex() == reg["entry_hash"]
    leaf = hashlib.sha256(b"\x00" + entry).digest()  # receipts.leaf

    receipt = cbor2.loads(base64.b64decode(reg["receipt_b64"]))
    assert receipt.tag == 18
    protected_bstr, unprotected, payload, signature = receipt.value
    assert payload is None  # detached
    protected = cbor2.loads(protected_bstr)
    assert protected[1] == -8
    assert protected[vds["label"]] == vds["value"]
    assert protected[4] == rules["key"]["key_id"].encode("utf-8")
    assert protected[15][1] == rules["key"]["receipt_issuer"]

    # inclusion_proof: unprotected 396, key -1, one bstr-wrapped [tree_size, leaf_index, path].
    (proof_bstr,) = unprotected[396][-1]
    tree_size, leaf_index, path = cbor2.loads(proof_bstr)
    root = _root_from_inclusion(leaf, leaf_index, tree_size, list(path))

    # signature: Sig_structure ["Signature1", protected, h'', root].
    pub.verify(signature, cbor2.dumps(["Signature1", protected_bstr, b"", root]))
    return tree_size, root


def _verified_sth(client: TestClient, pub: Ed25519PublicKey) -> SignedTreeHead:
    """Check the latest signed tree head per ``signed_tree_heads``, from its JSON alone."""
    raw = client.get("/anchor/sth").json()
    timestamp = raw["timestamp"]
    assert timestamp.endswith("Z")
    signing_input = json.dumps(
        {"root_hash": raw["root_hash"], "timestamp": timestamp[:-1] + "+00:00", "tree_size": raw["tree_size"]},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    pub.verify(bytes.fromhex(raw["signature"]["signature"]), signing_input)
    return raw


def test_an_outside_verifier_checks_receipts_from_the_policy_alone(client):
    issuer = Ed25519PrivateKey.generate()
    statements = [_statement(issuer, f'{{"n":{i}}}'.encode()) for i in range(6)]
    statements.append(_statement(issuer, b'{"detached":true}', detached=True))
    regs = [_register(client, s) for s in statements]
    assert [r["entry_hash_scheme"] for r in regs] == ["sig_structure"] * 6 + ["legacy"]
    # receipts.entry.registered_bytes: POST /register registers the capsule_id's 32 raw bytes.
    capsule_id = hashlib.sha256(b"a capsule").hexdigest()
    resp = client.post("/register", json={"capsule_id": capsule_id})
    assert resp.status_code == 200, resp.text
    statements.append(bytes.fromhex(capsule_id))
    regs.append(resp.json())
    assert regs[-1]["entry_hash_scheme"] == "legacy"

    policy = client.get("/transparency/registration-policy").json()

    # The key the policy names, and its key_id derivation.
    key = policy["receipts"]["key"]
    published = client.get("/anchor/authority-pubkey").json()
    raw_key = bytes.fromhex(published["pubkey_hex"])
    assert published["key_id"] == key["key_id"] == hashlib.sha256(raw_key).hexdigest()[:16]
    did = client.get("/.well-known/did.json").json()
    jwk_x = did["verificationMethod"][0]["publicKeyJwk"]["x"]
    assert base64.urlsafe_b64decode(jwk_x + "=" * (-len(jwk_x) % 4)) == raw_key
    assert key["receipt_issuer"] == "did:web:verifier-test.example"
    pub = Ed25519PublicKey.from_public_bytes(raw_key)

    sth = _verified_sth(client, pub)
    sth_root = bytes.fromhex(sth["root_hash"])
    for statement, reg in zip(statements, regs, strict=True):
        tree_size, root = _verify_receipt(policy, pub, statement, reg)
        assert tree_size == reg["tree_size"]
        # binding_a_receipt: the receipt's root, consistent with the verified head.
        proof = client.get(
            "/anchor/consistency-proof", params={"old_size": tree_size, "new_size": sth["tree_size"]}
        ).json()
        path = [bytes.fromhex(h) for h in proof["proof"]]
        assert _consistent(tree_size, sth["tree_size"], root, sth_root, path)


def test_a_tampered_receipt_or_head_fails_the_verifier(client):
    issuer = Ed25519PrivateKey.generate()
    statements = [_statement(issuer, f'{{"n":{i}}}'.encode()) for i in range(3)]
    regs = [_register(client, s) for s in statements]
    policy = client.get("/transparency/registration-policy").json()
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(client.get("/anchor/authority-pubkey").json()["pubkey_hex"]))

    # Another statement's bytes do not match this receipt's entry.
    with pytest.raises(AssertionError):
        _verify_receipt(policy, pub, statements[1], regs[0])

    # The STH signature does not verify over the "Z" form the JSON shows.
    raw = client.get("/anchor/sth").json()
    as_shown = json.dumps(
        {k: raw[k] for k in ("root_hash", "timestamp", "tree_size")}, sort_keys=True, separators=(",", ":")
    ).encode()
    with pytest.raises(InvalidSignature):
        pub.verify(bytes.fromhex(raw["signature"]["signature"]), as_shown)

    # A receipt whose unsigned tree_size or leaf_index was changed no longer recomputes the signed root.
    receipt = cbor2.loads(base64.b64decode(regs[2]["receipt_b64"]))
    protected_bstr, unprotected, _payload, signature = receipt.value
    (proof_bstr,) = unprotected[396][-1]
    tree_size, leaf_index, path = cbor2.loads(proof_bstr)
    assert (tree_size, leaf_index) == (3, 2)  # a real audit path, so a wrong root, not a range check
    for forged in ([tree_size, 1, path], [tree_size + 1, leaf_index, path]):
        forged_receipt = cbor2.CBORTag(18, [protected_bstr, {396: {-1: [cbor2.dumps(forged)]}}, None, signature])
        forged_reg = dict(regs[2], receipt_b64=base64.b64encode(cbor2.dumps(forged_receipt)).decode())
        with pytest.raises((AssertionError, InvalidSignature)):
            _verify_receipt(policy, pub, statements[2], forged_reg)

    # A wrong old root is not consistent with the head.
    tree_size, root = _verify_receipt(policy, pub, statements[0], regs[0])
    proof = client.get("/anchor/consistency-proof", params={"old_size": tree_size, "new_size": raw["tree_size"]}).json()
    path = [bytes.fromhex(h) for h in proof["proof"]]
    assert not _consistent(tree_size, raw["tree_size"], b"\x00" * 32, bytes.fromhex(raw["root_hash"]), path)


@pytest.mark.parametrize("microsecond", [0, 1, 304315])
def test_the_published_timestamp_form_matches_the_signed_bytes(microsecond):
    """``signed_tree_heads.timestamp_form``: the JSON's "Z" read as "+00:00" gives the signed bytes,
    including a whole-second time, where both forms drop the fraction."""
    ts = datetime(2026, 11, 28, 6, 52, 16, microsecond, tzinfo=UTC)
    sig = {"signature": "00", "key_id": "k", "created_at": ts}
    shown = json.loads(SignedTreeHead(tree_size=1, root_hash="aa", timestamp=ts, signature=sig).model_dump_json())
    rebuilt = json.dumps(
        {"root_hash": "aa", "timestamp": shown["timestamp"][:-1] + "+00:00", "tree_size": 1},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    assert rebuilt == sth_payload(1, "aa", ts)


def test_the_policy_states_the_rules_issue_124_asks_for(client):
    policy = client.get("/transparency/registration-policy").json()
    receipts = policy["receipts"]
    assert "Sig_structure [\"Signature1\", protected, h'', payload]" in receipts["entry"]["sig_structure"]
    assert "SHA-256 of the registered bytes" in receipts["entry"]["legacy"]
    assert "entry_hash_scheme" in receipts["entry"]["scheme"]
    assert set(receipts["entry"]["registered_bytes"]) == {
        "POST /transparency/register-statement", "POST /checkpoints", "POST /register and POST /v1/digest",
    }
    assert receipts["leaf"].startswith("SHA-256(0x00 || entry)")
    assert receipts["verifiable_data_structure"] == {
        "label": 395, "value": 1, "name": "RFC9162_SHA256", "reference": "RFC 9942 Section 5.1",
    }
    assert "396" in receipts["inclusion_proof"] and "[tree_size, leaf_index" in receipts["inclusion_proof"]
    assert "the signature binds the root alone" in receipts["unsigned"]
    assert "[\"Signature1\", protected, h'', root]" in receipts["signature"]
    assert receipts["key"]["key_id"] == client.get("/anchor/authority-pubkey").json()["key_id"]
    assert "/anchor/authority-pubkey" in receipts["key"]["public_key"]
    assert "no kid" in receipts["protected_header"]["before_capsule_anchor_103"]
    assert "exactly as received" in receipts["protected_header"]["as_received"]
    assert "kid" in receipts["key"]["selection"]
    assert "retired" in receipts["key"]["rotation"]

    heads = policy["signed_tree_heads"]
    assert heads["latest"] == "GET /anchor/sth"
    assert heads["consistency"].startswith("GET /anchor/consistency-proof")
    assert "keys sorted and no whitespace" in heads["signature"]
    example = json.loads(heads["signing_input_example"])
    assert list(example) == ["root_hash", "timestamp", "tree_size"]
    assert example["timestamp"].endswith("+00:00")
    assert json.dumps(example, sort_keys=True, separators=(",", ":")) == heads["signing_input_example"]
