"""The shared countersign/v1 golden vector (``vectors/countersign-v1.json``).

The same file, byte for byte, is committed in capsulectl, which verifies it
with its own Go code. These tests pin this repo's signer to it: the signature
covers ``UTF8(JCS({over, statement, type}))``, so rewriting a single check
result breaks it, and the receipt registers the statement's own digest.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest
from agent_action_capsule.canonical import jcs
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from scitt_cose.receipt import verify_receipt

from capsule_anchor.anchoring.service import AnchorerService
from capsule_anchor.attestation.service import AttestorService
from capsule_anchor.countersign.bundle import Bundle
from capsule_anchor.countersign.signer import countersign_signing_input, sign_countersignature
from capsule_anchor.signing_key import LoadedSigningKey, StaticKeyProvider

from .vectors import generate_countersign_v1
from .vectors.generate_countersign_v1 import BUNDLE, STATEMENT

VECTOR_PATH = Path(__file__).parent / "vectors" / "countersign-v1.json"
VECTOR = json.loads(VECTOR_PATH.read_text())

# The committed vector's SHA-256. capsulectl pins the same value for its
# byte-identical copy; regenerating must reproduce these bytes exactly.
VECTOR_SHA256 = "9f5649a7daa5c3d353dcddfb508a5c90ed81644c74740f54067ba3ce4884a0f2"


def test_vector_bytes_are_pinned():
    assert hashlib.sha256(VECTOR_PATH.read_bytes()).hexdigest() == VECTOR_SHA256


def test_generator_reproduces_the_committed_vector_byte_for_byte():
    """The generator is deterministic (fixed signing seed, fixed log clock),
    so a regeneration can never silently change the shared bytes."""
    assert generate_countersign_v1.render(generate_countersign_v1.build_vector()) == VECTOR_PATH.read_bytes()


def _public_key() -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(VECTOR["signer_public_key_hex"]))


def _signature_valid(entry: dict) -> bool:
    message = countersign_signing_input(entry["over"], entry["statement"], entry["type"])
    try:
        _public_key().verify(bytes.fromhex(entry["signature"]), message)
    except Exception:
        return False
    return True


def _receipt_valid(entry: dict) -> bool:
    """Recompute the log entry from the entry's own statement, never from the
    receipt's claimed ``entry_hash``: SHA-256 of the 32 registered bytes,
    which are SHA-256(JCS(statement))."""
    registered = hashlib.sha256(jcs(entry["statement"])).digest()
    leaf_entry_hex = hashlib.sha256(registered).hexdigest()
    pem = _public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    result = verify_receipt(
        base64.b64decode(entry["receipt"]["receipt_b64"]), leaf_entry_hex=leaf_entry_hex, log_public_key_pem=pem
    )
    return result.ok


def test_signer_reproduces_the_vector_signature_over_the_statement():
    """Ed25519 is deterministic: this repo's signer, under the vector's
    test-only seed, must produce exactly the vector's signature and statement."""
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(VECTOR["signer_seed_hex"]))
    attestor = AttestorService(key_provider=StaticKeyProvider(LoadedSigningKey(key, source="test", ephemeral=False)))
    entry = sign_countersignature(
        Bundle(raw=BUNDLE, digest=VECTOR["bundle_digest"]),
        STATEMENT,
        attestor=attestor,
        registrar=AnchorerService(attestor=attestor),
        signer_id="did:web:countersign.example",
        requester_key_id=VECTOR["producer_public_key_hex"],
    )
    assert entry["statement"] == VECTOR["entry"]["statement"]
    assert entry["signature"] == VECTOR["entry"]["signature"]
    assert entry["receipt"]["entry_hash"] == VECTOR["entry"]["receipt"]["entry_hash"]


def test_signing_input_is_jcs_of_over_statement_type():
    entry = VECTOR["entry"]
    expected = VECTOR["signing_input"].encode("utf-8")
    assert countersign_signing_input(entry["over"], entry["statement"], entry["type"]) == expected
    assert jcs({"over": entry["over"], "statement": entry["statement"], "type": entry["type"]}) == expected


def test_positive_entry_signature_and_receipt_verify():
    entry = VECTOR["entry"]
    assert entry["over"] == VECTOR["bundle_digest"]
    assert _signature_valid(entry)
    assert _receipt_valid(entry)
    assert hashlib.sha256(jcs(entry["statement"])).hexdigest() == VECTOR["statement_digest"]


def test_signature_does_not_verify_over_the_digest_alone():
    entry = VECTOR["entry"]
    with pytest.raises(Exception):
        _public_key().verify(bytes.fromhex(entry["signature"]), entry["over"].encode("ascii"))


@pytest.mark.parametrize("case", VECTOR["negative"], ids=lambda c: c["name"])
def test_negative_cases(case):
    entry = case["entry"]
    expect = case["expect"]
    assert _signature_valid(entry) is (expect["signature"] == "valid")
    if "receipt" in expect:
        assert _receipt_valid(entry) is (expect["receipt"] == "verified")


def test_flipped_result_negative_differs_from_the_signed_statement_only_in_one_result():
    """Guard the vector itself: the flipped case must be the genuine entry
    with exactly one result rewritten, so its failure is caused by that."""
    flipped = next(c for c in VECTOR["negative"] if c["name"] == "flipped-result")["entry"]
    genuine = VECTOR["entry"]
    assert flipped["signature"] == genuine["signature"]
    assert genuine["statement"]["checks"][1]["result"] == "failed"
    assert flipped["statement"]["checks"][1]["result"] == "established"
    flipped_back = json.loads(json.dumps(flipped))
    flipped_back["statement"]["checks"][1]["result"] = "failed"
    assert flipped_back == genuine
