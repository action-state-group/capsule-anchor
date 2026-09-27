"""sign_countersignature: independent flag, receipt attachment via the
instance's own log (the real AnchorerService/AttestorService this repo
already ships -- not a mock, so the receipt is a genuine registration)."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from capsule_anchor.anchoring.service import AnchorerService
from capsule_anchor.attestation.service import AttestorService
from capsule_anchor.countersign.bundle import parse_bundle
from capsule_anchor.countersign.policy import NullPolicyModule
from capsule_anchor.countersign.recompute import recompute_statement
from capsule_anchor.countersign.signer import (
    COUNTERSIGN_ENTRY_TYPE,
    countersign_signing_input,
    sign_countersignature,
)

from .conftest import TEST_LEDGER_ID


def _statement(valid_bundle_raw):
    bundle = parse_bundle(valid_bundle_raw)
    statement = recompute_statement(
        bundle, policy_module=NullPolicyModule(), ledger_id=TEST_LEDGER_ID, profile_id="test/v0"
    )
    return bundle, statement


def test_independent_countersignature_when_signer_differs_from_requester(valid_bundle_raw, requester_key):
    bundle, statement = _statement(valid_bundle_raw)
    attestor = AttestorService()  # generates its own ephemeral key -- differs from requester_key
    registrar = AnchorerService(attestor=attestor)

    entry = sign_countersignature(
        bundle,
        statement,
        attestor=attestor,
        registrar=registrar,
        signer_id="did:web:countersign.example",
        requester_key_id=requester_key.pubkey_hex,
    )

    assert entry["independent"] is True
    assert entry["signer"]["id"] == "did:web:countersign.example"
    # The wire key_id is the full 64-hex Ed25519 public key -- self-contained
    # and offline-verifiable -- never this repo's internal truncated key_id.
    assert entry["signer"]["key_id"] == attestor.authority_pubkey().hex()
    assert len(entry["signer"]["key_id"]) == 64
    assert entry["over"] == bundle.digest


def test_entry_carries_the_registered_countersign_type(valid_bundle_raw, requester_key):
    """AAC Evidence Bundle -00 MUSTs a registered ``type`` field on every
    countersignatures[] entry -- capsulectl already emits it
    (``countersignAPI`` in internal/cli/countersign.go); this asserts the
    engine's own entry matches, so an absent or mismatched type is a hard
    test failure, not a silent interop gap."""
    bundle, statement = _statement(valid_bundle_raw)
    attestor = AttestorService()
    registrar = AnchorerService(attestor=attestor)

    entry = sign_countersignature(
        bundle,
        statement,
        attestor=attestor,
        registrar=registrar,
        signer_id="did:web:countersign.example",
        requester_key_id=requester_key.pubkey_hex,
    )

    assert entry["type"] == "countersign/v1"
    assert entry["type"] == COUNTERSIGN_ENTRY_TYPE


def test_signature_covers_the_statement_not_the_bundle_digest_alone(valid_bundle_raw, requester_key):
    """The signature is over UTF8(JCS({over, statement, type})): it verifies
    over that signing input, never over the bundle digest alone, and a
    rewritten check result breaks it."""
    bundle, statement = _statement(valid_bundle_raw)
    attestor = AttestorService()
    registrar = AnchorerService(attestor=attestor)

    entry = sign_countersignature(
        bundle,
        statement,
        attestor=attestor,
        registrar=registrar,
        signer_id="did:web:countersign.example",
        requester_key_id=requester_key.pubkey_hex,
    )

    pubkey = Ed25519PublicKey.from_public_bytes(attestor.authority_pubkey())
    signature = bytes.fromhex(entry["signature"])
    pubkey.verify(signature, countersign_signing_input(entry["over"], entry["statement"], entry["type"]))
    with pytest.raises(Exception):
        pubkey.verify(signature, bundle.digest.encode("ascii"))

    tampered = dict(entry["statement"], checks=[dict(c, result="established") for c in entry["statement"]["checks"]])
    assert tampered != entry["statement"]
    with pytest.raises(Exception):
        pubkey.verify(signature, countersign_signing_input(entry["over"], tampered, entry["type"]))


def test_self_countersignature_is_well_formed_and_flagged_not_independent(valid_bundle_raw):
    """Brief item 7: self-countersignature (signer key == requester's own
    key) is well-formed and flagged independent:false -- never refused."""
    bundle, statement = _statement(valid_bundle_raw)
    attestor = AttestorService()
    registrar = AnchorerService(attestor=attestor)

    entry = sign_countersignature(
        bundle,
        statement,
        attestor=attestor,
        registrar=registrar,
        signer_id="did:web:countersign.example",
        # The requester's own key_id equals this instance's signer key -- the
        # self-countersignature case.
        requester_key_id=attestor.authority_pubkey().hex(),
    )

    assert entry["independent"] is False
    # Well-formed: still carries a real signature and a real receipt, never refused.
    assert entry["signature"]
    assert entry["receipt"]["entry_hash"]


def test_entry_carries_a_real_receipt_from_the_instances_own_log(valid_bundle_raw, requester_key):
    bundle, statement = _statement(valid_bundle_raw)
    attestor = AttestorService()
    registrar = AnchorerService(attestor=attestor)

    entry = sign_countersignature(
        bundle,
        statement,
        attestor=attestor,
        registrar=registrar,
        signer_id="did:web:countersign.example",
        requester_key_id=requester_key.pubkey_hex,
    )

    receipt = entry["receipt"]
    assert receipt["leaf_index"] == 0
    assert receipt["tree_size"] == 1
    assert receipt["receipt_b64"]

    # Idempotent: signing the identical statement twice returns the SAME
    # receipt (the underlying log dedups by entry_hash) rather than a second
    # leaf -- matches the digest-registration path's documented behavior.
    entry2 = sign_countersignature(
        bundle,
        statement,
        attestor=attestor,
        registrar=registrar,
        signer_id="did:web:countersign.example",
        requester_key_id=requester_key.pubkey_hex,
    )
    assert entry2["receipt"]["entry_hash"] == receipt["entry_hash"]
    assert entry2["receipt"]["leaf_index"] == receipt["leaf_index"]
