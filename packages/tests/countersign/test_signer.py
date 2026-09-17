"""sign_countersignature: independent flag, receipt attachment via the
instance's own log (the real AnchorerService/AttestorService this repo
already ships -- not a mock, so the receipt is a genuine registration)."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from capsule_anchor.anchoring.service import AnchorerService
from capsule_anchor.attestation.service import AttestorService
from capsule_anchor.countersign.bundle import Bundle
from capsule_anchor.countersign.policy import NullPolicyModule
from capsule_anchor.countersign.recompute import recompute_statement
from capsule_anchor.countersign.signer import sign_countersignature

from .conftest import base_bundle_raw


def _statement(producer_key):
    raw = base_bundle_raw(producer_key)
    bundle = Bundle.model_validate(raw)
    statement = recompute_statement(bundle, policy_module=NullPolicyModule())
    return bundle, statement


def test_independent_countersignature_when_signer_differs_from_producer(producer_key):
    bundle, statement = _statement(producer_key)
    attestor = AttestorService()  # generates its own ephemeral key -- differs from producer_key
    registrar = AnchorerService(attestor=attestor)

    entry = sign_countersignature(
        bundle, statement, attestor=attestor, registrar=registrar, signer_id="did:web:countersign.example"
    )

    assert entry["independent"] is True
    assert entry["signer"]["id"] == "did:web:countersign.example"
    # The wire key_id is the full 64-hex Ed25519 public key -- self-contained
    # and offline-verifiable -- never this repo's internal truncated key_id.
    assert entry["signer"]["key_id"] == attestor.authority_pubkey().hex()
    assert len(entry["signer"]["key_id"]) == 64
    assert entry["over"] == bundle.digest


def test_signature_verifies_over_the_bundle_digest_not_the_statement(producer_key):
    """Wire-shape ruling: the signature is over the UTF-8 bytes of the
    bundle digest's 64-hex-character form (the ``over`` field) -- matching
    the Go verifier -- never over the statement bytes."""
    bundle, statement = _statement(producer_key)
    attestor = AttestorService()
    registrar = AnchorerService(attestor=attestor)

    entry = sign_countersignature(
        bundle, statement, attestor=attestor, registrar=registrar, signer_id="did:web:countersign.example"
    )

    pubkey = Ed25519PublicKey.from_public_bytes(attestor.authority_pubkey())
    pubkey.verify(bytes.fromhex(entry["signature"]), bundle.digest.encode("ascii"))
    # Also confirm it is NOT a signature over the statement bytes.
    with pytest.raises(Exception):
        pubkey.verify(bytes.fromhex(entry["signature"]), statement.canonical_bytes())


def test_self_countersignature_is_well_formed_and_flagged_not_independent(producer_key):
    """Brief item 7: self-countersignature (signer key == producer key) is
    well-formed and flagged independent:false -- never refused."""
    bundle, statement = _statement(producer_key)
    attestor = AttestorService()
    registrar = AnchorerService(attestor=attestor)

    # Force the bundle's producer_key_id to equal this attestor's own key --
    # the self-countersignature case.
    bundle = bundle.model_copy(update={"producer_key_id": attestor.key_id})

    entry = sign_countersignature(
        bundle, statement, attestor=attestor, registrar=registrar, signer_id="did:web:countersign.example"
    )

    assert entry["independent"] is False
    # Well-formed: still carries a real signature and a real receipt, never refused.
    assert entry["signature"]
    assert entry["receipt"]["entry_hash"]


def test_entry_carries_a_real_receipt_from_the_instances_own_log(producer_key):
    bundle, statement = _statement(producer_key)
    attestor = AttestorService()
    registrar = AnchorerService(attestor=attestor)

    entry = sign_countersignature(
        bundle, statement, attestor=attestor, registrar=registrar, signer_id="did:web:countersign.example"
    )

    receipt = entry["receipt"]
    assert receipt["leaf_index"] == 0
    assert receipt["tree_size"] == 1
    assert receipt["receipt_b64"]

    # Idempotent: signing the identical statement twice returns the SAME
    # receipt (the underlying log dedups by entry_hash) rather than a second
    # leaf -- matches the digest-registration path's documented behavior.
    entry2 = sign_countersignature(
        bundle, statement, attestor=attestor, registrar=registrar, signer_id="did:web:countersign.example"
    )
    assert entry2["receipt"]["entry_hash"] == receipt["entry_hash"]
    assert entry2["receipt"]["leaf_index"] == receipt["leaf_index"]
