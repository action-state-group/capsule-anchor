"""Shared fixtures for the countersign test suite: a producer keypair and a
minimal, valid withheld-bundle builder that tests mutate from."""

from __future__ import annotations

import copy
import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from capsule_anchor.countersign.bundle import Bundle, compute_bundle_digest
from capsule_anchor.countersign.issuers import IssuerAllowlist

#: The ``ledger_id`` every bundle built by this file's helpers carries --
#: shared so ``issuer_allowlist`` enrolls the SAME identity ``base_bundle_raw``
#: puts in the bundle.
TEST_LEDGER_ID = "ledger:test-001"


class ProducerKey:
    def __init__(self) -> None:
        self.private = Ed25519PrivateKey.generate()
        pub = self.private.public_key().public_bytes_raw()
        self.pubkey_hex = pub.hex()
        self.key_id = hashlib.sha256(pub).hexdigest()[:16]

    def sign_hex(self, data: bytes) -> str:
        return self.private.sign(data).hex()


@pytest.fixture()
def producer_key() -> ProducerKey:
    return ProducerKey()


@pytest.fixture()
def issuer_allowlist(producer_key: ProducerKey) -> IssuerAllowlist:
    """A registration-policy trust anchor enrolling ``producer_key`` under
    ``TEST_LEDGER_ID`` -- the issuer identity this fixture's bundles carry."""
    return IssuerAllowlist.from_list(
        [{"ledger_id": TEST_LEDGER_ID, "pubkey_hex": producer_key.pubkey_hex}]
    )


def base_bundle_raw(producer_key: ProducerKey) -> dict:
    """A minimal, structurally valid withheld bundle with no records or
    checkpoints -- tests add what their case needs."""
    return {
        "schema": "evidence-bundle/v2",
        "payloads": "none",
        "ledger_id": TEST_LEDGER_ID,
        "period": {"from": "2026-09-01T00:00:00+00:00", "to": "2026-09-08T00:00:00+00:00"},
        "closure_depth": 3,
        "profile": {"id": "test/v0", "version": "1.0"},
        "records": [],
        "rotations": [],
        "checkpoints": [],
        "receipts": [],
        "producer_key_id": producer_key.key_id,
        "digest": "0" * 64,
        "producer_signature": "00" * 64,
    }


def finalize_bundle(raw: dict, producer_key: ProducerKey) -> dict:
    """Compute and sign the digest over ``raw``'s content, returning a
    fully self-consistent bundle dict ready for ``accept_bundle``."""
    raw = copy.deepcopy(raw)
    raw["producer_key_id"] = producer_key.key_id
    bundle = Bundle.model_validate(raw)
    digest = compute_bundle_digest(bundle)
    raw["digest"] = digest
    raw["producer_signature"] = producer_key.sign_hex(bytes.fromhex(digest))
    return raw


@pytest.fixture()
def valid_bundle_raw(producer_key: ProducerKey) -> dict:
    return finalize_bundle(base_bundle_raw(producer_key), producer_key)
