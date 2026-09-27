# SPDX-License-Identifier: Apache-2.0
"""Regenerate ``countersign-v1.json``, the shared golden vector for the
``countersign/v1`` signing input.

Run from the repository root:

    python packages/tests/countersign/vectors/generate_countersign_v1.py

The vector is produced by this repo's real signer (``sign_countersignature``)
and its real log (``AnchorerService``), under a fixed TEST-ONLY Ed25519 seed,
so the signature is deterministic. The log clock is pinned to ``LOG_CLOCK``
while the vector is built, so the receipt (which signs the registration time)
is deterministic too: regenerating reproduces the committed bytes exactly,
and ``test_golden_vector.py`` fails if it does not. Other implementations (capsulectl among
them) commit a byte-identical copy of the output and pin its SHA-256.

Signing input: ``UTF8(JCS({"over": over, "statement": statement, "type": type}))``.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from agent_action_capsule.bundle import bundle_digest
from agent_action_capsule.canonical import jcs
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from capsule_anchor.anchoring.service import AnchorerService
from capsule_anchor.attestation.service import AttestorService
from capsule_anchor.countersign.bundle import Bundle
from capsule_anchor.countersign.results import CheckResult
from capsule_anchor.countersign.signer import countersign_signing_input, sign_countersignature
from capsule_anchor.countersign.statement import Scope, Statement
from capsule_anchor.signing_key import LoadedSigningKey, StaticKeyProvider

OUT = Path(__file__).with_name("countersign-v1.json")

# The log's registration time for every receipt in the vector.
LOG_CLOCK = datetime(2026, 9, 27, 0, 0, 0, tzinfo=timezone.utc)

# TEST-ONLY keys. Never use either seed for anything but this vector.
SIGNER_SEED = bytes([0x42] * 32)
PRODUCER_SEED = bytes([0x07] * 32)

BUNDLE = {
    "checkpoints": [
        {
            "key_id": "k1",
            "log_id": "ledger:golden-vector-001",
            "mmr_root": "b" * 64,
            "mmr_size": 1,
            "prev_size": 0,
            "timestamp": "2026-09-01T00:00:00+00:00",
        }
    ],
    "closure_depth": 2,
    "ledger_id": "ledger:golden-vector-001",
    "payloads": "none",
    "records": [
        {
            "digest": "a" * 64,
            "kind": "action",
            "seq": 1,
            "timestamp": "2026-09-01T00:00:00+00:00",
        }
    ],
    "schema": "evidence-bundle/v2",
}

STATEMENT = Statement(
    checks=[
        CheckResult(name="chain consistency", result="not checked"),
        CheckResult(name="range membership", result="failed"),
        CheckResult(name="cadence", result="established"),
        CheckResult(name="key hygiene", result="not present"),
        CheckResult(name="profile conformance", result="inconclusive"),
    ],
    exclusions=["capture coverage"],
    scope=Scope(ledger_id="ledger:golden-vector-001", closure_depth=2),
    recomputed_at=datetime(2026, 9, 27, 0, 0, 0, tzinfo=timezone.utc),
)


def _public_hex(seed: bytes) -> str:
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw().hex()


def _sign(seed: bytes, message: bytes) -> str:
    return Ed25519PrivateKey.from_private_bytes(seed).sign(message).hex()


def build_vector() -> dict:
    with mock.patch("capsule_anchor.anchoring.service._now", return_value=LOG_CLOCK):
        return _build_vector()


def _build_vector() -> dict:
    key = Ed25519PrivateKey.from_private_bytes(SIGNER_SEED)
    attestor = AttestorService(key_provider=StaticKeyProvider(LoadedSigningKey(key, source="test", ephemeral=False)))
    registrar = AnchorerService(attestor=attestor)
    digest = bundle_digest(BUNDLE)
    producer_hex = _public_hex(PRODUCER_SEED)

    entry = sign_countersignature(
        Bundle(raw=BUNDLE, digest=digest),
        STATEMENT,
        attestor=attestor,
        registrar=registrar,
        signer_id="did:web:countersign.example",
        requester_key_id=producer_hex,
    )
    signing_input = countersign_signing_input(entry["over"], entry["statement"], entry["type"])

    # Negative 1: rewrite one result, keep the genuine signature.
    flipped = copy.deepcopy(entry)
    assert flipped["statement"]["checks"][1]["result"] == "failed"
    flipped["statement"]["checks"][1]["result"] = "established"

    # Negative 2: a signature over the bundle digest alone -- the scheme this
    # vector replaces. It must not verify under the new signing input.
    digest_only = copy.deepcopy(entry)
    digest_only["signature"] = _sign(SIGNER_SEED, entry["over"].encode("ascii"))

    # Negative 3: the signature is valid, but the receipt registers a
    # different statement. The entry stays valid; the receipt must not verify.
    other = copy.deepcopy(entry)
    other["statement"]["recomputed_at"] = "2026-09-28T00:00:00Z"
    other_digest = hashlib.sha256(jcs(other["statement"])).hexdigest()
    other_reg = registrar.register_signed_statement_full(bytes.fromhex(other_digest))
    wrong_receipt = copy.deepcopy(entry)
    wrong_receipt["receipt"] = {
        "receipt_b64": base64.b64encode(other_reg.receipt).decode("ascii"),
        "entry_hash": other_reg.entry_hash,
        "leaf_index": other_reg.leaf_index,
        "tree_size": other_reg.tree_size,
    }

    vector = {
        "description": (
            "countersign/v1 golden vector. signature = Ed25519 over "
            'UTF8(JCS({"over": over, "statement": statement, "type": type})), '
            "128 lowercase hex. receipt registers SHA-256(JCS(statement)) in the signer's log "
            "(RFC 9162 COSE Receipt; log entry hash = SHA-256 of those 32 bytes). "
            "Keys are TEST-ONLY."
        ),
        "signer_seed_hex": SIGNER_SEED.hex(),
        "signer_public_key_hex": _public_hex(SIGNER_SEED),
        "producer_public_key_hex": producer_hex,
        "directory": {
            "countersigners": [
                {
                    "name": "Countersign Test Operator",
                    "endpoint": "https://countersign.example",
                    "key_ids": [_public_hex(SIGNER_SEED)],
                    "statement_types_issued": ["countersign/v1"],
                }
            ]
        },
        "bundle": BUNDLE,
        "bundle_digest": digest,
        "signing_input": signing_input.decode("utf-8"),
        "statement_digest": hashlib.sha256(jcs(entry["statement"])).hexdigest(),
        "entry": entry,
        "negative": [
            {
                "name": "flipped-result",
                "note": "statement.checks[1].result rewritten 'failed' -> 'established'; signature unchanged",
                "entry": flipped,
                "expect": {"signature": "invalid"},
            },
            {
                "name": "digest-only-signature",
                "note": "signature over UTF8(over) alone, the pre-fix scheme",
                "entry": digest_only,
                "expect": {"signature": "invalid"},
            },
            {
                "name": "receipt-for-other-statement",
                "note": "valid signature; receipt registers a different statement",
                "entry": wrong_receipt,
                "expect": {"signature": "valid", "receipt": "unverified"},
            },
        ],
    }
    return vector


def render(vector: dict) -> bytes:
    return (json.dumps(vector, indent=2, sort_keys=True) + "\n").encode("utf-8")


def main() -> None:
    OUT.write_bytes(render(build_vector()))
    print(f"wrote {OUT} sha256={hashlib.sha256(OUT.read_bytes()).hexdigest()}")


if __name__ == "__main__":
    main()
