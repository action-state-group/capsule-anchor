# SPDX-License-Identifier: Apache-2.0
"""Tests for `capsule_anchor.cross_witness_conformance` -- the checker built
ahead of AgenTrust's trace-registry publishing its first real CLL checkpoint
(see `[trace-registry-first-checkpoint-conformance]`).

Checkpoint construction here deliberately mirrors
`test_checkpoints_and_register_witness_host.py`'s `_checkpoint_cose` helper
independently (same reasoning that file itself states: this tool must
verify what a STRANGER's bytes claim, never trusting a shared builder to
agree with itself).

The `test_full_pipeline_*` tests use the real FastAPI app via `TestClient`
(in-process, no network) to prove `check_witness_tie_back` genuinely works
against the real server code path -- not a live hit against the deployed
witness (no live-network tests here; see NOTES.md).
"""
from __future__ import annotations

import hashlib

import cbor2
import pytest
from capsule_anchor.app import create_app
from capsule_anchor.cross_witness_conformance.checker import (
    check_chain_continuity,
    check_checkpoint_wire,
    check_countersign_grade,
    check_witness_tie_back,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from fastapi.testclient import TestClient
from scitt_cose.statement import build_signed_statement

_CLL_CONTENT_TYPE = "application/cll-checkpoint+cbor"
_WIRE_KIND = "cll-checkpoint"
_LOG_ID = "trace-registry/v1"


def _root_from_peaks(peak_hashes: list[bytes]) -> bytes:
    if not peak_hashes:
        return bytes(32)
    hashes = list(peak_hashes)
    while len(hashes) > 1:
        right = hashes.pop()
        left = hashes.pop()
        hashes.append(hashlib.sha256(right + left).digest())
    return hashes[0]


def _commitment(peak_hashes: list[bytes]) -> bytes:
    return cbor2.dumps(peak_hashes, canonical=True)


def _peaks_for(seed: str, n: int = 1) -> list[bytes]:
    return [hashlib.sha256(f"{seed}-{i}".encode()).digest() for i in range(n)]


def _pem(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


def _checkpoint_cose(
    key: Ed25519PrivateKey,
    *,
    log_id: str = _LOG_ID,
    mmr_size: int,
    prev_size: int = 0,
    new_peaks: list[bytes] | None = None,
    prev_peaks: list[bytes] | None = None,
    issued_at: str = "2026-09-01T00:00:00Z",
    kid: bytes | None = None,
    content_type: str = _CLL_CONTENT_TYPE,
    subject: str | None = None,
    claims: dict | None = None,
) -> bytes:
    if new_peaks is None:
        new_peaks = _peaks_for(f"{log_id}-{mmr_size}")
    if claims is None:
        claims = {
            "kind": _WIRE_KIND,
            "log_size": mmr_size,
            "commitment": _commitment(new_peaks),
            "prev_size": prev_size,
            "prev_commitment": _commitment(prev_peaks) if prev_peaks else b"",
            "issued_at": issued_at,
        }
    payload = cbor2.dumps(claims, canonical=True)
    if kid is None:
        kid = key.public_key().public_bytes_raw()
    if subject is None:
        subject = f"{log_id}#{mmr_size}"
    return build_signed_statement(
        payload,
        alg="EdDSA",
        private_key_pem=_pem(key),
        issuer=log_id,
        subject=subject,
        content_type=content_type,
        kid=kid,
    )


@pytest.fixture()
def enrolled_key() -> Ed25519PrivateKey:
    """Stands in for AgenTrust's real enrolled key in tests -- the actual
    hex lives in `checker.DEFAULT_EXPECTED_PUBKEY_HEX`; tests pass this
    key's own hex as `expected_pubkey_hex` so they don't depend on a real
    private key none of us hold."""
    return Ed25519PrivateKey.generate()


@pytest.fixture()
def enrolled_key_hex(enrolled_key) -> str:
    return enrolled_key.public_key().public_bytes_raw().hex()


@pytest.fixture()
def client():
    return TestClient(create_app())


# --- check_checkpoint_wire (task item 1) -------------------------------------


def test_valid_checkpoint_passes_every_wire_check(enrolled_key, enrolled_key_hex):
    cose = _checkpoint_cose(enrolled_key, mmr_size=10)
    report = check_checkpoint_wire(cose, expected_log_id=_LOG_ID, expected_pubkey_hex=enrolled_key_hex)
    assert not report.has_failure, report.render()
    names = {c.name for c in report.checks}
    assert names == {
        "wire_structure",
        "signature_self_consistent",
        "sub_pattern",
        "enrolled_log_id",
        "enrolled_key",
    }
    assert report.claims["log_id"] == _LOG_ID
    assert report.claims["mmr_size"] == 10


def test_wrong_content_type_fails_named(enrolled_key, enrolled_key_hex):
    cose = _checkpoint_cose(enrolled_key, mmr_size=10, content_type="application/json")
    report = check_checkpoint_wire(cose, expected_pubkey_hex=enrolled_key_hex)
    assert report.has_failure
    assert report.claims is None
    assert any(c.name == "wire_structure" and c.status == "FAIL" for c in report.checks)


def test_bad_signature_fails_named(enrolled_key, enrolled_key_hex):
    good = _checkpoint_cose(enrolled_key, mmr_size=10)
    outer = cbor2.loads(good)
    protected, unprotected, payload, _sig = outer.value
    tampered = cbor2.dumps(cbor2.CBORTag(outer.tag, [protected, unprotected, payload, b"\x00" * 64]))
    report = check_checkpoint_wire(tampered, expected_pubkey_hex=enrolled_key_hex)
    assert report.has_failure
    assert report.claims is None
    assert any(c.name == "signature_self_consistent" and c.status == "FAIL" for c in report.checks)


def test_wrong_iss_fails_enrolled_log_id_check(enrolled_key, enrolled_key_hex):
    """A checkpoint from a DIFFERENT log claiming to be trace-registry's peer
    -- structurally fine, just not the identity we enrolled."""
    cose = _checkpoint_cose(enrolled_key, log_id="some-other-log/v1", mmr_size=10)
    report = check_checkpoint_wire(cose, expected_log_id=_LOG_ID, expected_pubkey_hex=enrolled_key_hex)
    assert report.has_failure
    assert report.claims is not None  # wire itself was fine
    assert any(c.name == "enrolled_log_id" and c.status == "FAIL" for c in report.checks)


def test_valid_signature_wrong_key_fails_enrolled_key_check():
    """THE distinguishing case: a checkpoint that is fully self-consistent
    (validly signed under its OWN kid) but signed by a keypair that is NOT
    the one we enrolled for trace-registry/v1. Generic COSE verification
    alone cannot catch this -- only comparing against the specific enrolled
    key can, which is exactly what `enrolled_key` exists to check."""
    impostor_key = Ed25519PrivateKey.generate()
    real_enrolled_key = Ed25519PrivateKey.generate()
    cose = _checkpoint_cose(impostor_key, mmr_size=10)  # self-consistent, wrong signer
    report = check_checkpoint_wire(
        cose,
        expected_log_id=_LOG_ID,
        expected_pubkey_hex=real_enrolled_key.public_key().public_bytes_raw().hex(),
    )
    assert report.has_failure
    assert any(c.name == "signature_self_consistent" and c.status == "PASS" for c in report.checks)
    assert any(c.name == "enrolled_key" and c.status == "FAIL" for c in report.checks)


# --- check_chain_continuity (task item 4 -- the critical regression check) --


def test_chain_continuity_passes_for_a_correctly_chained_pair(enrolled_key, enrolled_key_hex):
    peaks1 = _peaks_for("chain-100")
    cp1 = check_checkpoint_wire(
        _checkpoint_cose(enrolled_key, mmr_size=100, new_peaks=peaks1),
        expected_pubkey_hex=enrolled_key_hex,
    ).claims
    cp2 = check_checkpoint_wire(
        _checkpoint_cose(enrolled_key, mmr_size=150, prev_size=100, new_peaks=_peaks_for("chain-150"), prev_peaks=peaks1),
        expected_pubkey_hex=enrolled_key_hex,
    ).claims
    report = check_chain_continuity(cp1, cp2)
    assert not report.has_failure, report.render()


def test_chain_continuity_flags_fresh_chain_regression(enrolled_key, enrolled_key_hex):
    """Pins the EXACT reported bug: ephemeral runner state minting a fresh
    chain every ~15 minutes instead of continuing the one chain -- the
    second checkpoint's prev_size/prev_commitment don't chain from the
    first's log_size/commitment (they look like ANOTHER first checkpoint)."""
    cp1 = check_checkpoint_wire(
        _checkpoint_cose(enrolled_key, mmr_size=100, new_peaks=_peaks_for("chain-100")),
        expected_pubkey_hex=enrolled_key_hex,
    ).claims
    # A "second" checkpoint that is really a fresh chain start (prev_size=0),
    # 15 minutes later, log_size larger but NOT chained from cp1.
    cp2 = check_checkpoint_wire(
        _checkpoint_cose(enrolled_key, mmr_size=5, prev_size=0, new_peaks=_peaks_for("fresh-chain-5")),
        expected_pubkey_hex=enrolled_key_hex,
    ).claims
    report = check_chain_continuity(cp1, cp2)
    assert report.has_failure
    detail = next(c.detail for c in report.checks if c.name == "chain_continuity")
    assert "ephemeral-runner-state regression" in detail


def test_chain_continuity_fails_on_non_increasing_log_size(enrolled_key, enrolled_key_hex):
    cp1 = check_checkpoint_wire(
        _checkpoint_cose(enrolled_key, mmr_size=100), expected_pubkey_hex=enrolled_key_hex
    ).claims
    cp2 = check_checkpoint_wire(
        _checkpoint_cose(enrolled_key, mmr_size=100, new_peaks=_peaks_for("dup-100")),
        expected_pubkey_hex=enrolled_key_hex,
    ).claims
    report = check_chain_continuity(cp1, cp2)
    assert report.has_failure


# --- check_countersign_grade (task item 2 -- gap-aware) ----------------------


def test_grade_check_reports_unknown_when_no_field_configured():
    report = check_countersign_grade({})
    assert not report.has_failure
    status = {c.name: c.status for c in report.checks}
    assert status["countersign_grade"] == "UNKNOWN"


def test_grade_check_passes_and_fails_once_a_field_name_is_known():
    ok = check_countersign_grade({"grade": "observed"}, grade_field="grade")
    assert not ok.has_failure

    bad = check_countersign_grade({"grade": "mmr-verified"}, grade_field="grade")
    assert bad.has_failure


# --- full pipeline against the real server code path (TestClient, no network) --


def test_full_pipeline_ties_back_to_a_registered_checkpoint(client, enrolled_key, enrolled_key_hex):
    """Proves check_witness_tie_back genuinely round-trips against the real
    /checkpoints + /v1/inclusion/{capsule_id} + authority-pubkey routes --
    the exact sequence the watcher runs once a real trace-registry
    checkpoint exists to hand it."""
    cose = _checkpoint_cose(enrolled_key, mmr_size=42, new_peaks=_peaks_for("live-42"))
    wire = check_checkpoint_wire(cose, expected_pubkey_hex=enrolled_key_hex)
    assert not wire.has_failure, wire.render()

    post_resp = client.post("/checkpoints", content=cose, headers={"Content-Type": _CLL_CONTENT_TYPE})
    assert post_resp.status_code == 200, post_resp.text

    tie_back = check_witness_tie_back(wire.claims, get=client.get)
    assert not tie_back.has_failure, tie_back.render()
    status = {c.name: c.status for c in tie_back.checks}
    assert status["witness_registered"] == "PASS"
    assert status["receipt_offline_verify"] == "PASS"


def test_full_pipeline_tie_back_fails_for_an_unregistered_checkpoint(client, enrolled_key, enrolled_key_hex):
    """Negative case: a checkpoint that wire-verifies but was NEVER posted to
    this witness must FAIL the tie-back, not silently pass."""
    cose = _checkpoint_cose(enrolled_key, mmr_size=99, new_peaks=_peaks_for("never-posted-99"))
    wire = check_checkpoint_wire(cose, expected_pubkey_hex=enrolled_key_hex)
    assert not wire.has_failure

    tie_back = check_witness_tie_back(wire.claims, get=client.get)
    assert tie_back.has_failure
    assert any(c.name == "witness_registered" and c.status == "FAIL" for c in tie_back.checks)
