# SPDX-License-Identifier: Apache-2.0
"""Tests for `capsule_anchor.cross_witness_conformance` -- the checker built
ahead of AgenTrust's trace-registry publishing its first real CLL checkpoint
(see `[trace-registry-first-checkpoint-conformance]`).

Checkpoint construction here deliberately mirrors
`test_checkpoints_and_register_witness_host.py`'s `_checkpoint_cose` helper
independently (same reasoning that file itself states: this tool must
verify what a STRANGER's bytes claim, never trusting a shared builder to
agree with itself).

Most tests build their OWN small `SubmitterAllowlist` (rather than relying
on the real committed config) so they stay independent of whatever the real
AgenTrust key happens to be and never touch `configure_submitters`'s
process-wide state. `test_defaults_match_the_real_shipped_config` is the one
place that cross-checks against the actual committed file.

The `test_full_pipeline_*` tests use the real FastAPI app via `TestClient`
(in-process, no network) to prove `check_witness_tie_back` genuinely works
against the real server code path -- not a live hit against the deployed
witness (no live-network tests here; see NOTES.md). They deliberately use a
log_id NOT present in the real committed config, so they exercise the
default-open path without depending on or mutating the real enrollment.
"""
from __future__ import annotations

import hashlib

import cbor2
import pytest
from capsule_anchor.anchoring.submitters import (
    ACCUMULATOR_FOREIGN,
    ACCUMULATOR_NATIVE_MMR,
    DEFAULT_CONFIG_PATH,
    GRADE_COUNTERSIGNED_OBSERVED,
    GRADE_MMR_VERIFIED,
    SubmitterAllowlist,
)
from capsule_anchor.app import create_app
from capsule_anchor.cross_witness_conformance.checker import (
    DEFAULT_EXPECTED_GRADE,
    DEFAULT_EXPECTED_LOG_ID,
    check_chain_continuity,
    check_checkpoint_wire,
    check_witness_tie_back,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from fastapi.testclient import TestClient
from scitt_cose.statement import build_signed_statement

_CLL_CONTENT_TYPE = "application/cll-checkpoint+cbor"
_WIRE_KIND = "cll-checkpoint"
_LOG_ID = "trace-registry/v1"
_PIPELINE_TEST_LOG_ID = "trace-registry-conformance-pipeline-test/v1"  # NOT in the real config


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


def _allowlist(*, log_id: str = _LOG_ID, pubkey: bytes, accumulator: str = ACCUMULATOR_FOREIGN) -> SubmitterAllowlist:
    return SubmitterAllowlist.from_list(
        [{"log_id": log_id, "pubkey_hex": pubkey.hex(), "accumulator": accumulator, "rate_limit_per_min": 60}]
    )


@pytest.fixture()
def enrolled_key() -> Ed25519PrivateKey:
    """Stands in for AgenTrust's real private key (which this repo never
    holds) -- tests pin an `_allowlist()` to THIS key's own pubkey, exactly
    like `test_checkpoints_and_register_witness_host.py`'s `agentrust_key`
    fixture, so they don't depend on the real committed key."""
    return Ed25519PrivateKey.generate()


@pytest.fixture()
def client():
    return TestClient(create_app())


# --- check_checkpoint_wire (task items 1 + 2: wire + enrolled identity/grade) --


def test_valid_checkpoint_passes_every_wire_check(enrolled_key):
    allowlist = _allowlist(pubkey=enrolled_key.public_key().public_bytes_raw())
    cose = _checkpoint_cose(enrolled_key, mmr_size=10)
    report = check_checkpoint_wire(cose, expected_log_id=_LOG_ID, allowlist=allowlist)
    assert not report.has_failure, report.render()
    names = {c.name for c in report.checks}
    assert names == {"wire_structure", "signature_verified", "sub_pattern", "enrolled_log_id", "countersign_grade"}
    assert report.claims["log_id"] == _LOG_ID
    assert report.claims["mmr_size"] == 10
    assert report.claims["grade"] == GRADE_COUNTERSIGNED_OBSERVED


def test_wrong_content_type_fails_named(enrolled_key):
    allowlist = _allowlist(pubkey=enrolled_key.public_key().public_bytes_raw())
    cose = _checkpoint_cose(enrolled_key, mmr_size=10, content_type="application/json")
    report = check_checkpoint_wire(cose, allowlist=allowlist)
    assert report.has_failure
    assert report.claims is None
    assert any(c.name == "wire_structure" and c.status == "FAIL" for c in report.checks)


def test_bad_signature_fails_named(enrolled_key):
    allowlist = _allowlist(pubkey=enrolled_key.public_key().public_bytes_raw())
    good = _checkpoint_cose(enrolled_key, mmr_size=10)
    outer = cbor2.loads(good)
    protected, unprotected, payload, _sig = outer.value
    tampered = cbor2.dumps(cbor2.CBORTag(outer.tag, [protected, unprotected, payload, b"\x00" * 64]))
    report = check_checkpoint_wire(tampered, allowlist=allowlist)
    assert report.has_failure
    assert report.claims is None
    assert any(c.name == "signature_verified" and c.status == "FAIL" for c in report.checks)


def test_wrong_iss_fails_enrolled_log_id_check(enrolled_key):
    """A checkpoint from a DIFFERENT log claiming to be trace-registry's peer
    -- structurally fine (and not enrolled, so it verifies via the open
    self-asserted-kid path), just not the identity we enrolled."""
    allowlist = _allowlist(pubkey=enrolled_key.public_key().public_bytes_raw())
    cose = _checkpoint_cose(enrolled_key, log_id="some-other-log/v1", mmr_size=10)
    report = check_checkpoint_wire(cose, expected_log_id=_LOG_ID, allowlist=allowlist)
    assert report.has_failure
    assert report.claims is not None  # wire itself was fine
    assert any(c.name == "enrolled_log_id" and c.status == "FAIL" for c in report.checks)


def test_impostor_signature_under_enrolled_iss_fails_at_signature_stage():
    """THE core protection, from the read side: enrolling trace-registry/v1
    pins verification to AgenTrust's key -- the self-asserted COSE `kid` is
    ignored entirely for that iss (`#33`). A checkpoint claiming
    `trace-registry/v1` but signed (and self-asserting kid) with a
    DIFFERENT, unenrolled key must fail at signature verification, not pass
    through as "self-consistent but wrong identity" -- there is no such
    intermediate state anymore now that the server pins the key itself."""
    impostor_key = Ed25519PrivateKey.generate()
    real_enrolled_key = Ed25519PrivateKey.generate()
    allowlist = _allowlist(pubkey=real_enrolled_key.public_key().public_bytes_raw())
    cose = _checkpoint_cose(impostor_key, mmr_size=10)  # self-asserts its OWN kid, claims log_id
    report = check_checkpoint_wire(cose, expected_log_id=_LOG_ID, allowlist=allowlist)
    assert report.has_failure
    assert report.claims is None
    assert any(c.name == "wire_structure" and c.status == "PASS" for c in report.checks)
    assert any(
        c.name == "signature_verified" and c.status == "FAIL" and "pinned" in c.detail
        for c in report.checks
    )


def test_grade_fails_when_expecting_mmr_verified_for_a_foreign_entry(enrolled_key):
    """Pins the foreign-accumulator-honesty requirement itself: even if a
    checkpoint is otherwise perfect, claiming/expecting mmr-verified for a
    submitter enrolled as foreign must FAIL, never silently pass."""
    allowlist = _allowlist(pubkey=enrolled_key.public_key().public_bytes_raw(), accumulator=ACCUMULATOR_FOREIGN)
    cose = _checkpoint_cose(enrolled_key, mmr_size=10)
    report = check_checkpoint_wire(cose, allowlist=allowlist, expected_grade=GRADE_MMR_VERIFIED)
    assert report.has_failure
    assert any(c.name == "countersign_grade" and c.status == "FAIL" for c in report.checks)


def test_grade_passes_for_a_native_mmr_entry_expecting_mmr_verified(enrolled_key):
    allowlist = _allowlist(pubkey=enrolled_key.public_key().public_bytes_raw(), accumulator=ACCUMULATOR_NATIVE_MMR)
    cose = _checkpoint_cose(enrolled_key, mmr_size=10)
    report = check_checkpoint_wire(cose, allowlist=allowlist, expected_grade=GRADE_MMR_VERIFIED)
    assert not report.has_failure, report.render()
    assert report.claims["grade"] == GRADE_MMR_VERIFIED


def test_grade_fails_when_log_id_is_not_enrolled_at_all(enrolled_key):
    """If trace-registry/v1 ever drops out of the deployed allowlist (config
    drift), a checkpoint claiming that iss still verifies (falls back to
    open self-asserted-kid behavior) but carries grade=None -- this must
    FAIL the grade check, not be silently treated as fine."""
    empty_allowlist = SubmitterAllowlist({})
    cose = _checkpoint_cose(enrolled_key, mmr_size=10)
    report = check_checkpoint_wire(cose, allowlist=empty_allowlist)
    assert report.has_failure
    assert report.claims["grade"] is None
    assert any(c.name == "countersign_grade" and c.status == "FAIL" for c in report.checks)


def test_grade_check_reports_unknown_when_no_expectation_configured(enrolled_key):
    allowlist = _allowlist(pubkey=enrolled_key.public_key().public_bytes_raw())
    cose = _checkpoint_cose(enrolled_key, mmr_size=10)
    report = check_checkpoint_wire(cose, allowlist=allowlist, expected_grade=None)
    assert not report.has_failure
    status = {c.name: c.status for c in report.checks}
    assert status["countersign_grade"] == "UNKNOWN"


def test_defaults_match_the_real_shipped_config():
    """Catches drift between this tool's defaults and the actual committed
    enrollment -- if AgenTrust's entry is ever re-enrolled with a different
    accumulator, this fails loudly instead of the checker silently checking
    against a stale expectation."""
    allowlist = SubmitterAllowlist.load(DEFAULT_CONFIG_PATH)
    entry = allowlist.get(DEFAULT_EXPECTED_LOG_ID)
    assert entry is not None, f"{DEFAULT_EXPECTED_LOG_ID!r} is not enrolled in the shipped config"
    assert entry.grade == DEFAULT_EXPECTED_GRADE


# --- check_chain_continuity (task item 4 -- the critical regression check) --


def test_chain_continuity_passes_for_a_correctly_chained_pair(enrolled_key):
    allowlist = _allowlist(pubkey=enrolled_key.public_key().public_bytes_raw())
    peaks1 = _peaks_for("chain-100")
    cp1 = check_checkpoint_wire(
        _checkpoint_cose(enrolled_key, mmr_size=100, new_peaks=peaks1), allowlist=allowlist
    ).claims
    cp2 = check_checkpoint_wire(
        _checkpoint_cose(
            enrolled_key, mmr_size=150, prev_size=100, new_peaks=_peaks_for("chain-150"), prev_peaks=peaks1
        ),
        allowlist=allowlist,
    ).claims
    report = check_chain_continuity(cp1, cp2)
    assert not report.has_failure, report.render()


def test_chain_continuity_flags_fresh_chain_regression(enrolled_key):
    """Pins the EXACT reported bug: ephemeral runner state minting a fresh
    chain every ~15 minutes instead of continuing the one chain -- the
    second checkpoint's prev_size/prev_commitment don't chain from the
    first's log_size/commitment (they look like ANOTHER first checkpoint)."""
    allowlist = _allowlist(pubkey=enrolled_key.public_key().public_bytes_raw())
    cp1 = check_checkpoint_wire(
        _checkpoint_cose(enrolled_key, mmr_size=100, new_peaks=_peaks_for("chain-100")), allowlist=allowlist
    ).claims
    # A "second" checkpoint that is really a fresh chain start (prev_size=0),
    # 15 minutes later, log_size larger but NOT chained from cp1.
    cp2 = check_checkpoint_wire(
        _checkpoint_cose(enrolled_key, mmr_size=5, prev_size=0, new_peaks=_peaks_for("fresh-chain-5")),
        allowlist=allowlist,
    ).claims
    report = check_chain_continuity(cp1, cp2)
    assert report.has_failure
    detail = next(c.detail for c in report.checks if c.name == "chain_continuity")
    assert "ephemeral-runner-state regression" in detail


def test_chain_continuity_fails_on_non_increasing_log_size(enrolled_key):
    allowlist = _allowlist(pubkey=enrolled_key.public_key().public_bytes_raw())
    cp1 = check_checkpoint_wire(_checkpoint_cose(enrolled_key, mmr_size=100), allowlist=allowlist).claims
    cp2 = check_checkpoint_wire(
        _checkpoint_cose(enrolled_key, mmr_size=100, new_peaks=_peaks_for("dup-100")), allowlist=allowlist
    ).claims
    report = check_chain_continuity(cp1, cp2)
    assert report.has_failure


# --- full pipeline against the real server code path (TestClient, no network) --


def test_full_pipeline_ties_back_to_a_registered_checkpoint(client, enrolled_key):
    """Proves check_witness_tie_back genuinely round-trips against the real
    /checkpoints + /v1/inclusion/{capsule_id} + authority-pubkey routes --
    the exact sequence the watcher runs once a real trace-registry
    checkpoint exists to hand it. Uses a log_id NOT in the real committed
    config, so this stays on the pre-existing open self-asserted-kid path
    regardless of what's actually enrolled -- this test is about the tie-
    back plumbing, not the enrollment/grade logic (covered above)."""
    cose = _checkpoint_cose(enrolled_key, log_id=_PIPELINE_TEST_LOG_ID, mmr_size=42, new_peaks=_peaks_for("live-42"))
    wire = check_checkpoint_wire(cose, expected_log_id=_PIPELINE_TEST_LOG_ID, expected_grade=None)
    assert not wire.has_failure, wire.render()

    post_resp = client.post("/checkpoints", content=cose, headers={"Content-Type": _CLL_CONTENT_TYPE})
    assert post_resp.status_code == 200, post_resp.text

    tie_back = check_witness_tie_back(wire.claims, get=client.get)
    assert not tie_back.has_failure, tie_back.render()
    status = {c.name: c.status for c in tie_back.checks}
    assert status["witness_registered"] == "PASS"
    assert status["receipt_offline_verify"] == "PASS"


def test_full_pipeline_tie_back_fails_for_an_unregistered_checkpoint(client, enrolled_key):
    """Negative case: a checkpoint that wire-verifies but was NEVER posted to
    this witness must FAIL the tie-back, not silently pass."""
    cose = _checkpoint_cose(
        enrolled_key, log_id=_PIPELINE_TEST_LOG_ID, mmr_size=99, new_peaks=_peaks_for("never-posted-99")
    )
    wire = check_checkpoint_wire(cose, expected_log_id=_PIPELINE_TEST_LOG_ID, expected_grade=None)
    assert not wire.has_failure

    tie_back = check_witness_tie_back(wire.claims, get=client.get)
    assert tie_back.has_failure
    assert any(c.name == "witness_registered" and c.status == "FAIL" for c in tie_back.checks)
