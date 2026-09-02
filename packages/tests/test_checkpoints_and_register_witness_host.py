# SPDX-License-Identifier: Apache-2.0
"""Tests for the witness-host canonical routes: POST /checkpoints (default) and
POST /register (explicit opt-in) -- both always reachable on the SAME service,
per the single-host witness ruling (2026-08-27, supersedes the earlier
WITNESS_ONLY separate-deployment plan from #29).

``/checkpoints`` is STAGE 1 of the CLL (Checkpointed Local Log,
draft-mih-scitt-checkpointed-local-log) checkpoint witness: a SEPARATE,
stricter surface from the ``mmr-checkpoint`` artifact_type recognition on
``/transparency/register-statement`` (see ``test_checkpoint_witness.py``).

Since the [cll-checkpoint-cose-wire] wire alignment (rider 1, 2026-08-27)
this surface accepts a COSE_Sign1 statement (RFC 8949 canonical CBOR claims,
content type ``application/cll-checkpoint+cbor``) -- NOT JSON. This file
builds those COSE statements from scratch with ``scitt_cose`` + ``cbor2`` +
``cryptography`` alone, deliberately never importing capsule-emit: the
witness (and these tests) must exercise verifying what a STRANGER's bytes
claim, independent of any capsule-emit-side opinion of them (same boundary
rule ``capsule_anchor.anchoring.checkpoint_cose`` itself follows).

This surface:
  * accepts a COSE-wire CLL checkpoint statement and refuses anything else
    with a named error (400) -- BEFORE any signature check;
  * independently verifies the checkpoint's own COSE_Sign1 signature
    server-side before ever counter-signing -- 401 on failure, never
    appended/counter-signed;
  * is STATELESS: no per-log_id monotonicity/rollback/chain-linkage check,
    no MMR math -- existence-and-time evidence for one checkpoint only.

``/register`` is the explicit opt-in, plain-SCITT-interop digest-registration
route -- identical behavior to the legacy ``/v1/digest`` alias (see
``test_endpoint_consolidation.py`` for the legacy-route coverage), UNCHANGED
by the COSE-wire alignment (it never touches checkpoints at all). Privacy is
enforced at the ROUTE level here, not a host-level gate: both routes are
always reachable on this same service -- see ``test_no_host_level_gate``
below, and ``capsule_emit``'s no-egress CI test for the client-side half of
this guarantee.
"""
from __future__ import annotations

import hashlib
import json

import cbor2
import pytest
from capsule_anchor.app import create_app
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from fastapi.testclient import TestClient
from scitt_cose.statement import build_signed_statement

#: Must match capsule_anchor.anchoring.checkpoint_cose.CLL_CHECKPOINT_CONTENT_TYPE
#: (== capsule_emit.checkpoint.cose_wire.CLL_CHECKPOINT_CONTENT_TYPE) exactly.
_CLL_CONTENT_TYPE = "application/cll-checkpoint+cbor"
_WIRE_KIND = "cll-checkpoint"


def _root_from_peaks(peak_hashes: list[bytes]) -> bytes:
    """Same right-to-left pairwise fold as ``checkpoint_cose._root_from_peaks``
    / ``capsule_emit.checkpoint.core.root_from_peaks`` -- reimplemented here,
    independently, so this test file can predict the ``root``/``prev_root``
    the server itself derives from a submitted peak-list commitment."""
    if not peak_hashes:
        return bytes(32)
    hashes = list(peak_hashes)
    while len(hashes) > 1:
        right = hashes.pop()
        left = hashes.pop()
        hashes.append(hashlib.sha256(right + left).digest())
    return hashes[0]


def _commitment(peak_hashes: list[bytes]) -> bytes:
    """The MMRIVER-conformant commitment object: canonical CBOR ``[ *bstr ]``."""
    return cbor2.dumps(peak_hashes, canonical=True)


def _peaks_for(seed: str, n: int = 1) -> list[bytes]:
    """``n`` synthetic 32-byte peak hashes, deterministic from ``seed`` --
    these tests never run a real MMR, they only need SOME peak list whose
    fold (:func:`_root_from_peaks`) the server can independently reproduce."""
    return [hashlib.sha256(f"{seed}-{i}".encode()).digest() for i in range(n)]


def _pem(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


def _checkpoint_claims(
    *,
    mmr_size: int,
    new_peaks: list[bytes],
    prev_size: int = 0,
    prev_peaks: list[bytes] | None = None,
    issued_at: str = "2026-08-26T00:00:00Z",
    kind: str = _WIRE_KIND,
) -> dict:
    return {
        "kind": kind,
        "log_size": mmr_size,
        "commitment": _commitment(new_peaks),
        "prev_size": prev_size,
        "prev_commitment": _commitment(prev_peaks) if prev_peaks else b"",
        "issued_at": issued_at,
    }


def _checkpoint_cose(
    key: Ed25519PrivateKey,
    *,
    log_id: str,
    mmr_size: int,
    prev_size: int = 0,
    new_peaks: list[bytes] | None = None,
    prev_peaks: list[bytes] | None = None,
    issued_at: str = "2026-08-26T00:00:00Z",
    kid: bytes | None = None,
    content_type: str = _CLL_CONTENT_TYPE,
    subject: str | None = None,
    claims: dict | None = None,
) -> bytes:
    """Build a COSE_Sign1 CLL checkpoint statement from scratch, signed by
    ``key``. ``kid`` defaults to ``key``'s own raw public bytes (the honest
    case); pass a DIFFERENT 32 bytes to simulate a checkpoint whose claimed
    signer does not match who actually signed it. ``claims`` overrides the
    whole claims map (for malformed/adversarial payloads); otherwise built
    from the other kwargs via :func:`_checkpoint_claims`.
    """
    if new_peaks is None:
        new_peaks = _peaks_for(f"{log_id}-{mmr_size}")
    if claims is None:
        claims = _checkpoint_claims(
            mmr_size=mmr_size,
            new_peaks=new_peaks,
            prev_size=prev_size,
            prev_peaks=prev_peaks,
            issued_at=issued_at,
        )
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


def _tamper_payload(cose_bytes: bytes, new_claims: dict) -> bytes:
    """Swap a COSE_Sign1 statement's payload for a DIFFERENT claims map
    while leaving its protected header and signature bytes untouched -- the
    signature no longer covers the new payload, so this always fails
    verification cleanly (unlike flipping a random byte, which risks
    corrupting the outer CBOR structure and getting a different, unrelated
    "malformed" error instead of a clean signature failure)."""
    outer = cbor2.loads(cose_bytes)
    protected, unprotected, _payload, signature = outer.value
    new_payload = cbor2.dumps(new_claims, canonical=True)
    return cbor2.dumps(cbor2.CBORTag(outer.tag, [protected, unprotected, new_payload, signature]))


def _expected_record(
    *,
    log_id: str,
    mmr_size: int,
    new_peaks: list[bytes],
    prev_size: int = 0,
    prev_peaks: list[bytes] | None = None,
    issued_at: str = "2026-08-26T00:00:00Z",
    key_id: str,
) -> dict:
    """The 9-field ``CheckpointRecord``-shaped dict the server reconstructs
    from a COSE statement built with the same parameters -- what
    ``AnchorerService.witness_checkpoint``'s digest/idempotency scheme is
    computed over. MUST match ``checkpoint_cose.parse_and_verify_checkpoint_cose``'s
    own reconstruction exactly."""
    return {
        "v": 1,
        "kind": "mmr_checkpoint",
        "log_id": log_id,
        "mmr_size": mmr_size,
        "root": _root_from_peaks(new_peaks).hex(),
        "prev_size": prev_size,
        "prev_root": _root_from_peaks(prev_peaks).hex() if prev_peaks else "",
        "key_id": key_id,
        "timestamp": issued_at,
    }


def _signing_body(cp: dict) -> bytes:
    fields = (
        "v", "kind", "log_id", "mmr_size", "root", "prev_size", "prev_root", "key_id", "timestamp",
    )
    body = {k: cp[k] for k in fields}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def _digest(cp: dict) -> str:
    return hashlib.sha256(_signing_body(cp)).hexdigest()


def _entry_hash(cp: dict) -> str:
    return hashlib.sha256(bytes.fromhex(_digest(cp))).hexdigest()


@pytest.fixture()
def key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture()
def client():
    return TestClient(create_app())


def _post_checkpoint(client: TestClient, cose_bytes: bytes) -> tuple[int, dict]:
    resp = client.post(
        "/checkpoints", content=cose_bytes, headers={"Content-Type": _CLL_CONTENT_TYPE}
    )
    return resp.status_code, (resp.json() if resp.content else {})


# --- accepted path -----------------------------------------------------------


def test_checkpoint_accepted_returns_stamp(client, key):
    new_peaks = _peaks_for("log-A-100")
    cose = _checkpoint_cose(key, log_id="log-A", mmr_size=100, new_peaks=new_peaks)
    expected = _expected_record(
        log_id="log-A", mmr_size=100, new_peaks=new_peaks, key_id=key.public_key().public_bytes_raw().hex()
    )
    status, body = _post_checkpoint(client, cose)
    assert status == 200, body
    assert body["entry_hash"] == _entry_hash(expected)
    assert body["entry_hash_scheme"] == "legacy"
    assert body["leaf_index"] == 0
    assert body["tree_size"] == 1
    assert body["receipt_b64"]


def test_resubmitting_the_same_checkpoint_is_idempotent(client, key):
    cose = _checkpoint_cose(key, log_id="log-B", mmr_size=50, new_peaks=_peaks_for("log-B-50"))
    s1, b1 = _post_checkpoint(client, cose)
    s2, b2 = _post_checkpoint(client, cose)
    assert s1 == s2 == 200
    assert b1["entry_hash"] == b2["entry_hash"]
    assert b1["leaf_index"] == b2["leaf_index"]


# --- checkpoint-only gate: reject non-checkpoint / malformed artifacts -------


def test_non_checkpoint_content_type_refused_with_named_error(client, key):
    """A well-formed, well-signed COSE_Sign1 statement for a DIFFERENT
    purpose (wrong content type) is not a CLL checkpoint -- refused by name,
    never signature-checked as if it were one."""
    claims = {"unrelated": "payload"}
    payload = cbor2.dumps(claims, canonical=True)
    cose = build_signed_statement(
        payload,
        alg="EdDSA",
        private_key_pem=_pem(key),
        issuer="log-X",
        subject="log-X#1",
        content_type="application/some-other-statement+cbor",
        kid=key.public_key().public_bytes_raw(),
    )
    status, body = _post_checkpoint(client, cose)
    assert status == 400
    assert "checkpoint" in body["detail"].lower()


def test_garbage_bytes_refused_400_not_500(client):
    """Bytes that aren't even valid COSE/CBOR at all -- the checkpoint-only
    gate's most basic case -- never a 500."""
    status, body = _post_checkpoint(client, b"not-cose-at-all")
    assert status == 400
    assert "malformed" in body["detail"].lower() or "cose" in body["detail"].lower()


def test_missing_commitment_claim_refused_400(client, key):
    claims = _checkpoint_claims(mmr_size=10, new_peaks=_peaks_for("log-C-10"))
    del claims["commitment"]
    cose = _checkpoint_cose(key, log_id="log-C", mmr_size=10, claims=claims)
    status, body = _post_checkpoint(client, cose)
    assert status == 400
    assert "commitment" in body["detail"].lower()


def test_wrong_kind_refused_400(client, key):
    cose = _checkpoint_cose(
        key, log_id="log-D", mmr_size=10, new_peaks=_peaks_for("log-D-10"),
        claims=_checkpoint_claims(mmr_size=10, new_peaks=_peaks_for("log-D-10"), kind="offer_terms"),
    )
    status, body = _post_checkpoint(client, cose)
    assert status == 400
    assert "kind" in body["detail"].lower()


def test_malformed_commitment_refused_400(client, key):
    claims = _checkpoint_claims(mmr_size=10, new_peaks=_peaks_for("log-E-10"))
    claims["commitment"] = cbor2.dumps([b"too-short"], canonical=True)  # not 32-byte peaks
    cose = _checkpoint_cose(key, log_id="log-E", mmr_size=10, claims=claims)
    status, body = _post_checkpoint(client, cose)
    assert status == 400


def test_prev_size_not_less_than_mmr_size_refused_400(client, key):
    claims = _checkpoint_claims(
        mmr_size=10, new_peaks=_peaks_for("log-F-10"), prev_size=10, prev_peaks=_peaks_for("log-F-prev")
    )
    cose = _checkpoint_cose(key, log_id="log-F", mmr_size=10, claims=claims)
    status, body = _post_checkpoint(client, cose)
    assert status == 400


# --- signature verification ---------------------------------------------------


def test_invalid_signature_refused_401_and_never_countersigned(client, key):
    cose = _checkpoint_cose(key, log_id="log-G", mmr_size=100, new_peaks=_peaks_for("log-G-100"))
    tampered = _tamper_payload(
        cose, _checkpoint_claims(mmr_size=999, new_peaks=_peaks_for("log-G-999"))  # tamper after signing
    )
    sth_before = client.get("/anchor/sth")
    status, body = _post_checkpoint(client, tampered)
    assert status == 401, body
    assert "signature" in body["detail"].lower()
    # nothing appended: STH still empty (log was untouched by the refusal)
    sth_after = client.get("/anchor/sth")
    assert sth_before.status_code == sth_after.status_code == 503


def test_signature_by_wrong_key_refused_401(client, key):
    other_key = Ed25519PrivateKey.generate()
    # signed by `key`, but the envelope CLAIMS `other_key`'s public bytes as its kid
    cose = _checkpoint_cose(
        key, log_id="log-H", mmr_size=10, new_peaks=_peaks_for("log-H-10"),
        kid=other_key.public_key().public_bytes_raw(),
    )
    status, body = _post_checkpoint(client, cose)
    assert status == 401, body


def test_missing_kid_refused_400_not_500(client, key):
    """No/short kid is a STRUCTURAL problem the checkpoint-only gate catches
    BEFORE any signature check is even attempted (there is no key to check
    against) -- 400, not 401; still never a 500."""
    cose = _checkpoint_cose(
        key, log_id="log-I", mmr_size=10, new_peaks=_peaks_for("log-I-10"), kid=b"too-short"
    )
    status, body = _post_checkpoint(client, cose)
    assert status == 400, body


# --- statelessness: no MMR math, no per-log_id continuity check --------------


def test_stateless_no_rollback_check_across_same_log_id(client, key):
    """Unlike /transparency/register-statement's mmr-checkpoint path, this
    surface does NOT track per-log_id state -- a checkpoint that would be a
    rollback/fork against a prior one for the SAME log_id is still accepted
    (each checkpoint is judged only on its own signature), because stage 1
    is stateless by design."""
    cose1 = _checkpoint_cose(key, log_id="log-J", mmr_size=100, new_peaks=_peaks_for("log-J-100"))
    s1, b1 = _post_checkpoint(client, cose1)
    assert s1 == 200, b1

    # A "rollback" shape (mmr_size smaller than the previous submission for
    # the same log_id) — would 409 on the stateful surface, but this route
    # never consults or stores per-log_id state.
    cose2 = _checkpoint_cose(
        key, log_id="log-J", mmr_size=50, new_peaks=_peaks_for("log-J-50"), issued_at="2026-08-26T00:05:00Z"
    )
    s2, b2 = _post_checkpoint(client, cose2)
    assert s2 == 200, b2
    assert b2["leaf_index"] != b1["leaf_index"]


def test_two_valid_checkpoints_get_distinct_leaves(client, key):
    peaks_10 = _peaks_for("log-K-10")
    cose1 = _checkpoint_cose(key, log_id="log-K", mmr_size=10, new_peaks=peaks_10)
    cose2 = _checkpoint_cose(
        key, log_id="log-K", mmr_size=20, new_peaks=_peaks_for("log-K-20"),
        prev_size=10, prev_peaks=peaks_10, issued_at="2026-08-26T00:10:00Z",
    )
    s1, b1 = _post_checkpoint(client, cose1)
    s2, b2 = _post_checkpoint(client, cose2)
    assert s1 == s2 == 200
    assert b1["entry_hash"] != b2["entry_hash"]
    assert b1["leaf_index"] != b2["leaf_index"]


# --- /register: explicit opt-in digest registration ---------------------------


def test_register_returns_full_scitt_receipt(client):
    cid = "c" * 64
    resp = client.post("/register", json={"capsule_id": cid})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["entry_hash"] == hashlib.sha256(bytes.fromhex(cid)).hexdigest()
    assert body["entry_hash_scheme"] == "legacy"
    assert body["receipt_b64"]


def test_register_is_byte_identical_to_legacy_v1_digest(client):
    """/register is the canonical name; /v1/digest is the legacy alias kept for
    existing anchor.aac callers -- same handler, so a given capsule_id produces
    the identical receipt shape through either route."""
    cid = "d" * 64
    via_register = client.post("/register", json={"capsule_id": cid})
    via_legacy = client.post("/v1/digest", json={"capsule_id": cid})
    assert via_register.status_code == via_legacy.status_code == 200
    assert via_register.json() == via_legacy.json()


def test_register_never_accepts_a_checkpoint_cose_body_as_a_digest(client, key):
    """/register treats its body as a JSON ``{"capsule_id": ...}`` request --
    posting raw COSE checkpoint bytes to it is just a validation error (it
    isn't even JSON), not a channel that bypasses /checkpoints' signature
    verification."""
    cose = _checkpoint_cose(key, log_id="log-L", mmr_size=10, new_peaks=_peaks_for("log-L-10"))
    resp = client.post(
        "/register", content=cose, headers={"Content-Type": "application/json"}
    )
    # COSE/CBOR bytes are not valid JSON at all -- FastAPI's own body parser
    # rejects it (400) before pydantic's DigestRequest model is ever reached.
    assert resp.status_code == 400, resp.text


# --- two-route model: privacy is route-level, not a host-level gate -----------


def test_both_routes_always_reachable_on_the_same_service(client, key, monkeypatch):
    """The witness-host ruling (2026-08-27) replaces the earlier WITNESS_ONLY
    host-level reject (#29) with route-level privacy: /checkpoints (default)
    and /register (opt-in) are BOTH always reachable on one deployment -- there
    is no env flag that hides either. Setting the old WITNESS_ONLY var is a
    no-op now (it named no code path after the supersession)."""
    monkeypatch.setenv("WITNESS_ONLY", "1")
    client = TestClient(create_app())

    cose = _checkpoint_cose(key, log_id="log-M", mmr_size=10, new_peaks=_peaks_for("log-M-10"))
    checkpoint_resp = client.post(
        "/checkpoints", content=cose, headers={"Content-Type": _CLL_CONTENT_TYPE}
    )
    assert checkpoint_resp.status_code == 200, checkpoint_resp.text

    register_resp = client.post("/register", json={"capsule_id": "e" * 64})
    assert register_resp.status_code == 200, register_resp.text

    legacy_digest_resp = client.post("/v1/digest", json={"capsule_id": "f" * 64})
    assert legacy_digest_resp.status_code == 200, legacy_digest_resp.text


def test_legacy_v1_checkpoint_route_no_longer_exists(client, key):
    """/v1/checkpoint (PR #29's original path, never documented, never called
    by any client -- see repo-wide grep) is renamed to /checkpoints outright;
    no dual-mount, no deprecation period, since nothing depended on the old
    path."""
    cose = _checkpoint_cose(key, log_id="log-N", mmr_size=10, new_peaks=_peaks_for("log-N-10"))
    resp = client.post(
        "/v1/checkpoint", content=cose, headers={"Content-Type": _CLL_CONTENT_TYPE}
    )
    assert resp.status_code == 404


# --- enrolled submitter allowlist (submitters.py) -----------------------------
#
# [witness-enroll-trace-registry-key]: /checkpoints was fully open (any
# self-asserted `kid` is trusted, for any `log_id`) before this allowlist
# existed -- see every test above, none of which enroll a log_id and all of
# which keep passing unmodified (proving non-enrolled log_ids stay open).
# These tests cover the NEW, additive behavior: for a log_id present in the
# config-driven allowlist, verification uses the PINNED key from config, and
# the self-asserted `kid` is ignored entirely.

from capsule_anchor.anchoring.router import (  # noqa: E402
    _SlidingWindowLimiter,
    configure_submitters,
)
from capsule_anchor.anchoring.submitters import (  # noqa: E402
    ACCUMULATOR_FOREIGN,
    ACCUMULATOR_NATIVE_MMR,
    DEFAULT_CONFIG_PATH,
    GRADE_COUNTERSIGNED_OBSERVED,
    GRADE_MMR_VERIFIED,
    SubmitterAllowlist,
)

_TRACE_REGISTRY_LOG_ID = "trace-registry/v1"
_TRACE_REGISTRY_PUBKEY_HEX = (
    "bc133259c094f63694b4ec48a295d7501a9a0cd536df5631fb4663c155f7bc90"
)


@pytest.fixture()
def agentrust_key() -> Ed25519PrivateKey:
    """A LOCALLY GENERATED test key standing in for AgenTrust's real private
    key (which this repo never holds) -- used to build "honest" enrolled
    submissions. Tests that need to prove the PINNED key (not this one) is
    what's actually checked configure the allowlist with a DIFFERENT pubkey
    than this key's own."""
    return Ed25519PrivateKey.generate()


def _enroll(
    client: TestClient,
    *,
    log_id: str,
    pubkey: bytes,
    accumulator: str = ACCUMULATOR_FOREIGN,
    rate_limit_per_min: int = 60,
) -> None:
    """Configure the shared allowlist with exactly one entry. Safe to call
    after ``client`` was built -- ``configure_submitters`` is process-wide
    module state, same pattern as ``configure_service``, and the NEXT
    ``create_app()`` call (the next test's ``client`` fixture) resets it back
    to the real shipped default via ``app.py``'s own startup wiring."""
    configure_submitters(
        SubmitterAllowlist.from_list(
            [
                {
                    "log_id": log_id,
                    "pubkey_hex": pubkey.hex(),
                    "accumulator": accumulator,
                    "rate_limit_per_min": rate_limit_per_min,
                }
            ]
        )
    )


def test_real_shipped_config_enrolls_trace_registry_with_foreign_grade():
    """Pins the ACTUAL committed config file, not a synthetic one: the
    exact identity Imran provided (2026-09-01) must be the one that ships."""
    allowlist = SubmitterAllowlist.load(DEFAULT_CONFIG_PATH)
    entry = allowlist.get(_TRACE_REGISTRY_LOG_ID)
    assert entry is not None, "trace-registry/v1 is not enrolled in the shipped config"
    assert entry.pubkey.hex() == _TRACE_REGISTRY_PUBKEY_HEX
    assert entry.accumulator == ACCUMULATOR_FOREIGN
    assert entry.grade == GRADE_COUNTERSIGNED_OBSERVED


def test_enrolled_submission_signed_by_pinned_key_accepted_with_grade(client, agentrust_key):
    """iss contains a "/" ([witness-enroll-trace-registry-key] item 1) and
    the subject pattern `<iss>#<log_size>` -- both flow through unchanged;
    this is the honest, correctly-signed enrolled submission."""
    _enroll(client, log_id=_TRACE_REGISTRY_LOG_ID, pubkey=agentrust_key.public_key().public_bytes_raw())
    cose = _checkpoint_cose(
        agentrust_key, log_id=_TRACE_REGISTRY_LOG_ID, mmr_size=42,
        new_peaks=_peaks_for(f"{_TRACE_REGISTRY_LOG_ID}-42"),
    )
    status, body = _post_checkpoint(client, cose)
    assert status == 200, body
    assert body["grade"] == GRADE_COUNTERSIGNED_OBSERVED


def test_enrolled_native_mmr_submitter_gets_mmr_verified_grade(client, agentrust_key):
    _enroll(
        client, log_id="some-native-log", pubkey=agentrust_key.public_key().public_bytes_raw(),
        accumulator=ACCUMULATOR_NATIVE_MMR,
    )
    cose = _checkpoint_cose(
        agentrust_key, log_id="some-native-log", mmr_size=1, new_peaks=_peaks_for("native-1"),
    )
    status, body = _post_checkpoint(client, cose)
    assert status == 200, body
    assert body["grade"] == GRADE_MMR_VERIFIED


def test_non_enrolled_log_id_stays_open_even_with_allowlist_configured(client, key, agentrust_key):
    """Regression guard: enrolling trace-registry/v1 must not gate any OTHER
    log_id -- a default capsule-emit client using its own arbitrary log_id
    and self-asserted kid keeps working exactly as before enrollment."""
    _enroll(client, log_id=_TRACE_REGISTRY_LOG_ID, pubkey=agentrust_key.public_key().public_bytes_raw())
    cose = _checkpoint_cose(key, log_id="some-other-log", mmr_size=10, new_peaks=_peaks_for("other-10"))
    status, body = _post_checkpoint(client, cose)
    assert status == 200, body
    assert body["grade"] is None


def test_checkpoint_signed_by_unenrolled_key_but_claiming_enrolled_iss_rejects_401(client, key, agentrust_key):
    """The core protection: enrolling trace-registry/v1 pins verification to
    AgenTrust's key. A checkpoint claiming iss=trace-registry/v1 but signed
    (and self-asserting kid) with a DIFFERENT, unenrolled key must be
    rejected -- proves the self-asserted kid is ignored for an enrolled
    iss, not merely re-trusted."""
    _enroll(client, log_id=_TRACE_REGISTRY_LOG_ID, pubkey=agentrust_key.public_key().public_bytes_raw())
    impostor_key = key  # a completely different, unenrolled keypair
    cose = _checkpoint_cose(
        impostor_key, log_id=_TRACE_REGISTRY_LOG_ID, mmr_size=7,
        new_peaks=_peaks_for(f"{_TRACE_REGISTRY_LOG_ID}-impostor-7"),
    )
    status, body = _post_checkpoint(client, cose)
    assert status == 401, body
    assert "signature" in body["detail"].lower()


def test_tampered_signature_under_enrolled_iss_rejects_with_signature_error(client, agentrust_key):
    """A locally-constructed COSE_Sign1 carrying iss=trace-registry/v1 whose
    signature bytes don't verify (here: payload tampered post-signing, same
    technique as test_invalid_signature_refused_401_and_never_countersigned
    above) rejects with a signature error -- proving the PINNED key is what
    gets checked, not merely "was this well-formed"."""
    _enroll(client, log_id=_TRACE_REGISTRY_LOG_ID, pubkey=agentrust_key.public_key().public_bytes_raw())
    cose = _checkpoint_cose(
        agentrust_key, log_id=_TRACE_REGISTRY_LOG_ID, mmr_size=100,
        new_peaks=_peaks_for(f"{_TRACE_REGISTRY_LOG_ID}-100"),
    )
    tampered = _tamper_payload(
        cose,
        _checkpoint_claims(mmr_size=999, new_peaks=_peaks_for(f"{_TRACE_REGISTRY_LOG_ID}-999")),
    )
    status, body = _post_checkpoint(client, tampered)
    assert status == 401, body
    assert "signature" in body["detail"].lower()


def test_unknown_unenrolled_log_id_impersonation_still_rejects_cleanly(client, key, agentrust_key):
    """A checkpoint self-signed end-to-end (valid signature under ITS OWN
    self-asserted kid) but claiming the enrolled trace-registry/v1 identity
    with a key that was never enrolled -- still rejects cleanly (401, never
    a 500, never silently accepted as AgenTrust's stamp)."""
    _enroll(client, log_id=_TRACE_REGISTRY_LOG_ID, pubkey=agentrust_key.public_key().public_bytes_raw())
    unknown_key = Ed25519PrivateKey.generate()
    cose = _checkpoint_cose(
        unknown_key, log_id=_TRACE_REGISTRY_LOG_ID, mmr_size=3,
        new_peaks=_peaks_for(f"{_TRACE_REGISTRY_LOG_ID}-unknown-3"),
    )
    status, body = _post_checkpoint(client, cose)
    assert status == 401, body


def test_grade_is_not_part_of_the_signing_body_or_digest(client, agentrust_key):
    """grade must be purely informational -- an enrolled submission's
    entry_hash/digest is identical to what a non-enrolled submission with
    the same 9 CheckpointRecord fields would produce, so a relying party
    who only holds the 9-field record (no grade) can still recompute
    entry_hash independently (see CheckpointStampResponse's own docstring)."""
    _enroll(client, log_id=_TRACE_REGISTRY_LOG_ID, pubkey=agentrust_key.public_key().public_bytes_raw())
    new_peaks = _peaks_for(f"{_TRACE_REGISTRY_LOG_ID}-55")
    cose = _checkpoint_cose(agentrust_key, log_id=_TRACE_REGISTRY_LOG_ID, mmr_size=55, new_peaks=new_peaks)
    expected = _expected_record(
        log_id=_TRACE_REGISTRY_LOG_ID, mmr_size=55, new_peaks=new_peaks,
        key_id=agentrust_key.public_key().public_bytes_raw().hex(),
    )
    status, body = _post_checkpoint(client, cose)
    assert status == 200, body
    assert body["entry_hash"] == _entry_hash(expected)


def test_per_submitter_rate_limit_429_independent_of_global_limiter(client, agentrust_key, monkeypatch):
    """The global _POST_LIMITER budget (300/min) is untouched; a submitter's
    OWN configured rate_limit_per_min is a SEPARATE, additional budget."""
    monkeypatch.setattr(
        "capsule_anchor.anchoring.router._POST_LIMITER",
        _SlidingWindowLimiter(max_calls=100, window_s=60.0),
    )
    _enroll(
        client, log_id=_TRACE_REGISTRY_LOG_ID, pubkey=agentrust_key.public_key().public_bytes_raw(),
        rate_limit_per_min=1,
    )
    cose1 = _checkpoint_cose(
        agentrust_key, log_id=_TRACE_REGISTRY_LOG_ID, mmr_size=1, new_peaks=_peaks_for("rl-1"),
    )
    cose2 = _checkpoint_cose(
        agentrust_key, log_id=_TRACE_REGISTRY_LOG_ID, mmr_size=2, new_peaks=_peaks_for("rl-2"),
        prev_size=1, prev_peaks=_peaks_for("rl-1"),
    )
    s1, b1 = _post_checkpoint(client, cose1)
    s2, b2 = _post_checkpoint(client, cose2)
    assert s1 == 200, b1
    assert s2 == 429, b2


# --- read-back-by-log_id + equivocation flag (GET /checkpoints/{log_id}) -----
#
# [witness-checkpoint-read-surface]: POST /checkpoints alone gives a watcher
# no way to ask "what's the last checkpoint you witnessed for log_id X?" --
# these cover the queryable read-back surface and its equivocation flag
# (loud-surface detection of two DIFFERENT roots at the SAME position; see
# the module docstring's scope line -- refusing the write is a stage-2
# follow-up, NOT this surface's job -- both submissions below still 200).


def test_readback_unknown_log_id_404(client):
    resp = client.get("/checkpoints/never-seen-log")
    assert resp.status_code == 404


def test_readback_returns_last_checkpoint_claims_and_receipt(client, key):
    new_peaks = _peaks_for("log-RB-10")
    cose = _checkpoint_cose(key, log_id="log-RB", mmr_size=10, new_peaks=new_peaks)
    post_status, post_body = _post_checkpoint(client, cose)
    assert post_status == 200, post_body

    resp = client.get("/checkpoints/log-RB")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["log_id"] == "log-RB"
    assert body["mmr_size"] == 10
    assert body["root"] == _root_from_peaks(new_peaks).hex()
    assert body["key_id"] == key.public_key().public_bytes_raw().hex()
    assert body["grade"] is None  # non-enrolled log_id
    assert body["entry_hash"] == post_body["entry_hash"]
    assert body["receipt_b64"] == post_body["receipt_b64"]
    assert body["equivocations"] == []  # single checkpoint -- clean


def test_readback_reflects_enrolled_submitters_grade(client, agentrust_key):
    """log_id with a "/" ([witness-enroll-trace-registry-key]) round-trips
    through the :path route converter, and the countersign grade -- only
    ever returned on the original POST response before this task -- is now
    queryable later too (deliverable 1: bytes/claims AND grade)."""
    _enroll(client, log_id=_TRACE_REGISTRY_LOG_ID, pubkey=agentrust_key.public_key().public_bytes_raw())
    cose = _checkpoint_cose(
        agentrust_key, log_id=_TRACE_REGISTRY_LOG_ID, mmr_size=5,
        new_peaks=_peaks_for(f"{_TRACE_REGISTRY_LOG_ID}-rb-5"),
    )
    post_status, post_body = _post_checkpoint(client, cose)
    assert post_status == 200, post_body
    assert post_body["grade"] == GRADE_COUNTERSIGNED_OBSERVED

    resp = client.get(f"/checkpoints/{_TRACE_REGISTRY_LOG_ID}")
    assert resp.status_code == 200, resp.text
    assert resp.json()["grade"] == GRADE_COUNTERSIGNED_OBSERVED


def test_readback_tracks_the_most_recently_witnessed_position(client, key):
    peaks_10 = _peaks_for("log-RB2-10")
    cose1 = _checkpoint_cose(key, log_id="log-RB2", mmr_size=10, new_peaks=peaks_10)
    cose2 = _checkpoint_cose(
        key, log_id="log-RB2", mmr_size=20, new_peaks=_peaks_for("log-RB2-20"),
        prev_size=10, prev_peaks=peaks_10, issued_at="2026-08-26T00:10:00Z",
    )
    assert _post_checkpoint(client, cose1)[0] == 200
    assert _post_checkpoint(client, cose2)[0] == 200

    body = client.get("/checkpoints/log-RB2").json()
    assert body["mmr_size"] == 20
    assert body["equivocations"] == []


def test_two_checkpoints_same_position_different_root_flag_equivocation(client, key):
    """THE loud-surface case: two DIFFERENT roots submitted for the exact
    SAME (log_id, mmr_size). The write path accepts BOTH -- refusing at the
    write boundary is a stage-2 follow-up, not this task (see module
    docstring's scope line) -- but the read surface must surface the fork
    loudly, which is the launch claim's proof."""
    peaks_a = _peaks_for("log-EQ-100-a")
    peaks_b = _peaks_for("log-EQ-100-b")
    cose_a = _checkpoint_cose(key, log_id="log-EQ", mmr_size=100, new_peaks=peaks_a)
    cose_b = _checkpoint_cose(
        key, log_id="log-EQ", mmr_size=100, new_peaks=peaks_b, issued_at="2026-08-26T00:05:00Z",
    )
    status_a, body_a = _post_checkpoint(client, cose_a)
    status_b, body_b = _post_checkpoint(client, cose_b)
    assert status_a == 200, body_a
    assert status_b == 200, body_b  # write boundary does NOT refuse (scope line)
    assert body_a["entry_hash"] != body_b["entry_hash"]

    body = client.get("/checkpoints/log-EQ").json()
    # the FIRST-seen root is preserved as "last" -- never silently
    # overwritten by a later conflicting submission
    assert body["root"] == _root_from_peaks(peaks_a).hex()
    assert len(body["equivocations"]) == 1
    eq = body["equivocations"][0]
    assert eq["mmr_size"] == 100
    assert eq["first"]["root"] == _root_from_peaks(peaks_a).hex()
    assert eq["conflicting"]["root"] == _root_from_peaks(peaks_b).hex()
    assert eq["first"]["entry_hash"] == body_a["entry_hash"]
    assert eq["conflicting"]["entry_hash"] == body_b["entry_hash"]


def test_resubmitting_the_same_checkpoint_does_not_flag_equivocation(client, key):
    """Idempotent resubmission (identical bytes, identical root) at the SAME
    position is NOT a fork -- must stay clean (this is the "single ->
    clean" acceptance case, exercised via the idempotent-resubmit path)."""
    cose = _checkpoint_cose(key, log_id="log-EQ2", mmr_size=30, new_peaks=_peaks_for("log-EQ2-30"))
    assert _post_checkpoint(client, cose)[0] == 200
    assert _post_checkpoint(client, cose)[0] == 200

    body = client.get("/checkpoints/log-EQ2").json()
    assert body["equivocations"] == []


def test_equivocation_at_an_older_position_does_not_shadow_the_latest_checkpoint(client, key):
    """An equivocation flagged at an EARLIER position must not hide behind
    (or corrupt) the honestly-advanced latest checkpoint -- both surface:
    mmr_size/root still reflect the latest honest state, equivocations
    still lists the older fork."""
    peaks_10a = _peaks_for("log-EQ3-10-a")
    peaks_10b = _peaks_for("log-EQ3-10-b")
    cose_10a = _checkpoint_cose(key, log_id="log-EQ3", mmr_size=10, new_peaks=peaks_10a)
    cose_10b = _checkpoint_cose(
        key, log_id="log-EQ3", mmr_size=10, new_peaks=peaks_10b, issued_at="2026-08-26T00:05:00Z",
    )
    cose_20 = _checkpoint_cose(
        key, log_id="log-EQ3", mmr_size=20, new_peaks=_peaks_for("log-EQ3-20"),
        prev_size=10, prev_peaks=peaks_10a, issued_at="2026-08-26T00:10:00Z",
    )
    assert _post_checkpoint(client, cose_10a)[0] == 200
    assert _post_checkpoint(client, cose_10b)[0] == 200
    assert _post_checkpoint(client, cose_20)[0] == 200

    body = client.get("/checkpoints/log-EQ3").json()
    assert body["mmr_size"] == 20
    assert len(body["equivocations"]) == 1
    assert body["equivocations"][0]["mmr_size"] == 10


def test_per_submitter_rate_limit_does_not_affect_non_enrolled_log_ids(client, key, agentrust_key):
    """The per-submitter budget is scoped to the enrolled log_id only -- an
    unrelated, non-enrolled log_id is unaffected even after the enrolled
    submitter's own budget is exhausted."""
    _enroll(
        client, log_id=_TRACE_REGISTRY_LOG_ID, pubkey=agentrust_key.public_key().public_bytes_raw(),
        rate_limit_per_min=1,
    )
    cose_enrolled = _checkpoint_cose(
        agentrust_key, log_id=_TRACE_REGISTRY_LOG_ID, mmr_size=1, new_peaks=_peaks_for("rl-scope-1"),
    )
    s1, b1 = _post_checkpoint(client, cose_enrolled)
    assert s1 == 200, b1

    cose_other = _checkpoint_cose(key, log_id="unrelated-log", mmr_size=1, new_peaks=_peaks_for("rl-scope-2"))
    s2, b2 = _post_checkpoint(client, cose_other)
    assert s2 == 200, b2
