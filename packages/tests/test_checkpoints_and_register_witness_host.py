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
