"""capsule-anchor#110, ruling u226: ``GET /checkpoints/{log_id}`` answers a
log's size, root, time and receipt only to a read signed with the log's own
checkpoint key; ``equivocations`` stays public. An unenrolled log id is
bound to its first accepted key, so a stranger can neither read the log's tip
from a POST refusal nor plant records or equivocations under it.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from capsule_anchor.anchoring.checkpoint_cose import parse_and_verify_checkpoint_cose
from capsule_anchor.anchoring.checkpoint_json import CLL_CHECKPOINT_JSON_CONTENT_TYPE
from capsule_anchor.anchoring.checkpoint_read import (
    CODE_KEY_MISMATCH,
    CODE_MALFORMED,
    CODE_TIME_SKEW,
    READ_SIGNATURE_HEADER,
    READ_TIME_HEADER,
    READ_WINDOW_SECONDS,
    ReadRefused,
    verify_read,
)
from capsule_anchor.anchoring.service import AnchorerService, LogKeyMismatchError
from capsule_anchor.anchoring.submitters import (
    ACCUMULATOR_NATIVE_MMR,
    WIRE_FORM_JSON_ED25519,
    SubmitterAllowlist,
)
from capsule_anchor.app import create_app
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from .signed_read import signed_read_headers
from .test_checkpoint_continuity import _Log, _proof_claim
from .test_checkpoint_json import _checkpoint as _json_checkpoint
from .test_checkpoints_and_register_witness_host import (
    _checkpoint_cose,
    _enroll,
    _peaks_for,
    _post_checkpoint,
    _root_from_peaks,
)

# Every field of the full answer except the two an unsigned read keeps.
_GATED = {
    "mmr_size", "root", "prev_size", "prev_root", "key_id", "timestamp", "grade",
    "receipt_b64", "entry_hash", "entry_hash_scheme", "leaf_index", "tree_size",
    "continuity_grade",
}

_VECTORS = Path(__file__).parent / "vectors" / "checkpoint-read-vectors.json"


@pytest.fixture()
def key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture()
def client():
    return TestClient(create_app())


def _post(client, key, log_id, mmr_size, **kw):
    status, body = _post_checkpoint(
        client, _checkpoint_cose(key, log_id=log_id, mmr_size=mmr_size, new_peaks=_peaks_for(f"{log_id}-{mmr_size}"), **kw)
    )
    assert status == 200, body
    return body


def _assert_names_nothing_about(body: dict, *values) -> None:
    text = json.dumps(body)
    for value in values:
        assert str(value) not in text, (value, text)


# --- the split read ----------------------------------------------------------


def test_unsigned_read_gets_only_log_id_and_equivocations(client, key):
    _post(client, key, "gate-1", 10)
    resp = client.get("/checkpoints/gate-1")
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"log_id": "gate-1", "equivocations": []}
    assert resp.headers["cache-control"] == "no-store"


def test_unsigned_read_still_shows_a_fork_by_the_logs_own_key(client, key):
    """The launch claim: anyone can watch a log for forks, unsigned."""
    _post(client, key, "gate-fork", 100)
    status, body = _post_checkpoint(
        client,
        _checkpoint_cose(key, log_id="gate-fork", mmr_size=100, new_peaks=_peaks_for("gate-fork-b"),
                         issued_at="2026-08-26T00:05:00Z"),
    )
    assert status == 200, body
    resp = client.get("/checkpoints/gate-fork")
    body = resp.json()
    assert set(body) == {"log_id", "equivocations"}
    assert len(body["equivocations"]) == 1
    assert body["equivocations"][0]["conflicting"]["root"] == _root_from_peaks(_peaks_for("gate-fork-b")).hex()


def test_signed_read_by_the_logs_key_gets_the_full_answer(client, key):
    post = _post(client, key, "gate-2", 10)
    resp = client.get("/checkpoints/gate-2", headers=signed_read_headers(key, "gate-2"))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert _GATED <= set(body)
    assert body["mmr_size"] == 10
    assert body["receipt_b64"] == post["receipt_b64"]
    assert resp.headers["cache-control"] == "no-store"


def test_read_signed_by_another_key_is_refused_with_nothing_about_the_log(client, key):
    _post(client, key, "gate-3", 10)
    stranger = Ed25519PrivateKey.generate()
    resp = client.get("/checkpoints/gate-3", headers=signed_read_headers(stranger, "gate-3"))
    assert resp.status_code == 403, resp.text
    assert resp.json()["detail"]["code"] == CODE_KEY_MISMATCH
    assert resp.headers["cache-control"] == "no-store"
    _assert_names_nothing_about(resp.json(), _root_from_peaks(_peaks_for("gate-3-10")).hex(), "2026-08-26")


def test_signature_over_another_log_id_is_refused(client, key):
    _post(client, key, "gate-4", 10)
    _post(client, key, "gate-4b", 10)
    headers = signed_read_headers(key, "gate-4b")
    resp = client.get("/checkpoints/gate-4", headers=headers)
    assert resp.status_code == 403
    assert resp.json()["detail"]["code"] == CODE_KEY_MISMATCH


@pytest.mark.parametrize("offset", [-READ_WINDOW_SECONDS, READ_WINDOW_SECONDS])
def test_read_time_at_the_window_edge_is_accepted(client, key, monkeypatch, offset):
    _post(client, key, "gate-5", 10)
    now = 1_795_645_990
    monkeypatch.setattr(time, "time", lambda: now)
    resp = client.get("/checkpoints/gate-5", headers=signed_read_headers(key, "gate-5", at=now + offset))
    assert resp.status_code == 200, resp.text
    assert resp.json()["mmr_size"] == 10


@pytest.mark.parametrize("offset", [-READ_WINDOW_SECONDS - 1, READ_WINDOW_SECONDS + 1])
def test_read_time_outside_the_window_is_refused(client, key, monkeypatch, offset):
    _post(client, key, "gate-6", 10)
    now = 1_795_645_990
    monkeypatch.setattr(time, "time", lambda: now)
    resp = client.get("/checkpoints/gate-6", headers=signed_read_headers(key, "gate-6", at=now + offset))
    assert resp.status_code == 403
    assert resp.json()["detail"]["code"] == CODE_TIME_SKEW


def test_malformed_read_headers_are_refused(client, key):
    _post(client, key, "gate-7", 10)
    good = signed_read_headers(key, "gate-7")
    t, sig = good[READ_TIME_HEADER], good[READ_SIGNATURE_HEADER]
    cases = [
        {READ_TIME_HEADER: t},  # signature missing
        {READ_SIGNATURE_HEADER: sig},  # time missing
        {READ_TIME_HEADER: "0" + t, READ_SIGNATURE_HEADER: sig},  # leading zero
        {READ_TIME_HEADER: "-" + t, READ_SIGNATURE_HEADER: sig},
        {READ_TIME_HEADER: t, READ_SIGNATURE_HEADER: sig + "=="},  # padded
        {READ_TIME_HEADER: t, READ_SIGNATURE_HEADER: sig[:-4]},  # short
        {READ_TIME_HEADER: t, READ_SIGNATURE_HEADER: sig.replace("-", "+").replace("_", "/") + "+"},
    ]
    for headers in cases:
        resp = client.get("/checkpoints/gate-7", headers=headers)
        assert resp.status_code == 403, (headers, resp.text)
        assert resp.json()["detail"]["code"] == CODE_MALFORMED, headers


@pytest.mark.parametrize("length", [1, 85, 87, 88])
def test_signature_of_the_wrong_length_is_malformed_not_an_error(client, key, length):
    _post(client, key, "gate-len", 10)
    t = signed_read_headers(key, "gate-len")[READ_TIME_HEADER]
    resp = client.get("/checkpoints/gate-len", headers={READ_TIME_HEADER: t, READ_SIGNATURE_HEADER: "A" * length})
    assert resp.status_code == 403, resp.text
    assert resp.json()["detail"]["code"] == CODE_MALFORMED
    assert resp.headers["cache-control"] == "no-store"


def test_duplicate_read_headers_are_refused(client, key):
    _post(client, key, "gate-8", 10)
    good = signed_read_headers(key, "gate-8")
    resp = client.get(
        "/checkpoints/gate-8",
        headers=[
            (READ_TIME_HEADER, good[READ_TIME_HEADER]),
            (READ_TIME_HEADER, good[READ_TIME_HEADER]),
            (READ_SIGNATURE_HEADER, good[READ_SIGNATURE_HEADER]),
        ],
    )
    assert resp.status_code == 403
    assert resp.json()["detail"]["code"] == CODE_MALFORMED


def test_never_witnessed_is_404_signed_or_not(client, key):
    for headers in ({}, signed_read_headers(key, "gate-none")):
        resp = client.get("/checkpoints/gate-none", headers=headers)
        assert resp.status_code == 404
        assert resp.headers["cache-control"] == "no-store"


def test_log_id_with_slashes_signs_the_decoded_id(client, key):
    log_id = "deal-cadence/abcd/x"
    _post(client, key, log_id, 10)
    resp = client.get("/checkpoints/deal-cadence/abcd%2Fx", headers=signed_read_headers(key, log_id))
    assert resp.status_code == 200, resp.text
    assert resp.json()["log_id"] == log_id
    assert resp.json()["mmr_size"] == 10


# --- enrolled submitters: the pinned key decides ------------------------------


def test_enrolled_json_submitter_reads_with_its_pinned_key(client):
    """The JSON wire form stores a submitted ``key_id`` label, not a key: the
    read is checked against the pinned key, never that label."""
    pinned = Ed25519PrivateKey.generate()
    other = Ed25519PrivateKey.generate()
    _enroll(client, log_id="json-log/v1", pubkey=pinned.public_key().public_bytes_raw(),
            accumulator=ACCUMULATOR_NATIVE_MMR, wire_form=WIRE_FORM_JSON_ED25519)
    # key_id names ANOTHER key's hex: it must not become the read key.
    cp = _json_checkpoint(pinned, log_id="json-log/v1", mmr_size=10,
                          key_id=other.public_key().public_bytes_raw().hex())
    resp = client.post("/checkpoints", content=json.dumps(cp).encode(),
                       headers={"Content-Type": CLL_CHECKPOINT_JSON_CONTENT_TYPE})
    assert resp.status_code == 200, resp.text

    ok = client.get("/checkpoints/json-log/v1", headers=signed_read_headers(pinned, "json-log/v1"))
    assert ok.status_code == 200, ok.text
    assert ok.json()["mmr_size"] == 10
    refused = client.get("/checkpoints/json-log/v1", headers=signed_read_headers(other, "json-log/v1"))
    assert refused.status_code == 403


def test_enrolled_pin_rotation_moves_the_read_key(client):
    old, new = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    _enroll(client, log_id="rot-log/v1", pubkey=old.public_key().public_bytes_raw())
    _post(client, old, "rot-log/v1", 10)
    _enroll(client, log_id="rot-log/v1", pubkey=new.public_key().public_bytes_raw())
    # The rotated pin signs the next checkpoint: no ownership refusal.
    _post(client, new, "rot-log/v1", 20, prev_size=10, prev_peaks=_peaks_for("rot-log/v1-10"))
    assert client.get("/checkpoints/rot-log/v1", headers=signed_read_headers(new, "rot-log/v1")).status_code == 200
    assert client.get("/checkpoints/rot-log/v1", headers=signed_read_headers(old, "rot-log/v1")).status_code == 403


# --- a stranger under a bound log id ------------------------------------------


@pytest.mark.parametrize("stranger_size", [5, 10, 50])
def test_strangers_checkpoint_under_a_bound_log_id_is_refused_and_changes_nothing(client, key, stranger_size):
    """Smaller, equal and larger positions: refused 403 with nothing about the
    log, no equivocation, and the owner's read still returns its own record."""
    _post(client, key, "owned", 10)
    stranger = Ed25519PrivateKey.generate()
    status, body = _post_checkpoint(
        client,
        _checkpoint_cose(stranger, log_id="owned", mmr_size=stranger_size,
                         new_peaks=_peaks_for(f"stranger-{stranger_size}")),
    )
    assert status == 403, body
    assert body["detail"]["code"] == "log_key_mismatch"
    _assert_names_nothing_about(body, _root_from_peaks(_peaks_for("owned-10")).hex(), "2026-08-26")
    assert "last_accepted" not in json.dumps(body)

    owner = client.get("/checkpoints/owned", headers=signed_read_headers(key, "owned")).json()
    assert owner["mmr_size"] == 10
    assert owner["key_id"] == key.public_key().public_bytes_raw().hex()
    assert owner["equivocations"] == []
    assert client.get("/checkpoints/owned", headers=signed_read_headers(stranger, "owned")).status_code == 403


def test_strangers_proof_carrying_checkpoint_does_not_get_the_tip(client, key):
    """Before #110 a stranger's proof-carrying checkpoint with a wrong prev
    got a 409 naming the owner's last size and root."""
    log = _Log("owned-proof")
    size1 = log.grow_leaves(2)
    status, body = _post_checkpoint(client, log.checkpoint_cose(key, size=size1, prev_size=0, issued_at="2026-09-06T00:00:00Z"))
    assert status == 200, body
    size2 = log.grow_leaves(2)
    stranger = Ed25519PrivateKey.generate()
    status, body = _post_checkpoint(
        client,
        log.checkpoint_cose(stranger, size=size2, prev_size=size1, issued_at="2026-09-06T00:05:00Z",
                            consistency_proof=_proof_claim(log.proof(size1, size2)),
                            prev_peaks_override=_peaks_for("wrong-prev")),
    )
    assert status == 403, body
    assert body["detail"]["code"] == "log_key_mismatch"
    _assert_names_nothing_about(body, log.root_at(size1).hex())
    assert "last_accepted" not in json.dumps(body)


@pytest.mark.parametrize("stranger_size", [10, 50])
def test_a_digest_preregistered_on_register_does_not_carry_a_strangers_checkpoint(client, key, stranger_size):
    """The receipt cache answers a digest already registered: the ownership
    check runs before it, so a stranger who first registers its checkpoint's
    digest on /register still cannot put that checkpoint on the owner's log."""
    from capsule_anchor.anchoring.service import _checkpoint_digest

    _post(client, key, "owned-cache", 10)
    stranger = Ed25519PrivateKey.generate()
    cose = _checkpoint_cose(stranger, log_id="owned-cache", mmr_size=stranger_size,
                            new_peaks=_peaks_for(f"cache-{stranger_size}"))
    digest = _checkpoint_digest(parse_and_verify_checkpoint_cose(cose, allowlist=SubmitterAllowlist.from_list([])))
    assert client.post("/register", json={"capsule_id": digest}).status_code == 200

    status, body = _post_checkpoint(client, cose)
    assert status == 403, body
    assert body["detail"]["code"] == "log_key_mismatch"
    owner = client.get("/checkpoints/owned-cache", headers=signed_read_headers(key, "owned-cache")).json()
    assert owner["mmr_size"] == 10
    assert owner["equivocations"] == []


def test_owners_resubmission_still_returns_its_stamp(client, key):
    cose = _checkpoint_cose(key, log_id="owned-again", mmr_size=10, new_peaks=_peaks_for("again"))
    s1, b1 = _post_checkpoint(client, cose)
    s2, b2 = _post_checkpoint(client, cose)
    assert s1 == s2 == 200
    assert b2["receipt_b64"] == b1["receipt_b64"]


def _assert_bound_to(client, owner, log_id, size):
    resp = client.get(f"/checkpoints/{log_id}", headers=signed_read_headers(owner, log_id))
    assert resp.status_code == 200, resp.text
    assert resp.json()["mmr_size"] == size
    stranger = Ed25519PrivateKey.generate()
    status, body = _post_checkpoint(
        client, _checkpoint_cose(stranger, log_id=log_id, mmr_size=size, new_peaks=_peaks_for(f"{log_id}-x"))
    )
    assert status == 403, body
    assert client.get(f"/checkpoints/{log_id}").json()["equivocations"] == []


def test_a_legacy_label_binds_no_key_and_the_next_verified_key_owns_the_log(client, key):
    """The legacy mmr-checkpoint path stores a self-asserted key_id label: it
    must not lock the log's real key out, nor leave the log open to any key."""
    from .test_checkpoint_witness import _build_statement, _register
    from .test_checkpoint_witness import _checkpoint as _legacy_checkpoint

    status, body = _register(client, _build_statement(_legacy_checkpoint("labelled", mmr_size=5, prev_size=0), key))
    assert status == 200, body
    post = _post(client, key, "labelled", 10, prev_size=5, prev_peaks=_peaks_for("labelled-5"))
    assert post["continuity_grade"] == "first-seen"
    _assert_bound_to(client, key, "labelled", 10)


def test_a_first_checkpoint_preregistered_on_register_still_binds_its_key(client, key):
    from capsule_anchor.anchoring.service import _checkpoint_digest

    cose = _checkpoint_cose(key, log_id="prereg", mmr_size=10, new_peaks=_peaks_for("prereg-10"))
    digest = _checkpoint_digest(parse_and_verify_checkpoint_cose(cose, allowlist=SubmitterAllowlist.from_list([])))
    assert client.post("/register", json={"capsule_id": digest}).status_code == 200
    status, body = _post_checkpoint(client, cose)
    assert status == 200, body
    _assert_bound_to(client, key, "prereg", 10)


# --- every store binds the same way -----------------------------------------


@pytest.mark.parametrize("db", ["memory", "sqlite"])
def test_binding_holds_in_each_store(tmp_path, db):
    svc = AnchorerService() if db == "memory" else AnchorerService(db_path=str(tmp_path / "w.db"))
    owner, stranger = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()

    def cp(k, size, **kw):
        return parse_and_verify_checkpoint_cose(
            _checkpoint_cose(k, log_id="store-log", mmr_size=size, new_peaks=_peaks_for(f"s-{size}-{id(k)}"), **kw),
            allowlist=SubmitterAllowlist.from_list([]),
        )

    svc.witness_checkpoint(cp(owner, 10))
    for size in (5, 10, 50):
        with pytest.raises(LogKeyMismatchError):
            svc.witness_checkpoint(cp(stranger, size))
    assert svc.checkpoint_owner_key("store-log") == owner.public_key().public_bytes_raw().hex()
    assert svc.get_checkpoint_readback("store-log")["equivocations"] == []
    assert svc.get_checkpoint_readback("store-log")["mmr_size"] == 10


# --- the wire bytes ----------------------------------------------------------


def test_shared_vectors_verify():
    """The same file is checked by evidencebook's canary signer."""
    doc = json.loads(_VECTORS.read_text(encoding="utf-8"))
    pub = bytes.fromhex(doc["public_key_hex"])
    seed = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(doc["seed_hex"]))
    assert seed.public_key().public_bytes_raw() == pub
    for case in doc["cases"]:
        now = int(case["time"])
        assert verify_read(case["log_id"], [case["time"]], [case["signature"]], pub, now) is True
        assert signed_read_headers(seed, case["log_id"], at=now)[READ_SIGNATURE_HEADER] == case["signature"]
        with pytest.raises(ReadRefused):
            verify_read(case["log_id"] + "x", [case["time"]], [case["signature"]], pub, now)


def test_unsigned_read_is_not_an_error():
    assert verify_read("any", [], [], None, 0) is False


def test_no_usable_key_refuses_every_signature():
    signer = Ed25519PrivateKey.generate()
    h = signed_read_headers(signer, "x", at=100)
    with pytest.raises(ReadRefused) as exc:
        verify_read("x", [h[READ_TIME_HEADER]], [h[READ_SIGNATURE_HEADER]], None, 100)
    assert exc.value.code == CODE_KEY_MISMATCH
