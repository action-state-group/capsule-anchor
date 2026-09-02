# SPDX-License-Identifier: Apache-2.0
"""Unit tests for ``checkpoint_json.parse_and_verify_checkpoint_json`` --
independent of the HTTP layer (see
``test_checkpoints_and_register_witness_host.py`` for end-to-end coverage of
``POST /checkpoints`` dispatching to this module on the JSON content type).

Includes the REAL live checkpoint published by AgenTrust's trace-registry
(``trace-registry/v1``, mmr_size=1) -- read directly from
``agentrust-io/trace-registry`` upstream commit ``55e1270``
(``registry/2026/09/01.ndjson``'s ``.mmr_checkpoint``), not retyped from
memory (see ``_ops/QUEUE_PROTOCOL.md`` §7b) -- so this suite proves the
parser accepts the bytes their pipeline actually produced, not just a
synthetic stand-in shaped like them.
"""
from __future__ import annotations

import hashlib
import json

import pytest
from capsule_anchor.anchoring.checkpoint_json import parse_and_verify_checkpoint_json
from capsule_anchor.anchoring.service import CheckpointSignatureError, NotACheckpointError
from capsule_anchor.anchoring.submitters import (
    ACCUMULATOR_FOREIGN,
    GRADE_COUNTERSIGNED_OBSERVED,
    WIRE_FORM_COSE_SIGN1,
    WIRE_FORM_JSON_ED25519,
    SubmitterAllowlist,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

#: trace-registry/v1's checkpoint 1, LIVE as of 2026-09-01 -- read verbatim
#: from agentrust-io/trace-registry upstream commit 55e1270
#: (registry/2026/09/01.ndjson .mmr_checkpoint), the same identity/key
#: enrolled in the shipped config (checkpoint_submitters.json).
_LIVE_LOG_ID = "trace-registry/v1"
_LIVE_PUBKEY_HEX = "bc133259c094f63694b4ec48a295d7501a9a0cd536df5631fb4663c155f7bc90"
_LIVE_CHECKPOINT_1 = {
    "v": 1,
    "kind": "mmr_checkpoint",
    "log_id": _LIVE_LOG_ID,
    "mmr_size": 1,
    "root": "3af8ddf2c1f429bb4fc670437e48640887f60de809b18f8ccea55fefb0c6639a",
    "prev_size": 0,
    "prev_root": "",
    "key_id": _LIVE_PUBKEY_HEX,
    "timestamp": "2026-09-01T21:39:37Z",
    "signature": (
        "a1ad25e2fd8f56e9c07a345fd5bde66f950afffc9d55af91f586cef1840c4ad"
        "cd992fc1e277c94f26fb673c0e0ad51a6fcff2e22cd58806133416d4c5c3e930e"
    ),
}


def _allowlist(*, log_id: str, pubkey_hex: str, wire_form: str = WIRE_FORM_JSON_ED25519, **extra) -> SubmitterAllowlist:
    entry = {
        "log_id": log_id,
        "pubkey_hex": pubkey_hex,
        "accumulator": ACCUMULATOR_FOREIGN,
        "wire_form": wire_form,
    }
    entry.update(extra)
    return SubmitterAllowlist.from_list([entry])


def _signing_body(cp: dict) -> dict:
    fields = ("v", "kind", "log_id", "mmr_size", "root", "prev_size", "prev_root", "key_id", "timestamp")
    return {k: cp[k] for k in fields}


def _digest(cp: dict) -> str:
    body = json.dumps(_signing_body(cp), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(body.encode()).hexdigest()


def _checkpoint(key: Ed25519PrivateKey, *, log_id: str, mmr_size: int, prev_size: int = 0, **overrides) -> dict:
    cp = {
        "v": 1,
        "kind": "mmr_checkpoint",
        "log_id": log_id,
        "mmr_size": mmr_size,
        "root": "a" * 64,
        "prev_size": prev_size,
        "prev_root": "" if prev_size == 0 else "b" * 64,
        "key_id": key.public_key().public_bytes_raw().hex(),
        "timestamp": "2026-09-02T00:00:00Z",
    }
    cp.update(overrides)
    cp["signature"] = key.sign(_digest(cp).encode("ascii")).hex()
    return cp


# --- the real live checkpoint ------------------------------------------------


def test_real_live_checkpoint_1_accepted_and_graded():
    allowlist = _allowlist(log_id=_LIVE_LOG_ID, pubkey_hex=_LIVE_PUBKEY_HEX)
    result = parse_and_verify_checkpoint_json(json.dumps(_LIVE_CHECKPOINT_1).encode(), allowlist=allowlist)
    assert result["log_id"] == _LIVE_LOG_ID
    assert result["mmr_size"] == 1
    assert result["root"] == _LIVE_CHECKPOINT_1["root"]
    assert result["grade"] == GRADE_COUNTERSIGNED_OBSERVED


# --- accepted path (synthetic) -----------------------------------------------


def test_enrolled_json_submission_accepted_with_grade():
    key = Ed25519PrivateKey.generate()
    allowlist = _allowlist(log_id="log-A", pubkey_hex=key.public_key().public_bytes_raw().hex())
    cp = _checkpoint(key, log_id="log-A", mmr_size=10)
    result = parse_and_verify_checkpoint_json(json.dumps(cp).encode(), allowlist=allowlist)
    assert result["log_id"] == "log-A"
    assert result["mmr_size"] == 10
    assert result["grade"] == GRADE_COUNTERSIGNED_OBSERVED


def test_root_and_prev_root_pass_through_opaque_never_reconstructed():
    """A json-ed25519 checkpoint's root is the submitter's OWN commitment
    (e.g. their bagged MMR root) -- this parser must never attempt to
    recompute it from a peak list (that's the COSE form's job); it is
    carried through as an authenticated opaque hex string."""
    key = Ed25519PrivateKey.generate()
    allowlist = _allowlist(log_id="log-B", pubkey_hex=key.public_key().public_bytes_raw().hex())
    weird_root = "deadbeef" * 8
    cp = _checkpoint(key, log_id="log-B", mmr_size=5, root=weird_root)
    result = parse_and_verify_checkpoint_json(json.dumps(cp).encode(), allowlist=allowlist)
    assert result["root"] == weird_root


# --- security invariants -----------------------------------------------------


def test_unknown_key_rejects_even_with_correct_log_id():
    """The core protection: signing with a DIFFERENT key than the pinned
    entry, while self-asserting key_id honestly as that different key's own
    public bytes, must still fail -- the pinned key is what's checked, never
    the submitted key_id (mutant: if verification used key_id to select the
    verifying key instead of the pinned entry, this submission would
    incorrectly succeed)."""
    enrolled_key = Ed25519PrivateKey.generate()
    attacker_key = Ed25519PrivateKey.generate()
    allowlist = _allowlist(log_id="log-C", pubkey_hex=enrolled_key.public_key().public_bytes_raw().hex())
    cp = _checkpoint(attacker_key, log_id="log-C", mmr_size=1)  # self-signs + self-asserts its OWN key_id
    with pytest.raises(CheckpointSignatureError, match="pinned enrolled key"):
        parse_and_verify_checkpoint_json(json.dumps(cp).encode(), allowlist=allowlist)


def test_bad_signature_rejects_with_signature_error():
    key = Ed25519PrivateKey.generate()
    allowlist = _allowlist(log_id="log-D", pubkey_hex=key.public_key().public_bytes_raw().hex())
    cp = _checkpoint(key, log_id="log-D", mmr_size=1)
    cp["signature"] = ("0" if cp["signature"][0] != "0" else "1") + cp["signature"][1:]
    with pytest.raises(CheckpointSignatureError):
        parse_and_verify_checkpoint_json(json.dumps(cp).encode(), allowlist=allowlist)


def test_log_id_not_enrolled_at_all_rejects_named():
    key = Ed25519PrivateKey.generate()
    allowlist = _allowlist(log_id="some-other-log", pubkey_hex=key.public_key().public_bytes_raw().hex())
    cp = _checkpoint(key, log_id="not-enrolled/v1", mmr_size=1)
    with pytest.raises(NotACheckpointError, match="enrolled json-ed25519"):
        parse_and_verify_checkpoint_json(json.dumps(cp).encode(), allowlist=allowlist)


def test_empty_allowlist_rejects_named():
    cp = _checkpoint(Ed25519PrivateKey.generate(), log_id="anything", mmr_size=1)
    with pytest.raises(NotACheckpointError, match="enrolled json-ed25519"):
        parse_and_verify_checkpoint_json(json.dumps(cp).encode(), allowlist=SubmitterAllowlist({}))


def test_enrolled_but_declared_cose_form_rejects_json_submission():
    """A log_id enrolled as wire_form=cose (the default/COSE-only case) must
    NOT accept a JSON submission just because the log_id happens to be
    enrolled -- json form is only for an entry that explicitly declares
    json-ed25519."""
    key = Ed25519PrivateKey.generate()
    allowlist = SubmitterAllowlist.from_list(
        [
            {
                "log_id": "cose-only-log",
                "pubkey_hex": key.public_key().public_bytes_raw().hex(),
                "accumulator": ACCUMULATOR_FOREIGN,
                "wire_form": WIRE_FORM_COSE_SIGN1,
            }
        ]
    )
    cp = _checkpoint(key, log_id="cose-only-log", mmr_size=1)
    with pytest.raises(NotACheckpointError, match="enrolled json-ed25519"):
        parse_and_verify_checkpoint_json(json.dumps(cp).encode(), allowlist=allowlist)


# --- structural validation ----------------------------------------------------


def test_not_json_rejects_named():
    allowlist = _allowlist(log_id="log-E", pubkey_hex="ab" * 32)
    with pytest.raises(NotACheckpointError, match="not valid JSON"):
        parse_and_verify_checkpoint_json(b"not json at all", allowlist=allowlist)


def test_json_array_not_object_rejects_named():
    allowlist = _allowlist(log_id="log-F", pubkey_hex="ab" * 32)
    with pytest.raises(NotACheckpointError, match="JSON object"):
        parse_and_verify_checkpoint_json(b"[1, 2, 3]", allowlist=allowlist)


def test_missing_required_field_rejects_named():
    key = Ed25519PrivateKey.generate()
    allowlist = _allowlist(log_id="log-G", pubkey_hex=key.public_key().public_bytes_raw().hex())
    cp = _checkpoint(key, log_id="log-G", mmr_size=1)
    del cp["mmr_size"]
    with pytest.raises(NotACheckpointError, match="missing required field"):
        parse_and_verify_checkpoint_json(json.dumps(cp).encode(), allowlist=allowlist)


def test_wrong_kind_rejects_named():
    key = Ed25519PrivateKey.generate()
    allowlist = _allowlist(log_id="log-H", pubkey_hex=key.public_key().public_bytes_raw().hex())
    cp = _checkpoint(key, log_id="log-H", mmr_size=1, kind="something-else")
    with pytest.raises(NotACheckpointError, match="kind"):
        parse_and_verify_checkpoint_json(json.dumps(cp).encode(), allowlist=allowlist)


def test_prev_size_not_less_than_mmr_size_rejects():
    key = Ed25519PrivateKey.generate()
    allowlist = _allowlist(log_id="log-I", pubkey_hex=key.public_key().public_bytes_raw().hex())
    cp = _checkpoint(key, log_id="log-I", mmr_size=5, prev_size=5)
    with pytest.raises(NotACheckpointError, match="prev_size"):
        parse_and_verify_checkpoint_json(json.dumps(cp).encode(), allowlist=allowlist)


# --- explicit field mapping (never guessed) -----------------------------------


def test_explicit_field_map_reads_submitters_own_field_names():
    """A submitter whose JSON uses DIFFERENT key names entirely -- proves the
    parser reads fields via the config's explicit field_map, never assumes
    our own field names apply."""
    key = Ed25519PrivateKey.generate()
    field_map = {
        "v": "schemaVersion",
        "kind": "recordKind",
        "log_id": "registryId",
        "mmr_size": "size",
        "root": "mmrRoot",
        "prev_size": "previousSize",
        "prev_root": "previousRoot",
        "key_id": "signerKey",
        "timestamp": "issuedAt",
        "signature": "sig",
    }
    allowlist = SubmitterAllowlist.from_list(
        [
            {
                "log_id": "renamed-log/v1",
                "pubkey_hex": key.public_key().public_bytes_raw().hex(),
                "accumulator": ACCUMULATOR_FOREIGN,
                "wire_form": WIRE_FORM_JSON_ED25519,
                "field_map": field_map,
            }
        ]
    )
    cp = _checkpoint(key, log_id="renamed-log/v1", mmr_size=7)
    renamed = {field_map[our_key]: value for our_key, value in cp.items()}
    result = parse_and_verify_checkpoint_json(json.dumps(renamed).encode(), allowlist=allowlist)
    assert result["log_id"] == "renamed-log/v1"
    assert result["mmr_size"] == 7
    assert result["grade"] == GRADE_COUNTERSIGNED_OBSERVED


def test_our_own_field_names_rejected_once_a_field_map_renames_them():
    """The flip side of the above: once a submitter's field_map says
    log_id lives under 'registryId', a body using the literal key 'log_id'
    must NOT be accepted -- there is no silent fallback to guessing."""
    key = Ed25519PrivateKey.generate()
    allowlist = SubmitterAllowlist.from_list(
        [
            {
                "log_id": "renamed-log/v1",
                "pubkey_hex": key.public_key().public_bytes_raw().hex(),
                "accumulator": ACCUMULATOR_FOREIGN,
                "wire_form": WIRE_FORM_JSON_ED25519,
                "field_map": {"log_id": "registryId"},
            }
        ]
    )
    cp = _checkpoint(key, log_id="renamed-log/v1", mmr_size=1)  # uses our own field names
    with pytest.raises(NotACheckpointError, match="enrolled json-ed25519"):
        parse_and_verify_checkpoint_json(json.dumps(cp).encode(), allowlist=allowlist)
