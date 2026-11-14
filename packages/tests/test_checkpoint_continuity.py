# SPDX-License-Identifier: Apache-2.0
"""Stage-2 checkpoint-aware witness tests: the ``consistency_proof``-bearing
half of ``POST /checkpoints``.

``test_checkpoints_and_register_witness_host.py`` covers the proof-LESS
default path (signature/structural gates, always-accepted `registered` /
`first-seen`). This file is scoped to what happens once a checkpoint carries
a `consistency_proof` claim: the two-check continuity gate
(`AnchorerService._check_checkpoint_continuity`) that refuses (409) a fork or
a rewritten/truncated tree, and never otherwise.

Builds REAL Merkle Mountain Ranges with the neutral ``cll.checkpoint.core``
module (the exact library ``capsule_anchor.anchoring.checkpoint_cose`` and
``service.py`` import for ``verify_consistency`` -- the witness never builds
trees itself, so these tests build one to have a genuine extension proof to
hand it) -- never capsule-emit, matching this package's boundary discipline.
Everything else (COSE envelope construction, signing) is hand-rolled with
``scitt_cose`` + ``cbor2`` + ``cryptography`` alone, mirroring
``test_checkpoints_and_register_witness_host.py``'s own style.
"""
from __future__ import annotations

import base64
import hashlib

import cbor2
import pytest
from capsule_anchor.anchoring.service import (
    CONTINUITY_GRADE_FIRST_SEEN,
    CONTINUITY_GRADE_REGISTERED,
    CONTINUITY_GRADE_WITNESSED,
    CONTINUITY_POLICY_ID,
    _COSE_CONTINUITY_LABEL,
)
from capsule_anchor.app import create_app
from cll.checkpoint import core
from cll.checkpoint.store import MemoryNodeStore
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from fastapi.testclient import TestClient
from scitt_cose.statement import build_signed_statement

_CLL_CONTENT_TYPE = "application/cll-checkpoint+cbor"
_WIRE_KIND = "cll-checkpoint"


def _pem(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


def _commitment(peak_hashes: list[bytes]) -> bytes:
    """MMRIVER-conformant commitment object: canonical CBOR ``[ *bstr ]``."""
    return cbor2.dumps(peak_hashes, canonical=True)


def _proof_claim(proof: core.ConsistencyProof) -> dict:
    """CBOR-wire encoding of a real ``ConsistencyProof`` -- matches
    ``checkpoint_cose._decode_consistency_proof``'s expected shape exactly
    (independently hand-rolled here, same discipline as this test package's
    other COSE-building helpers: never import the wire encoder capsule-anchor
    itself deliberately never imports)."""
    return {
        "size_a": proof.size_a,
        "size_b": proof.size_b,
        "old_peaks": [bytes.fromhex(h) for h in proof.old_peaks],
        "witness": [[bytes.fromhex(h) for h in w] for w in proof.witness],
        "new_peaks": [bytes.fromhex(h) for h in proof.new_peaks],
    }


class _Log:
    """A REAL, incrementally-grown Merkle Mountain Range (via the neutral
    ``cll.checkpoint.core`` algorithm), so these tests can hand the witness a
    genuine, independently-checkable ``consistency_proof`` -- not a synthetic
    peak list standing in for one."""

    def __init__(self, log_id: str) -> None:
        self.log_id = log_id
        self._store = MemoryNodeStore()
        self._n = 0

    def grow_leaves(self, n: int) -> int:
        """Append ``n`` more leaves; return the MMR's new node-array
        ``size()`` (a node count, NOT a leaf count -- e.g. 2 leaves lands on
        node-array size 3, not 2). Tests grow by leaf COUNT and read back
        whatever size that lands on, rather than guessing at valid MMR sizes
        directly (only certain sizes -- 1, 3, 4, 7, 8, 10, 11, 15, ... --
        are ever valid ``core.peaks``/``consistency_proof`` inputs)."""
        for _ in range(n):
            self._n += 1
            body = hashlib.sha256(f"{self.log_id}-leaf-{self._n}".encode()).digest()
            core.add_leaf(self._store, core.leaf_hash(body))
        return self._store.size()

    def peaks_at(self, size: int) -> list[bytes]:
        return [self._store.node(p) for p in core.peaks(size)]

    def root_at(self, size: int) -> bytes:
        return core.root_from_peaks(self.peaks_at(size))

    def proof(self, size_a: int, size_b: int) -> core.ConsistencyProof:
        return core.consistency_proof(self._store, size_a, size_b)

    def checkpoint_cose(
        self,
        key: Ed25519PrivateKey,
        *,
        size: int,
        prev_size: int,
        issued_at: str,
        consistency_proof: dict | None = None,
        prev_peaks_override: list[bytes] | None = None,
    ) -> bytes:
        new_peaks = self.peaks_at(size)
        if prev_peaks_override is not None:
            prev_peaks = prev_peaks_override
        else:
            prev_peaks = self.peaks_at(prev_size) if prev_size else []
        claims: dict = {
            "kind": _WIRE_KIND,
            "log_size": size,
            "commitment": _commitment(new_peaks),
            "prev_size": prev_size,
            "prev_commitment": _commitment(prev_peaks) if prev_size else b"",
            "issued_at": issued_at,
        }
        if consistency_proof is not None:
            claims["consistency_proof"] = consistency_proof
        payload = cbor2.dumps(claims, canonical=True)
        return build_signed_statement(
            payload,
            alg="EdDSA",
            private_key_pem=_pem(key),
            issuer=self.log_id,
            subject=f"{self.log_id}#{size}",
            content_type=_CLL_CONTENT_TYPE,
            kid=key.public_key().public_bytes_raw(),
        )


@pytest.fixture()
def key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture()
def client() -> TestClient:
    return TestClient(create_app())


def _post_checkpoint(client: TestClient, cose_bytes: bytes) -> tuple[int, dict]:
    resp = client.post(
        "/checkpoints", content=cose_bytes, headers={"Content-Type": _CLL_CONTENT_TYPE}
    )
    return resp.status_code, (resp.json() if resp.content else {})


def _receipt_protected_header(receipt_b64: str) -> dict:
    receipt = base64.b64decode(receipt_b64)
    protected_bstr = cbor2.loads(receipt).value[0]
    return cbor2.loads(protected_bstr) if protected_bstr else {}


# --- positive: a chain of 3 checkpoints, first-seen then continuity-witnessed x2 --


def test_chain_of_three_checkpoints_grades_first_seen_then_witnessed_twice(client, key):
    log = _Log("continuity-log-A")
    size1 = log.grow_leaves(2)

    cose1 = log.checkpoint_cose(key, size=size1, prev_size=0, issued_at="2026-09-06T00:00:00Z")
    status1, body1 = _post_checkpoint(client, cose1)
    assert status1 == 200, body1
    assert body1["continuity_grade"] == CONTINUITY_GRADE_FIRST_SEEN

    size2 = log.grow_leaves(2)
    proof12 = log.proof(size1, size2)
    cose2 = log.checkpoint_cose(
        key, size=size2, prev_size=size1, issued_at="2026-09-06T00:05:00Z",
        consistency_proof=_proof_claim(proof12),
    )
    status2, body2 = _post_checkpoint(client, cose2)
    assert status2 == 200, body2
    assert body2["continuity_grade"] == CONTINUITY_GRADE_WITNESSED

    size3 = log.grow_leaves(2)
    proof23 = log.proof(size2, size3)
    cose3 = log.checkpoint_cose(
        key, size=size3, prev_size=size2, issued_at="2026-09-06T00:10:00Z",
        consistency_proof=_proof_claim(proof23),
    )
    status3, body3 = _post_checkpoint(client, cose3)
    assert status3 == 200, body3
    assert body3["continuity_grade"] == CONTINUITY_GRADE_WITNESSED

    # The signed continuity assertion is only carried for the WITNESSED grades.
    protected1 = _receipt_protected_header(body1["receipt_b64"])
    assert _COSE_CONTINUITY_LABEL not in protected1

    protected2 = _receipt_protected_header(body2["receipt_b64"])
    assertion2 = protected2[_COSE_CONTINUITY_LABEL]
    assert assertion2["policy_id"] == CONTINUITY_POLICY_ID
    assert assertion2["log_id"] == log.log_id
    assert assertion2["prev_size"] == size1
    assert assertion2["mmr_size"] == size2
    assert sorted(assertion2["checked"]) == ["consistency_proof", "prev_equality"]


def test_missing_proof_on_known_log_grades_registered_never_refused(client, key):
    log = _Log("continuity-log-B")
    size1 = log.grow_leaves(2)
    cose1 = log.checkpoint_cose(key, size=size1, prev_size=0, issued_at="2026-09-06T00:00:00Z")
    status1, body1 = _post_checkpoint(client, cose1)
    assert status1 == 200, body1

    size2 = log.grow_leaves(2)
    # A checkpoint that would extend cleanly, but carries NO consistency_proof
    # -- must be registered, never refused (pre-stage-2 clients keep working).
    cose2 = log.checkpoint_cose(key, size=size2, prev_size=size1, issued_at="2026-09-06T00:05:00Z")
    status2, body2 = _post_checkpoint(client, cose2)
    assert status2 == 200, body2
    assert body2["continuity_grade"] == CONTINUITY_GRADE_REGISTERED
    protected2 = _receipt_protected_header(body2["receipt_b64"])
    assert _COSE_CONTINUITY_LABEL not in protected2


# --- negative: fork / rollback -- check (a) (prev-equality) fails -----------


def test_fork_wrong_prev_root_refused_409_with_last_accepted_body(client, key):
    log = _Log("continuity-log-C")
    size1 = log.grow_leaves(2)
    cose1 = log.checkpoint_cose(key, size=size1, prev_size=0, issued_at="2026-09-06T00:00:00Z")
    status1, body1 = _post_checkpoint(client, cose1)
    assert status1 == 200, body1

    size2 = log.grow_leaves(2)
    proof12 = log.proof(size1, size2)
    cose2 = log.checkpoint_cose(
        key, size=size2, prev_size=size1, issued_at="2026-09-06T00:05:00Z",
        consistency_proof=_proof_claim(proof12),
    )
    status2, body2 = _post_checkpoint(client, cose2)
    assert status2 == 200 and body2["continuity_grade"] == CONTINUITY_GRADE_WITNESSED

    # Fork attempt: witness's last-accepted is now (size2, root(size2)), but
    # this submission's `prev_commitment` claim is a FABRICATED peak list at
    # size2 -- structurally valid (right size, right shape), genuinely
    # signed, but bagging to a DIFFERENT root than what this witness actually
    # accepted. Check (a) (pure field equality) must catch this before check
    # (b) (which would need a real proof anyway) is ever consulted.
    size3 = log.grow_leaves(2)
    fabricated_prev_peaks = [hashlib.sha256(b"fork-attempt-peak").digest()] * len(
        log.peaks_at(size2)
    )
    assert core.root_from_peaks(fabricated_prev_peaks) != log.root_at(size2)
    proof23 = log.proof(size2, size3)  # a REAL proof, but for the wrong claimed prior
    cose3 = log.checkpoint_cose(
        key, size=size3, prev_size=size2, issued_at="2026-09-06T00:10:00Z",
        consistency_proof=_proof_claim(proof23),
        prev_peaks_override=fabricated_prev_peaks,
    )

    status3, body3 = _post_checkpoint(client, cose3)
    assert status3 == 409, body3
    assert body3["detail"]["last_accepted_mmr_size"] == size2
    assert body3["detail"]["last_accepted_root"] == log.root_at(size2).hex()


def test_fork_wrong_prev_size_refused_409(client, key):
    """A submission whose ``prev_size`` doesn't match this witness's own
    last-accepted ``mmr_size`` for the log -- e.g. re-extending from an
    EARLIER position than the witness has already advanced past -- is
    refused on check (a) regardless of whether ``prev_size`` was itself once
    a real, honestly-witnessed position."""
    log = _Log("continuity-log-D")
    size1 = log.grow_leaves(2)
    cose1 = log.checkpoint_cose(key, size=size1, prev_size=0, issued_at="2026-09-06T00:00:00Z")
    status1, body1 = _post_checkpoint(client, cose1)
    assert status1 == 200, body1

    size2 = log.grow_leaves(2)
    proof12 = log.proof(size1, size2)
    cose2 = log.checkpoint_cose(
        key, size=size2, prev_size=size1, issued_at="2026-09-06T00:05:00Z",
        consistency_proof=_proof_claim(proof12),
    )
    status2, body2 = _post_checkpoint(client, cose2)
    assert status2 == 200 and body2["continuity_grade"] == CONTINUITY_GRADE_WITNESSED

    # A THIRD, brand-new position (size3) that claims to extend directly from
    # size1 (already superseded by size2 in this witness's own state) --
    # rollback-shaped: the witness's chain-tip has already moved past size1.
    size3 = log.grow_leaves(2)
    proof1_3 = log.proof(size1, size3)
    cose3 = log.checkpoint_cose(
        key, size=size3, prev_size=size1, issued_at="2026-09-06T00:10:00Z",
        consistency_proof=_proof_claim(proof1_3),
    )
    status3, body3 = _post_checkpoint(client, cose3)
    assert status3 == 409, body3
    assert body3["detail"]["last_accepted_mmr_size"] == size2
    assert body3["detail"]["last_accepted_root"] == log.root_at(size2).hex()


# --- negative: rewritten tree with HONEST-looking prev_* -- check (b) fails -


def test_rewritten_tree_honest_prev_but_forged_proof_refused_409(client, key):
    """The critical mutant-distinguishing case: ``prev_size``/``prev_root``
    are byte-for-byte what this witness itself last accepted (check (a)
    would pass), but the accompanying ``consistency_proof`` is corrupted --
    a single flipped byte in one witness hash, everything else genuine. This
    is exactly the gap field-equality alone would miss: an attacker who
    copies the honest prev_* fields but cannot produce a REAL extension
    proof (because the actual tree behind their claimed new root does not
    genuinely derive from the witness's last-accepted state)."""
    log = _Log("continuity-log-E")
    size1 = log.grow_leaves(2)
    cose1 = log.checkpoint_cose(key, size=size1, prev_size=0, issued_at="2026-09-06T00:00:00Z")
    status1, body1 = _post_checkpoint(client, cose1)
    assert status1 == 200, body1

    size2 = log.grow_leaves(2)
    proof = log.proof(size1, size2)
    claim = _proof_claim(proof)
    # Corrupt exactly one byte of one witness sibling hash -- old_peaks,
    # new_peaks (and therefore root_a/root_b) stay genuine and honest; only
    # the extension math itself is now unreconstructable.
    corrupted_witness = [[bytes(h) for h in w] for w in claim["witness"]]
    assert corrupted_witness and corrupted_witness[0], "expected at least one witness hash"
    b = bytearray(corrupted_witness[0][0])
    b[0] ^= 0xFF
    corrupted_witness[0][0] = bytes(b)
    claim["witness"] = corrupted_witness

    cose2 = log.checkpoint_cose(
        key, size=size2, prev_size=size1, issued_at="2026-09-06T00:05:00Z",
        consistency_proof=claim,
    )
    status2, body2 = _post_checkpoint(client, cose2)
    assert status2 == 409, body2
    assert body2["detail"]["last_accepted_mmr_size"] == size1
    assert body2["detail"]["last_accepted_root"] == log.root_at(size1).hex()

    # Confirm nothing was appended/counter-signed: resubmitting the SAME
    # genuine (uncorrupted) checkpoint afterwards still grades continuity-witnessed.
    cose2_honest = log.checkpoint_cose(
        key, size=size2, prev_size=size1, issued_at="2026-09-06T00:05:00Z",
        consistency_proof=_proof_claim(proof),
    )
    status2b, body2b = _post_checkpoint(client, cose2_honest)
    assert status2b == 200, body2b
    assert body2b["continuity_grade"] == CONTINUITY_GRADE_WITNESSED


# --- positive: a gap, reproved from the WITNESS's own view, must pass ------


def test_gap_then_reprove_from_witness_view_passes(client, key):
    """The client submitted checkpoint 1 to this witness, then (for
    whatever reason -- a dropped request, a witness it hadn't registered
    with yet) never submitted an intermediate checkpoint here. When it
    catches back up, it reproves directly from THIS witness's own
    last-accepted state to the log's current state, skipping the gap
    entirely -- this must PASS: continuity is checked against what the
    witness itself last accepted, not against every intermediate position
    the log passed through."""
    log = _Log("continuity-log-F")
    size1 = log.grow_leaves(2)
    cose1 = log.checkpoint_cose(key, size=size1, prev_size=0, issued_at="2026-09-06T00:00:00Z")
    status1, body1 = _post_checkpoint(client, cose1)
    assert status1 == 200, body1

    # The log grows through an intermediate position this witness never sees...
    log.grow_leaves(2)
    # ...and further, to where the client finally re-registers with this witness.
    size_final = log.grow_leaves(2)

    gap_proof = log.proof(size1, size_final)
    cose_final = log.checkpoint_cose(
        key, size=size_final, prev_size=size1, issued_at="2026-09-06T01:00:00Z",
        consistency_proof=_proof_claim(gap_proof),
    )
    status_final, body_final = _post_checkpoint(client, cose_final)
    assert status_final == 200, body_final
    assert body_final["continuity_grade"] == CONTINUITY_GRADE_WITNESSED


# --- read-back surfaces the continuity grade --------------------------------


def test_readback_exposes_continuity_grade(client, key):
    log = _Log("continuity-log-G")
    size1 = log.grow_leaves(2)
    cose1 = log.checkpoint_cose(key, size=size1, prev_size=0, issued_at="2026-09-06T00:00:00Z")
    _post_checkpoint(client, cose1)

    resp = client.get(f"/checkpoints/{log.log_id}")
    assert resp.status_code == 200, resp.text
    assert resp.json()["continuity_grade"] == CONTINUITY_GRADE_FIRST_SEEN
