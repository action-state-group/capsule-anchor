"""Tests for STH lifecycle: persistence, consistency proofs, and stale-head detection.

Three properties the task requires:

1. **STH tracks the log** — after every registration, GET /anchor/sth reflects the
   new tree_size. Verified by checking the persisted STH advances inline.

2. **Consistency proof between successive heads** — a monitor can verify that the
   tree at size M is an honest append-only extension of the tree at size N.
   This is the core anti-fork / anti-backdate guarantee of the CT design.

3. **Stale-head failing direction** — a head whose tree_size has not advanced with
   the log is DETECTABLE as stale. Shown in BOTH directions:
   - stale head → is_sth_stale() returns True  (detection fires)
   - current head → is_sth_stale() returns False  (non-trivially correct)
   "A green that has never seen red proves nothing."
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from capsule_anchor.anchoring.service import AnchorerService


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _digest(n: int) -> bytes:
    return hashlib.sha256(f"sth-test-entry-{n}".encode()).digest()


def _fresh() -> AnchorerService:
    return AnchorerService()


# ---------------------------------------------------------------------------
# 1. STH tracks the log
# ---------------------------------------------------------------------------

class TestSTHTracksLog:
    """The persisted STH tree_size equals the log size after every registration."""

    def test_sth_tree_size_matches_after_each_registration(self):
        svc = _fresh()
        for i in range(5):
            svc.register_signed_statement(_digest(i))
            sth = svc.get_sth()
            assert sth.tree_size == svc._store.size(), (
                f"STH tree_size={sth.tree_size} lags log size={svc._store.size()} after entry {i}"
            )

    def test_sth_is_persisted_to_store(self):
        svc = _fresh()
        svc.register_signed_statement(_digest(0))
        assert svc._store.get_latest_sth() is not None, "STH was not persisted after registration"

    def test_sth_persists_across_simulated_restart(self, tmp_path):
        """Close and reopen the SQLite store — persisted STH survives the restart."""
        db = str(tmp_path / "sth_restart.db")
        svc1 = AnchorerService(db_path=db)
        for i in range(4):
            svc1.register_signed_statement(_digest(i))
        sth_before = svc1.get_sth()
        svc1._store.close()

        svc2 = AnchorerService(db_path=db)
        sth_after = svc2.get_sth()
        assert sth_after.tree_size == sth_before.tree_size
        assert sth_after.root_hash == sth_before.root_hash
        # Signature is the SAME persisted one (not freshly re-signed on read).
        assert sth_after.signature.signature == sth_before.signature.signature

    def test_refresh_sth_advances_timestamp(self):
        """refresh_sth() produces a newer timestamp than the last persisted STH."""
        svc = _fresh()
        svc.register_signed_statement(_digest(0))
        sth1 = svc.get_sth()
        sth2 = svc.refresh_sth()
        assert sth2.tree_size == sth1.tree_size
        assert sth2.root_hash == sth1.root_hash
        # refresh_sth re-signs so the signature may differ (new timestamp).
        assert sth2.timestamp >= sth1.timestamp


# ---------------------------------------------------------------------------
# 2. Consistency proof between successive heads
# ---------------------------------------------------------------------------

class TestConsistencyProof:
    """RFC6962 consistency proof verifies between two valid STHs."""

    def _register_n(self, svc: AnchorerService, n: int, offset: int = 0) -> None:
        for i in range(offset, offset + n):
            svc.register_signed_statement(_digest(i))

    def test_consistency_proof_verifies(self):
        svc = _fresh()
        self._register_n(svc, 3)
        sth_small = svc.get_sth()           # tree_size = 3

        self._register_n(svc, 4, offset=3)
        sth_large = svc.get_sth()           # tree_size = 7

        proof = svc.consistency_proof(sth_small.tree_size, sth_large.tree_size)
        assert AnchorerService.verify_consistency(proof), (
            "consistency proof between size-3 and size-7 STHs did not verify"
        )
        assert proof.first_root == sth_small.root_hash
        assert proof.second_root == sth_large.root_hash

    def test_consistency_proof_single_entry(self):
        """Degenerate case: consistency proof from size 1 to size 1 (trivial)."""
        svc = _fresh()
        svc.register_signed_statement(_digest(0))
        sth = svc.get_sth()
        proof = svc.consistency_proof(sth.tree_size, sth.tree_size)
        assert AnchorerService.verify_consistency(proof)
        assert proof.proof == []  # RFC6962: same size → empty proof

    def test_consistency_proof_large_tree(self):
        svc = _fresh()
        self._register_n(svc, 10)
        sth_a = svc.get_sth()               # tree_size = 10
        self._register_n(svc, 10, offset=10)
        sth_b = svc.get_sth()               # tree_size = 20

        proof = svc.consistency_proof(sth_a.tree_size, sth_b.tree_size)
        assert AnchorerService.verify_consistency(proof)

    def test_tampered_proof_fails(self):
        """A consistency proof with a corrupted hash MUST be rejected — green + red."""
        svc = _fresh()
        self._register_n(svc, 3)
        sth_small = svc.get_sth()
        self._register_n(svc, 3, offset=3)
        sth_large = svc.get_sth()

        proof = svc.consistency_proof(sth_small.tree_size, sth_large.tree_size)
        # Verify the honest proof passes first (green).
        assert AnchorerService.verify_consistency(proof), "honest proof must pass"

        # Tamper: flip one bit in the first proof element.
        from capsule_anchor.anchoring.service import ConsistencyProof
        if proof.proof:
            tampered_hash = proof.proof[0][:-2] + (
                "00" if proof.proof[0][-2:] != "00" else "ff"
            )
            tampered = ConsistencyProof(
                first_size=proof.first_size,
                second_size=proof.second_size,
                first_root=proof.first_root,
                second_root=proof.second_root,
                proof=[tampered_hash] + proof.proof[1:],
            )
        else:
            # Single-size proof has no elements — tamper the root instead.
            tampered = ConsistencyProof(
                first_size=proof.first_size,
                second_size=proof.second_size,
                first_root="00" * 32,
                second_root=proof.second_root,
                proof=proof.proof,
            )
        # Red: tampered proof must NOT verify.
        assert not AnchorerService.verify_consistency(tampered), (
            "tampered consistency proof must not verify — staleness is not detectable if it does"
        )

    def test_wrong_root_in_proof_fails(self):
        """Proof with wrong first_root (forged old STH) must fail."""
        from capsule_anchor.anchoring.service import ConsistencyProof
        svc = _fresh()
        self._register_n(svc, 3)
        sth_small = svc.get_sth()
        self._register_n(svc, 3, offset=3)

        proof = svc.consistency_proof(sth_small.tree_size, svc._store.size())
        forged_root = "ab" * 32
        forged = ConsistencyProof(
            first_size=proof.first_size,
            second_size=proof.second_size,
            first_root=forged_root,
            second_root=proof.second_root,
            proof=proof.proof,
        )
        assert not AnchorerService.verify_consistency(forged)


# ---------------------------------------------------------------------------
# 3. Stale-head detection — BOTH directions required
# ---------------------------------------------------------------------------

class TestStaleHeadDetection:
    """A head that has not advanced with the log is DETECTABLE as stale.

    The task requires both directions: stale → True, fresh → False.
    A test that only ever returns True proves nothing; a test that only
    ever returns False is tautological. Both must pass.
    """

    def test_stale_by_tree_size_detectable(self):
        """STALE direction: snapshot STH at size N, log grows to M > N."""
        svc = _fresh()
        for i in range(3):
            svc.register_signed_statement(_digest(i))
        old_sth = svc.get_sth()             # tree_size = 3

        # Add more entries after the snapshot (log is now ahead of old_sth).
        for i in range(3, 6):
            svc.register_signed_statement(_digest(i))
        current_size = svc._store.size()    # 6

        assert old_sth.tree_size < current_size  # precondition: old_sth IS stale
        assert AnchorerService.is_sth_stale(old_sth, current_size), (
            "is_sth_stale must return True when tree_size < current log size"
        )

    def test_fresh_head_not_stale(self):
        """FRESH direction: current STH is not stale relative to the log."""
        svc = _fresh()
        for i in range(5):
            svc.register_signed_statement(_digest(i))
        current_sth = svc.get_sth()         # tree_size = 5
        current_size = svc._store.size()    # 5

        assert not AnchorerService.is_sth_stale(current_sth, current_size), (
            "is_sth_stale must return False when tree_size == current log size"
        )

    def test_stale_by_timestamp_detectable(self):
        """STALE direction: STH timestamp older than max_age_seconds."""
        svc = _fresh()
        svc.register_signed_statement(_digest(0))
        current_sth = svc.get_sth()
        current_size = svc._store.size()

        # Forge an STH with a timestamp 25 hours in the past (> 24-hour default MMD).
        from capsule_anchor.anchoring.service import SignedTreeHead
        stale_sth = SignedTreeHead(
            tree_size=current_sth.tree_size,
            root_hash=current_sth.root_hash,
            timestamp=datetime.now(UTC) - timedelta(hours=25),
            signature=current_sth.signature,
        )
        assert AnchorerService.is_sth_stale(
            stale_sth, current_size, max_age_seconds=86400
        ), "is_sth_stale must return True when timestamp > max_age_seconds"

    def test_recent_head_not_stale_by_timestamp(self):
        """FRESH direction: just-produced STH is not stale by timestamp."""
        svc = _fresh()
        svc.register_signed_statement(_digest(0))
        sth = svc.get_sth()
        current_size = svc._store.size()

        assert not AnchorerService.is_sth_stale(
            sth, current_size, max_age_seconds=86400
        ), "fresh STH must not be stale by timestamp"

    def test_stale_detected_via_consistency_proof_endpoint(self):
        """Monitor workflow: detect staleness then verify via consistency proof.

        A monitor who holds an old STH (tree_size=N) detects it is stale by
        comparing to the current STH (tree_size=M, M>N). It then requests a
        consistency proof from N to M. If the proof verifies, the log grew
        honestly (good — stale but not forked). If it fails, the service is
        lying (bad — fork detected). Both checks are exercised here.
        """
        svc = _fresh()
        for i in range(3):
            svc.register_signed_statement(_digest(i))
        cached_sth = svc.get_sth()          # monitor's snapshot: tree_size=3

        for i in range(3, 7):
            svc.register_signed_statement(_digest(i))
        live_sth = svc.get_sth()            # current: tree_size=7

        # Step 1: monitor detects staleness.
        assert AnchorerService.is_sth_stale(cached_sth, live_sth.tree_size)

        # Step 2: consistency proof — honest log, so it MUST verify.
        proof = svc.consistency_proof(cached_sth.tree_size, live_sth.tree_size)
        assert AnchorerService.verify_consistency(proof), (
            "honest log grew, so consistency proof from old to new STH must verify"
        )
        # The proof roots match the actual STH roots.
        assert proof.first_root == cached_sth.root_hash
        assert proof.second_root == live_sth.root_hash

    def test_both_stale_directions_in_sequence(self):
        """Both directions exercised in a single test — the canonical guard."""
        svc = _fresh()
        for i in range(4):
            svc.register_signed_statement(_digest(i))
        old_sth = svc.get_sth()             # tree_size = 4 (will become stale)

        for i in range(4, 8):
            svc.register_signed_statement(_digest(i))
        current_sth = svc.get_sth()         # tree_size = 8 (current)
        current_size = svc._store.size()

        # OLD STH → stale (tree_size=4 < current_size=8).
        assert AnchorerService.is_sth_stale(old_sth, current_size), (
            "stale direction: old_sth must be detected as stale"
        )
        # CURRENT STH → not stale.
        assert not AnchorerService.is_sth_stale(current_sth, current_size), (
            "fresh direction: current_sth must NOT be detected as stale"
        )


# ---------------------------------------------------------------------------
# 4. HTTP surface — STH endpoint over the full app
# ---------------------------------------------------------------------------

class TestSTHHTTPSurface:
    """GET /anchor/sth via the FastAPI test client."""

    @pytest.fixture()
    def client(self):
        from capsule_anchor.app import create_app
        from fastapi.testclient import TestClient
        return TestClient(create_app())

    def test_sth_503_on_empty_log(self, client):
        resp = client.get("/anchor/sth")
        assert resp.status_code == 503

    def test_sth_200_after_registration(self, client):
        payload = hashlib.sha256(b"http-surface-test").hexdigest()
        client.post("/v1/digest", json={"capsule_id": payload})
        resp = client.get("/anchor/sth")
        assert resp.status_code == 200
        body = resp.json()
        assert body["tree_size"] >= 1
        assert len(body["root_hash"]) == 64
        assert "signature" in body

    def test_sth_advances_after_new_registration(self, client):
        p1 = hashlib.sha256(b"advance-test-1").hexdigest()
        p2 = hashlib.sha256(b"advance-test-2").hexdigest()
        client.post("/v1/digest", json={"capsule_id": p1})
        sth1 = client.get("/anchor/sth").json()

        client.post("/v1/digest", json={"capsule_id": p2})
        sth2 = client.get("/anchor/sth").json()

        assert sth2["tree_size"] == sth1["tree_size"] + 1, (
            "STH tree_size must advance by 1 after each new registration"
        )

    def test_consistency_proof_endpoint_verifies(self, client):
        """GET /anchor/consistency-proof returns a proof that verify_consistency accepts."""
        for i in range(3):
            pid = hashlib.sha256(f"cp-entry-{i}".encode()).hexdigest()
            client.post("/v1/digest", json={"capsule_id": pid})
        sth3 = client.get("/anchor/sth").json()
        size3 = sth3["tree_size"]

        for i in range(3, 6):
            pid = hashlib.sha256(f"cp-entry-{i}".encode()).hexdigest()
            client.post("/v1/digest", json={"capsule_id": pid})
        sth6 = client.get("/anchor/sth").json()
        size6 = sth6["tree_size"]

        resp = client.get(f"/anchor/consistency-proof?old_size={size3}&new_size={size6}")
        assert resp.status_code == 200
        from capsule_anchor.anchoring.service import ConsistencyProof
        proof = ConsistencyProof.model_validate(resp.json())
        assert AnchorerService.verify_consistency(proof)
        assert proof.first_root == sth3["root_hash"]
        assert proof.second_root == sth6["root_hash"]
