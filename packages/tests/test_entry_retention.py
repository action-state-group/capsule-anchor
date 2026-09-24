# SPDX-License-Identifier: Apache-2.0
"""Entry-retention tests.

Covers:
1. Config parsing (``CAPSULE_ANCHOR_ENTRY_RETENTION``) -- unlimited default,
   fail-closed on a malformed value.
2. Default is a no-op -- upgrading to this code changes nothing until an
   operator opts in.
3. THE key negative case: entries aged out -> an old receipt still
   verifies against a RETAINED root. Both halves shown (pruning actually
   happened; the receipt survives it anyway), each with its mutant
   demonstrated failing.
4. Root history (``get_sth_at``) survives a simulated restart, same as the
   rest of the durable state.
5. ``/health`` reports the declared posture.
"""
from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import pytest

from capsule_anchor.anchoring import service as service_module
from capsule_anchor.anchoring.retention import declared_posture, entry_retention_seconds
from capsule_anchor.anchoring.service import AnchorerService, SignedTreeHead
from capsule_anchor.app import create_app
from fastapi.testclient import TestClient


def _digest(n: int) -> bytes:
    return hashlib.sha256(f"retention-test-entry-{n}".encode()).digest()


def _fixed_clock(monkeypatch, start: datetime) -> None:
    """Deterministic, monotonically-advancing clock so a retention window can
    be crossed without sleeping. Each call advances 1000s -- comfortably past
    any second-scale window used below."""
    clock = [start]

    def _fake_now() -> datetime:
        clock[0] = clock[0] + timedelta(seconds=1000)
        return clock[0]

    monkeypatch.setattr(service_module, "_now", _fake_now)


# ---------------------------------------------------------------------------
# 1. Config parsing
# ---------------------------------------------------------------------------

class TestRetentionConfig:
    def test_unset_is_unlimited(self, monkeypatch):
        monkeypatch.delenv("CAPSULE_ANCHOR_ENTRY_RETENTION", raising=False)
        assert entry_retention_seconds() is None
        assert declared_posture() == "unlimited"

    def test_explicit_unlimited_case_insensitive(self, monkeypatch):
        monkeypatch.setenv("CAPSULE_ANCHOR_ENTRY_RETENTION", "Unlimited")
        assert entry_retention_seconds() is None
        assert declared_posture() == "unlimited"

    def test_seconds_value(self, monkeypatch):
        monkeypatch.setenv("CAPSULE_ANCHOR_ENTRY_RETENTION", "90")
        assert entry_retention_seconds() == 90
        assert declared_posture() == "90s"

    def test_malformed_value_fails_closed(self, monkeypatch):
        monkeypatch.setenv("CAPSULE_ANCHOR_ENTRY_RETENTION", "not-a-number")
        with pytest.raises(RuntimeError):
            entry_retention_seconds()

    def test_zero_fails_closed(self, monkeypatch):
        monkeypatch.setenv("CAPSULE_ANCHOR_ENTRY_RETENTION", "0")
        with pytest.raises(RuntimeError):
            entry_retention_seconds()

    def test_negative_fails_closed(self, monkeypatch):
        monkeypatch.setenv("CAPSULE_ANCHOR_ENTRY_RETENTION", "-5")
        with pytest.raises(RuntimeError):
            entry_retention_seconds()


# ---------------------------------------------------------------------------
# 2. Default is a no-op
# ---------------------------------------------------------------------------

class TestDefaultIsNoOp:
    def test_prune_is_noop_when_unlimited(self, monkeypatch):
        monkeypatch.delenv("CAPSULE_ANCHOR_ENTRY_RETENTION", raising=False)
        svc = AnchorerService()
        for i in range(3):
            svc.register_signed_statement(_digest(i))
        far_future = datetime.now(UTC) + timedelta(days=3650)
        assert svc.prune_expired_statements(now=far_future) == 0

    def test_app_starts_without_retention_thread_when_unset(self, monkeypatch):
        """create_app() must not require the knob -- absence is a valid,
        fully-supported default, not a degraded state."""
        monkeypatch.delenv("CAPSULE_ANCHOR_ENTRY_RETENTION", raising=False)
        client = TestClient(create_app())
        assert client.get("/health").json()["entry_retention"] == "unlimited"


# ---------------------------------------------------------------------------
# 3. THE negative: aged-out entry still verifies against a retained root
# ---------------------------------------------------------------------------

class TestAgedOutEntryStillVerifies:
    """The asymmetric trade's core property. Register an entry, advance the
    log well past it (so the singleton "latest" STH no longer covers its
    tree_size), prune its cache row, and show the ALREADY-ISSUED receipt
    still verifies -- against a root fetched from the retained HISTORY, not
    a live recompute or the singleton latest.
    """

    def test_pruned_entry_receipt_verifies_against_retained_root(self, monkeypatch):
        monkeypatch.setenv("CAPSULE_ANCHOR_ENTRY_RETENTION", "1")  # 1-second window
        _fixed_clock(monkeypatch, datetime(2026, 1, 1, tzinfo=UTC))

        svc = AnchorerService()
        _receipt, entry_hash, leaf_index, tree_size = svc.register_signed_statement(_digest(0))

        # Sanity/green: verifies BEFORE any pruning.
        proof_before = svc.inclusion_proof_ct(leaf_index, tree_size)
        assert svc.verify_inclusion(proof_before), "receipt must verify before pruning (sanity)"
        old_root_hash = proof_before.root_hash

        # Advance the log well past this entry's tree_size -- the singleton
        # "latest" STH no longer covers tree_size once this runs.
        for i in range(1, 6):
            svc.register_signed_statement(_digest(i))
        current_sth = svc.get_sth()
        assert current_sth.tree_size > tree_size, "log must have advanced past the old entry"

        # Age out entry 0's cache row (the fake clock has advanced well past
        # the 1s window by now).
        pruned = svc.prune_expired_statements()
        assert pruned >= 1, "pruning must actually remove the aged-out cache row"

        # Half 1: the re-issue cache is gone -- proves pruning is not a no-op.
        assert svc.get_registered_statement(entry_hash) is None, (
            "pruned entry must no longer be re-issuable from the cache"
        )

        # Half 2: the ALREADY-ISSUED receipt still verifies -- self-contained,
        # independent of the cache (log_entries is never pruned).
        proof_after = svc.inclusion_proof_ct(leaf_index, tree_size)
        assert svc.verify_inclusion(proof_after), (
            "an old receipt must still verify after its cache entry is pruned"
        )

        # Half 3: the root it verifies against is one this witness actually
        # SIGNED and RETAINED at that exact historical tree_size -- not
        # merely internally self-consistent, and not the CURRENT (advanced)
        # root, which is a different value entirely.
        retained = svc.get_sth_at(tree_size)
        assert retained is not None, "root history must retain the STH at the old tree_size"
        assert retained.root_hash == old_root_hash == proof_after.root_hash
        assert retained.root_hash != current_sth.root_hash, (
            "sanity: the log actually advanced, so latest != retained-at-old-size"
        )
        assert svc.verify_sth(retained), "retained historical STH signature must verify"

    def test_mutant_no_prune_leaves_cache_hit(self, monkeypatch):
        """R4: the mutant where pruning silently no-ops (e.g. a knob wired
        but never invoked). The cache-miss assertion above must FAIL against
        this mutant -- shown here by demonstrating the SAME assertion holds
        both ways depending on whether prune actually ran."""
        monkeypatch.setenv("CAPSULE_ANCHOR_ENTRY_RETENTION", "1")
        _fixed_clock(monkeypatch, datetime(2026, 1, 1, tzinfo=UTC))
        svc = AnchorerService()
        _, entry_hash, _, _ = svc.register_signed_statement(_digest(0))

        # Mutant state: prune_expired_statements() never called. The cache
        # row must still be there -- this is what "pruning is a no-op" looks
        # like, and it is what the real assertion (in the test above) must
        # be able to detect and fail against.
        assert svc.get_registered_statement(entry_hash) is not None, (
            "mutant sanity: without pruning, the cache entry is still present"
        )

        # Apply the real prune and show the identical assertion flips to
        # None -- i.e. the check is capable of distinguishing the two states,
        # not a tautology that passes either way.
        svc.prune_expired_statements()
        assert svc.get_registered_statement(entry_hash) is None

    def test_mutant_latest_sth_instead_of_history_gives_wrong_root(self, monkeypatch):
        """R4, other half: the mutant where "retained root" reads the
        pre-existing singleton (get_latest_sth) instead of the new history
        (get_sth_at). Confirms get_sth_at is load-bearing: the singleton
        silently returns the WRONG root for an old tree_size once the log
        has advanced -- exactly the failure this feature exists to prevent.
        """
        monkeypatch.setenv("CAPSULE_ANCHOR_ENTRY_RETENTION", "1")
        _fixed_clock(monkeypatch, datetime(2026, 1, 1, tzinfo=UTC))
        svc = AnchorerService()
        _, _, leaf_index, tree_size = svc.register_signed_statement(_digest(0))
        proof = svc.inclusion_proof_ct(leaf_index, tree_size)
        old_root_hash = proof.root_hash

        for i in range(1, 6):
            svc.register_signed_statement(_digest(i))

        # The mutant: use the pre-existing singleton "latest" accessor
        # instead of the new historical lookup.
        mutant_latest = SignedTreeHead.model_validate_json(svc._store.get_latest_sth())
        assert mutant_latest.root_hash != old_root_hash, (
            "mutant must actually diverge from the true historical root -- "
            "otherwise this test proves nothing"
        )

        # The real fix does not have this bug.
        retained = svc.get_sth_at(tree_size)
        assert retained.root_hash == old_root_hash


# ---------------------------------------------------------------------------
# 4. Root history survives a simulated restart (SQLite backend)
# ---------------------------------------------------------------------------

class TestRootHistoryPersistsAcrossRestart:
    def test_get_sth_at_survives_reopen_after_pruning(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CAPSULE_ANCHOR_ENTRY_RETENTION", "1")
        _fixed_clock(monkeypatch, datetime(2026, 1, 1, tzinfo=UTC))

        db = str(tmp_path / "retention.db")
        svc1 = AnchorerService(db_path=db)
        _, entry_hash, leaf_index, tree_size = svc1.register_signed_statement(_digest(0))
        for i in range(1, 4):
            svc1.register_signed_statement(_digest(i))
        old_root_hash = svc1.get_sth_at(tree_size).root_hash

        pruned = svc1.prune_expired_statements()
        assert pruned >= 1
        assert svc1.get_registered_statement(entry_hash) is None
        svc1._store.close()

        # Reopen -- simulates a process restart.
        svc2 = AnchorerService(db_path=db)
        retained = svc2.get_sth_at(tree_size)
        assert retained is not None, "retained root history must survive a restart"
        assert retained.root_hash == old_root_hash
        # The pruned cache row must ALSO stay pruned (not resurrected by reopen).
        assert svc2.get_registered_statement(entry_hash) is None
        # And the old receipt still verifies.
        proof = svc2.inclusion_proof_ct(leaf_index, tree_size)
        assert svc2.verify_inclusion(proof)


# ---------------------------------------------------------------------------
# 5. /health reports the declared posture
# ---------------------------------------------------------------------------

class TestHealthReportsPosture:
    def test_health_reports_unlimited_by_default(self, monkeypatch):
        monkeypatch.delenv("CAPSULE_ANCHOR_ENTRY_RETENTION", raising=False)
        client = TestClient(create_app())
        assert client.get("/health").json()["entry_retention"] == "unlimited"

    def test_health_reports_configured_window(self, monkeypatch):
        monkeypatch.setenv("CAPSULE_ANCHOR_ENTRY_RETENTION", "120")
        client = TestClient(create_app())
        assert client.get("/health").json()["entry_retention"] == "120s"

    def test_app_startup_fails_closed_on_malformed_retention(self, monkeypatch):
        monkeypatch.setenv("CAPSULE_ANCHOR_ENTRY_RETENTION", "garbage")
        with pytest.raises(RuntimeError):
            create_app()
