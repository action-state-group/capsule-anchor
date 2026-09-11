"""Concurrent STH refresh across independent instances (Cloud Run scale-out).

PR #20 added a background daemon that re-signs and persists the Signed Tree
Head (STH) into a SINGLETON ``signed_tree_heads`` row. With N Cloud Run
instances (cap off, per DEPLOY.md's HA guidance), N independent processes
write that row on independent, unsynchronized ~60s timers. This test answers
the two questions from [anchor-instance-count-and-sth-refresh-race] with real
cross-process concurrency, in the shape of [ldg-guardengine-caps-race]
(subprocesses, not threads, coordinated via events to force a deterministic
interleaving rather than hoping a real clock race reproduces):

1. MONOTONICITY -- can a slower-committing writer with an EARLIER timestamp
   overwrite a faster writer's already-observed, later-timestamped STH, so a
   client polling twice sees the head move backwards in time? Before the fix:
   yes (``put_sth`` was an unconditional last-write-wins overwrite). After
   the fix: no (``put_sth`` is now an atomic compare-and-swap on
   ``(tree_size, timestamp)``, enforced in the SQL WHERE clause so no
   process can win the race by writing an older head).

2. SELF-CONSISTENCY -- can an interleaved write leave a signature that does
   not verify against its own stored root? No: ``put_sth`` always persists
   one complete, pre-signed JSON document in a single atomic statement, so
   whichever writer's row wins is always internally self-consistent. This
   was already true before the fix and stays true after -- asserted here as
   a regression guard, not as the defect under test.
"""

from __future__ import annotations

import multiprocessing as mp
from datetime import datetime

from capsule_anchor.anchoring.service import AnchorerService, SignedTreeHead, sth_payload
from capsule_anchor.anchoring.store import SqliteLogStore
from capsule_anchor.attestation.service import AttestorService
from capsule_anchor.contracts.crypto_shim import default_crypto


def _shared_attestor(priv: bytes, pub: bytes) -> AttestorService:
    """An AttestorService pinned to a FIXED keypair.

    Simulates every Cloud Run instance loading the SAME authority key from
    Secret Manager (``CAPSULE_ANCHOR_SIGNING_KEY``, see deploy/cloudbuild.yaml)
    -- production instances share one physical key, they don't each generate
    their own.
    """
    att = AttestorService()
    att._private_key = priv  # noqa: SLF001 -- test-only key pin, see docstring
    att._public_key = pub  # noqa: SLF001
    return att


def _persist_sth_at(
    db_path: str, priv: bytes, pub: bytes, tree_size: int, ts_iso: str, ready_evt, go_evt
) -> None:
    """Subprocess body: sign and persist an STH at an EXPLICIT timestamp.

    Bypasses AnchorerService.refresh_sth()'s internal clock so the test can
    force a specific commit ORDER deterministically -- exactly the way
    [ldg-guardengine-caps-race] forced its append-order race instead of
    hoping a real clock race would reproduce on every CI run.
    """
    store = SqliteLogStore(db_path)
    attestor = _shared_attestor(priv, pub)
    root_hash = "ab" * 32  # fixed; this test is about write ORDERING, not tree content
    timestamp = datetime.fromisoformat(ts_iso)
    signature = attestor.attest(sth_payload(tree_size, root_hash, timestamp))
    sth = SignedTreeHead(
        tree_size=tree_size, root_hash=root_hash, timestamp=timestamp, signature=signature
    )

    ready_evt.set()  # tell the parent this writer has built its STH and is ready to commit
    assert go_evt.wait(timeout=10), "parent never signaled commit order"
    store.put_sth(sth.model_dump_json(), tree_size=tree_size, timestamp=timestamp)
    store.close()


def _fixed_keypair() -> tuple[bytes, bytes]:
    return default_crypto().generate_keypair()


class TestSTHRefreshMonotonicity:
    """A client polling GET /anchor/sth must never see the timestamp regress."""

    def test_slower_writer_with_earlier_timestamp_cannot_win_the_race(self, tmp_path):
        db_path = str(tmp_path / "sth_race.db")
        priv, pub = _fixed_keypair()

        # Seed the singleton table so both writers hit the ON CONFLICT path.
        SqliteLogStore(db_path).close()

        ctx = mp.get_context("spawn")
        ready_fast, ready_slow = ctx.Event(), ctx.Event()
        go_fast, go_slow = ctx.Event(), ctx.Event()

        # Same tree_size for both -- two instances refreshing an idle log.
        # "fast" reads a LATER wall-clock timestamp but is told to commit FIRST.
        # "slow" reads an EARLIER wall-clock timestamp but is told to commit
        # SECOND -- reproducing an instance whose signing/IO took longer even
        # though its clock read happened first.
        ts_fast = "2026-01-01T00:00:01.000000+00:00"
        ts_slow = "2026-01-01T00:00:00.000000+00:00"

        proc_fast = ctx.Process(
            target=_persist_sth_at, args=(db_path, priv, pub, 5, ts_fast, ready_fast, go_fast)
        )
        proc_slow = ctx.Process(
            target=_persist_sth_at, args=(db_path, priv, pub, 5, ts_slow, ready_slow, go_slow)
        )
        proc_fast.start()
        proc_slow.start()
        try:
            assert ready_fast.wait(timeout=10), "fast writer never became ready"
            assert ready_slow.wait(timeout=10), "slow writer never became ready"

            # A client polls right after the FAST (later-timestamp) writer commits.
            go_fast.set()
            proc_fast.join(timeout=10)
            reader = SqliteLogStore(db_path)
            observed_1 = SignedTreeHead.model_validate_json(reader.get_latest_sth())
            reader.close()
            assert observed_1.timestamp == datetime.fromisoformat(ts_fast)

            # ...then the SLOW (earlier-timestamp) writer commits AFTER it.
            go_slow.set()
            proc_slow.join(timeout=10)
            reader = SqliteLogStore(db_path)
            observed_2 = SignedTreeHead.model_validate_json(reader.get_latest_sth())
            reader.close()
        finally:
            proc_fast.join(timeout=10)
            proc_slow.join(timeout=10)

        # THE FIX: a client polling twice must NEVER see the STH timestamp
        # regress, no matter which writer's commit lands last.
        assert observed_2.timestamp >= observed_1.timestamp, (
            f"STH timestamp moved BACKWARDS: {observed_1.timestamp!r} -> "
            f"{observed_2.timestamp!r}. A slower writer with an earlier "
            "timestamp overwrote a fresher STH a client already observed."
        )
        # The slow writer's earlier-timestamped STH must have been rejected;
        # the fast writer's STH is still what's stored.
        assert observed_2.timestamp == datetime.fromisoformat(ts_fast)

    def test_larger_tree_size_always_wins_even_with_an_earlier_timestamp(self, tmp_path):
        """tree_size regressing is worse than a timestamp regressing -- a
        writer signing a LARGER tree must win even if its timestamp (e.g.
        from a skewed clock) reads earlier than the smaller-tree writer's.
        """
        db_path = str(tmp_path / "sth_race_size.db")
        priv, pub = _fixed_keypair()
        SqliteLogStore(db_path).close()

        ctx = mp.get_context("spawn")
        ready_small, ready_large = ctx.Event(), ctx.Event()
        go_small, go_large = ctx.Event(), ctx.Event()

        ts_small = "2026-01-01T00:00:05.000000+00:00"  # later timestamp, smaller tree
        ts_large = "2026-01-01T00:00:00.000000+00:00"  # earlier timestamp, larger tree

        proc_small = ctx.Process(
            target=_persist_sth_at, args=(db_path, priv, pub, 3, ts_small, ready_small, go_small)
        )
        proc_large = ctx.Process(
            target=_persist_sth_at, args=(db_path, priv, pub, 7, ts_large, ready_large, go_large)
        )
        proc_small.start()
        proc_large.start()
        try:
            assert ready_small.wait(timeout=10)
            assert ready_large.wait(timeout=10)

            # small commits first...
            go_small.set()
            proc_small.join(timeout=10)
            # ...then large commits second, despite its EARLIER timestamp.
            go_large.set()
            proc_large.join(timeout=10)
        finally:
            proc_small.join(timeout=10)
            proc_large.join(timeout=10)

        reader = SqliteLogStore(db_path)
        final = SignedTreeHead.model_validate_json(reader.get_latest_sth())
        reader.close()
        assert final.tree_size == 7, "a larger tree_size must never be reverted by a smaller one"


class TestSTHSelfConsistency:
    """The winning row is always a validly self-signed STH -- regression guard."""

    def test_concurrent_writers_never_leave_a_non_self_verifying_sth(self, tmp_path):
        db_path = str(tmp_path / "sth_race_verify.db")
        priv, pub = _fixed_keypair()
        SqliteLogStore(db_path).close()

        ctx = mp.get_context("spawn")
        ready_a, ready_b = ctx.Event(), ctx.Event()
        go_a, go_b = ctx.Event(), ctx.Event()
        ts_a = "2026-01-01T00:00:02.000000+00:00"
        ts_b = "2026-01-01T00:00:03.000000+00:00"

        proc_a = ctx.Process(
            target=_persist_sth_at, args=(db_path, priv, pub, 2, ts_a, ready_a, go_a)
        )
        proc_b = ctx.Process(
            target=_persist_sth_at, args=(db_path, priv, pub, 2, ts_b, ready_b, go_b)
        )
        proc_a.start()
        proc_b.start()
        try:
            assert ready_a.wait(timeout=10)
            assert ready_b.wait(timeout=10)
            go_a.set()
            go_b.set()
        finally:
            proc_a.join(timeout=10)
            proc_b.join(timeout=10)

        reader = SqliteLogStore(db_path)
        stored_json = reader.get_latest_sth()
        reader.close()
        winner = SignedTreeHead.model_validate_json(stored_json)

        attestor = _shared_attestor(priv, pub)
        payload = sth_payload(winner.tree_size, winner.root_hash, winner.timestamp)
        assert attestor.verify(payload, winner.signature), (
            "the persisted STH's signature does not verify against its own "
            "stored (tree_size, root_hash, timestamp) -- a torn/interleaved "
            "write corrupted the singleton row"
        )


class TestServiceLevelIntegration:
    """The fix is wired through AnchorerService.refresh_sth(), not just the store."""

    def test_refresh_sth_never_regresses_across_two_service_instances(self, tmp_path):
        """Two AnchorerService instances (simulating two Cloud Run instances
        sharing one Postgres-equivalent store) pointed at the same db file,
        both calling refresh_sth() -- the persisted head must still reflect
        whichever call actually advances (tree_size, timestamp), never a
        regression, exercised through the real service entrypoint the
        background daemon calls (app.py's ``_start_sth_refresh_thread``).
        """
        db_path = str(tmp_path / "sth_service_race.db")

        svc1 = AnchorerService(db_path=db_path)
        svc1.register_signed_statement(b"seed-entry")
        first = svc1.refresh_sth()

        svc2 = AnchorerService(store=SqliteLogStore(db_path))
        # svc2 has its own (ephemeral) authority key in this constructor path,
        # so we only assert on tree_size/timestamp ordering here, not
        # cross-instance signature verification (that requires a shared
        # key_provider, covered by TestSTHSelfConsistency above).
        second = svc2.refresh_sth()

        stored = SignedTreeHead.model_validate_json(svc1._store.get_latest_sth())  # noqa: SLF001
        assert stored.tree_size >= first.tree_size
        assert (stored.tree_size, stored.timestamp) >= (first.tree_size, first.timestamp)
        assert (stored.tree_size, stored.timestamp) >= (second.tree_size, second.timestamp)
