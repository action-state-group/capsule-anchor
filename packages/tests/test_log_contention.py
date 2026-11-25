"""capsule-anchor#109: concurrent appends never answer 500, and a registration
reads only the log entries it has not seen.

The hosted witness runs several instances on one Postgres database. Each
instance's service lock serializes only its own threads, so the
registration section also takes a cross-instance writer lock
(``PostgresLogStore.writer_lock``); an index taken anyway answers 429.
"""

from __future__ import annotations

import hashlib
import os
import random
import threading

import pytest
from capsule_anchor.anchoring import ct
from capsule_anchor.anchoring.ct_cache import MEMO_MIN, CachedTree
from capsule_anchor.anchoring.service import AnchorerService, ct_leaf_hash
from capsule_anchor.anchoring.store import (
    InMemoryLogStore,
    LogIndexTaken,
    SqliteLogStore,
    WriterBusy,
)
from capsule_anchor.attestation.service import AttestorService


def _digest(n: int | str) -> bytes:
    return hashlib.sha256(f"contention-{n}".encode()).digest()


def _leaf(n: int) -> str:
    return ct.leaf_hash(f"leaf-{n}".encode())


# --- the cached tree equals the full computation ------------------------------


def test_cached_root_equals_full_tree_hash_at_every_size():
    tree = CachedTree()
    leaves: list[str] = []
    assert tree.root(0) == ct.merkle_tree_hash([])
    for n in range(1, 601):
        leaves.append(_leaf(n))
        tree.append(leaves[-1])
        assert tree.root(n) == ct.merkle_tree_hash(leaves), n
    # Earlier sizes still answer from the grown tree (historical roots).
    for n in (1, 2, 255, 256, 257, 511, 512, 513):
        assert tree.root(n) == ct.merkle_tree_hash(leaves[:n]), n


def test_cached_audit_path_equals_full_audit_path():
    tree = CachedTree()
    leaves = [_leaf(n) for n in range(600)]
    for h in leaves:
        tree.append(h)
    rng = random.Random(109)
    sizes = list(range(1, 70)) + [255, 256, 257, 300, 511, 512, 513, 600]
    for size in sizes:
        indices = range(size) if size < 70 else rng.sample(range(size), 25) + [0, size - 1]
        for i in indices:
            assert tree.audit_path(i, size) == ct.inclusion_audit_path(i, leaves[:size]), (i, size)


def test_memo_keeps_only_large_complete_subtrees():
    tree = CachedTree()
    for n in range(4 * MEMO_MIN + 3):
        tree.append(_leaf(n))
    tree.root(tree.size)
    assert tree._memo  # noqa: SLF001
    assert all(size >= MEMO_MIN and size & (size - 1) == 0 for _start, size in tree._memo)  # noqa: SLF001


# --- a registration reads only new entries -------------------------------------


class _CountingStore(InMemoryLogStore):
    def __init__(self) -> None:
        super().__init__()
        self.read_from: list[int] = []
        self.full_reads = 0

    def entries_after(self, after_index):
        self.read_from.append(after_index)
        return super().entries_after(after_index)

    def all_entries(self):
        self.full_reads += 1
        return super().all_entries()

    def size(self):
        self.full_reads += 1
        return super().size()


def test_registration_reads_only_entries_it_has_not_seen():
    store = _CountingStore()
    svc = AnchorerService(store=store)
    for n in range(50):
        svc.register_signed_statement_full(_digest(n))
    assert store.full_reads == 0
    # Every read starts where the cache ends: never from 0 again.
    assert store.read_from == sorted(store.read_from)
    assert store.read_from.count(0) == 1
    assert svc.verify_log()
    # The receipt's tree and the tree head agree with a full recomputation.
    leaves = [ct_leaf_hash(e) for e in store.all_entries()]
    assert svc.get_sth().root_hash == ct.merkle_tree_hash(leaves)


# --- an index taken by another writer ---------------------------------------


class _RacingStore(InMemoryLogStore):
    """Before our insert lands, another instance (one without the writer lock,
    as during a rollout) appends at the same index."""

    def __init__(self, other: AnchorerService | None = None) -> None:
        super().__init__()
        self.race_next = False

    def append_entry(self, entry):
        if self.race_next:
            self.race_next = False
            competitor = entry.model_copy(update={"payload_hash": "ff" * 32})
            super().append_entry(competitor)
        super().append_entry(entry)


def test_an_index_taken_by_another_writer_is_refused_as_busy_and_writes_nothing():
    store = _RacingStore()
    svc = AnchorerService(store=store)
    svc.register_signed_statement_full(_digest("first"))
    store.race_next = True
    with pytest.raises(WriterBusy):
        svc.register_signed_statement_full(_digest("raced"))
    # Only the competitor landed; our statement has no receipt and no leaf.
    assert store.size() == 2
    assert store.get_statement(_digest("raced").hex()) is None
    # The next try syncs past the competitor and succeeds.
    result = svc.register_signed_statement_full(_digest("raced"))
    assert result.leaf_index == 2
    assert result.tree_size == 3


class _AckLostStore(InMemoryLogStore):
    """The insert commits, then the acknowledgement is lost and the replay
    finds its own row (PostgresLogStore._transact's reconnect-and-retry)."""

    def __init__(self) -> None:
        super().__init__()
        self.lose_next = False

    def append_entry(self, entry):
        super().append_entry(entry)
        if self.lose_next:
            self.lose_next = False
            raise LogIndexTaken(entry.log_index)


def test_a_replayed_commit_of_our_own_entry_is_success_not_a_second_leaf():
    store = _AckLostStore()
    svc = AnchorerService(store=store)
    svc.register_signed_statement_full(_digest("a"))
    store.lose_next = True
    result = svc.register_signed_statement_full(_digest("b"))
    assert result.leaf_index == 1
    assert store.size() == 2
    assert svc.verify_log()


def test_busy_checkpoint_post_answers_429_with_retry_after(monkeypatch):
    from capsule_anchor.anchoring import router
    from capsule_anchor.app import create_app
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from fastapi.testclient import TestClient

    from .test_checkpoints_and_register_witness_host import _checkpoint_cose, _peaks_for, _post_checkpoint

    client = TestClient(create_app())
    svc = router.get_service()

    def busy(*_a, **_k):
        raise WriterBusy("another instance holds the log writer lock")

    monkeypatch.setattr(svc, "witness_checkpoint", busy)
    key = Ed25519PrivateKey.generate()
    resp = client.post(
        "/checkpoints",
        content=_checkpoint_cose(key, log_id="busy-log", mmr_size=3, new_peaks=_peaks_for("busy")),
        headers={"Content-Type": "application/cll-checkpoint+cbor"},
    )
    assert resp.status_code == 429, resp.text
    assert resp.headers["retry-after"] == "2"
    assert _post_checkpoint  # the helper module is the same one the witness tests use


def test_busy_answers_429_with_retry_after(monkeypatch):
    from capsule_anchor.anchoring import router
    from capsule_anchor.app import create_app
    from fastapi.testclient import TestClient

    client = TestClient(create_app())
    svc = router.get_service()

    def busy(*_a, **_k):
        raise WriterBusy("another instance holds the log writer lock")

    monkeypatch.setattr(svc, "register_signed_statement_full", busy)
    resp = client.post("/register", json={"capsule_id": "ab" * 32})
    assert resp.status_code == 429, resp.text
    assert resp.headers["retry-after"] == "2"
    assert resp.json()["detail"]["code"] == "log_busy"


def test_sqlite_store_names_a_taken_index(tmp_path):
    store = SqliteLogStore(str(tmp_path / "w.db"))
    svc = AnchorerService(store=store)
    entry = svc._append_log("k", b"x", svc_now())  # noqa: SLF001
    with pytest.raises(LogIndexTaken):
        store.append_entry(entry)
    assert store.get_entry(0) == entry


def svc_now():
    from datetime import UTC, datetime

    return datetime.now(UTC)


# --- two instances on one SQLite file: each section reads fresh state ---------


def test_a_second_instance_sees_the_first_instances_statement_and_tip(tmp_path):
    db = str(tmp_path / "shared.db")
    attestor = AttestorService()
    a = AnchorerService(attestor=attestor, store=SqliteLogStore(db))
    b = AnchorerService(attestor=attestor, store=SqliteLogStore(db))
    a.register_signed_statement_full(_digest(1))
    first = b.register_signed_statement_full(_digest(2))  # b's cache is cold
    again = a.register_signed_statement_full(_digest(2))  # a's cache is stale
    assert again.leaf_index == first.leaf_index  # one statement, one leaf
    assert a.log_size() == b.log_size() == 2
    assert a.verify_log() and b.verify_log()


# --- Postgres: the cross-instance writer lock ---------------------------------

# These tests TRUNCATE every table, so they run only against a database named
# for tests, never the application's CAPSULE_ANCHOR_DATABASE_URL.
_PG_URL = os.environ.get("CAPSULE_ANCHOR_TEST_DATABASE_URL")
_pg_required = pytest.mark.skipif(not _PG_URL, reason="CAPSULE_ANCHOR_TEST_DATABASE_URL not set")


def _pg_pair():
    from capsule_anchor.anchoring.store import PostgresLogStore

    first = PostgresLogStore(_PG_URL)
    with first._lock, first._conn.transaction():  # noqa: SLF001
        first._conn.execute(  # noqa: SLF001
            "TRUNCATE TABLE submitted_statements, log_capsule_bindings, "
            "countersigned_roots, log_entries, checkpoint_witnesses, "
            "checkpoint_records, checkpoint_equivocations RESTART IDENTITY CASCADE"
        )
    return first, PostgresLogStore(_PG_URL)


@_pg_required
def test_pg_writer_lock_excludes_another_instance_until_released():
    one, two = _pg_pair()
    with one.writer_lock():
        with pytest.raises(WriterBusy), two.writer_lock(timeout_s=0.2):
            pass
    with two.writer_lock(timeout_s=1.0):
        pass


@_pg_required
def test_pg_writer_lock_is_reentrant_in_one_process():
    one, _two = _pg_pair()
    with one.writer_lock(), one.writer_lock():
        pass
    with _two.writer_lock(timeout_s=1.0):
        pass


@_pg_required
def test_pg_a_taken_index_is_named_not_a_unique_violation():
    one, two = _pg_pair()
    attestor = AttestorService()
    svc = AnchorerService(attestor=attestor, store=one)
    svc.register_signed_statement_full(_digest("pg-1"))
    entry = two.get_entry(0)
    with pytest.raises(LogIndexTaken):
        two.append_entry(entry)


@_pg_required
def test_pg_parallel_registrations_on_two_instances_never_fail():
    """N threads on each of two instances (separate connections, as two Cloud
    Run instances): every registration succeeds, each statement has one leaf,
    and the chain verifies."""
    one, two = _pg_pair()
    attestor = AttestorService()
    services = [AnchorerService(attestor=attestor, store=one), AnchorerService(attestor=attestor, store=two)]
    errors: list[BaseException] = []
    results: list[int] = []
    lock = threading.Lock()

    def worker(svc: AnchorerService, n: int) -> None:
        try:
            # Half the statements are sent to both instances at once.
            r = svc.register_signed_statement_full(_digest(f"pg-par-{n // 2 if n % 2 else n}"))
            with lock:
                results.append(r.leaf_index)
        except BaseException as exc:  # noqa: BLE001
            with lock:
                errors.append(exc)

    threads = [threading.Thread(target=worker, args=(services[i % 2], i)) for i in range(40)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    assert not errors, errors
    assert len(results) == 40
    entries = one.all_entries()
    assert [e.log_index for e in entries] == list(range(len(entries)))
    assert len({e.payload_hash for e in entries}) == len(entries), "a statement landed at two leaves"
    assert services[0].verify_log()


@_pg_required
def test_pg_waiters_are_served_in_order_not_starved():
    """One instance runs short sections back to back; the other still gets
    the lock well before its timeout, because Postgres queues waiters."""
    import time as _time

    one, two = _pg_pair()
    stop = threading.Event()

    def stream():
        while not stop.is_set():
            with one.writer_lock(timeout_s=5.0):
                _time.sleep(0.005)

    t = threading.Thread(target=stream)
    t.start()
    try:
        _time.sleep(0.1)
        start = _time.monotonic()
        with two.writer_lock(timeout_s=3.0):
            waited = _time.monotonic() - start
    finally:
        stop.set()
        t.join(10)
    assert waited < 1.0, waited


@_pg_required
def test_pg_a_failed_unlock_drops_the_session_so_the_lock_is_free():
    one, two = _pg_pair()

    class _UnlockFails:
        def __init__(self, conn):
            self._conn = conn

        def execute(self, sql, *args, **kwargs):
            if "pg_advisory_unlock" in sql:
                raise one._pg.OperationalError("unlock interrupted")  # noqa: SLF001
            return self._conn.execute(sql, *args, **kwargs)

        def __getattr__(self, name):
            return getattr(self._conn, name)

    with one.writer_lock():
        one._conn = _UnlockFails(one._conn)  # noqa: SLF001
    with two.writer_lock(timeout_s=2.0):
        pass


@_pg_required
def test_pg_a_dropped_connection_inside_the_section_refuses_further_writes():
    one, two = _pg_pair()
    svc = AnchorerService(attestor=AttestorService(), store=one)
    svc.register_signed_statement_full(_digest("before-drop"))
    with pytest.raises(WriterBusy):
        with one.writer_lock():
            pid = one._conn.execute("SELECT pg_backend_pid()").fetchone()[0]  # noqa: SLF001
            two._conn.execute("SELECT pg_terminate_backend(%s)", (pid,))  # noqa: SLF001
            entry = one.get_entry(0)  # reconnects: the lock went with the old session
            one.append_entry(entry.model_copy(update={"log_index": 1}))
    assert two.size() == 1
    with two.writer_lock(timeout_s=2.0):
        pass


def _cp(key, log, size, prev_size, issued_at, proof=None):
    from capsule_anchor.anchoring.checkpoint_cose import parse_and_verify_checkpoint_cose
    from capsule_anchor.anchoring.submitters import SubmitterAllowlist

    return parse_and_verify_checkpoint_cose(
        log.checkpoint_cose(key, size=size, prev_size=prev_size, issued_at=issued_at, consistency_proof=proof),
        allowlist=SubmitterAllowlist.from_list([]),
    )


@_pg_required
def test_pg_two_first_keys_for_one_log_on_two_instances_bind_exactly_one():
    from capsule_anchor.anchoring.service import LogKeyMismatchError
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from .test_checkpoint_continuity import _Log

    one, two = _pg_pair()
    attestor = AttestorService()
    services = [AnchorerService(attestor=attestor, store=one), AnchorerService(attestor=attestor, store=two)]
    for round_ in range(5):
        logs = [_Log(f"race-first-{round_}"), _Log(f"race-first-{round_}")]
        sizes = [log.grow_leaves(2 + i) for i, log in enumerate(logs)]
        cps = [_cp(Ed25519PrivateKey.generate(), logs[i], sizes[i], 0, "2026-11-25T00:00:00Z") for i in range(2)]
        outcomes: list[str] = []
        barrier = threading.Barrier(2)

        def submit(i):
            barrier.wait()
            try:
                services[i].witness_checkpoint(cps[i])
                outcomes.append("ok")
            except LogKeyMismatchError:
                outcomes.append("refused")

        threads = [threading.Thread(target=submit, args=(i,)) for i in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(30)
        assert sorted(outcomes) == ["ok", "refused"], outcomes


@_pg_required
def test_pg_two_successors_of_one_tip_on_two_instances_are_never_both_accepted():
    """A fork: two different checkpoints, each with a valid proof that it
    extends the same accepted tip, reach two instances at once. Without one
    writer across instances both pass the continuity check against the tip
    they read and both are co-signed; with it, the second sees the first as
    the tip and is refused."""
    from capsule_anchor.anchoring.service import ContinuityMismatchError
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from .test_checkpoint_continuity import _Log, _proof_claim

    one, two = _pg_pair()
    attestor = AttestorService()
    services = [AnchorerService(attestor=attestor, store=one), AnchorerService(attestor=attestor, store=two)]
    key = Ed25519PrivateKey.generate()
    for round_ in range(5):
        log_id = f"fork-{round_}"
        a, b = _Log(log_id), _Log(log_id)  # same leaves, then they diverge in length
        base = a.grow_leaves(1)
        assert b.grow_leaves(1) == base
        services[0].witness_checkpoint(_cp(key, a, base, 0, "2026-11-25T00:00:00Z"))
        size_a, size_b = a.grow_leaves(1), b.grow_leaves(2)
        cps = [
            _cp(key, a, size_a, base, "2026-11-25T00:01:00Z", _proof_claim(a.proof(base, size_a))),
            _cp(key, b, size_b, base, "2026-11-25T00:01:00Z", _proof_claim(b.proof(base, size_b))),
        ]
        outcomes: list[str] = []
        barrier = threading.Barrier(2)

        def submit(i, cps=cps, outcomes=outcomes, barrier=barrier):
            barrier.wait()
            try:
                services[i].witness_checkpoint(cps[i])
                outcomes.append("ok")
            except ContinuityMismatchError:
                outcomes.append("refused")
            except BaseException as exc:  # noqa: BLE001
                outcomes.append(repr(exc))

        threads = [threading.Thread(target=submit, args=(i,)) for i in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(30)
        assert sorted(outcomes) == ["ok", "refused"], (round_, outcomes)


def test_one_deadline_covers_the_local_queue_and_the_database_lock(monkeypatch):
    import time as _time

    from capsule_anchor.anchoring import service as service_module

    monkeypatch.setattr(service_module, "WRITER_LOCK_TIMEOUT_S", 0.3)
    svc = AnchorerService()
    held = threading.Event()
    release = threading.Event()

    def hold():
        with svc._lock:  # noqa: SLF001 -- a writer of this instance in the middle of its section
            held.set()
            release.wait(5)

    t = threading.Thread(target=hold)
    t.start()
    held.wait(5)
    start = _time.monotonic()
    try:
        with pytest.raises(WriterBusy):
            svc.register_signed_statement_full(_digest("queued"))
    finally:
        release.set()
        t.join(5)
    assert _time.monotonic() - start < 1.0


@_pg_required
def test_pg_a_drop_during_the_insert_is_refused_and_not_replayed():
    one, two = _pg_pair()
    svc = AnchorerService(attestor=AttestorService(), store=one)
    svc.register_signed_statement_full(_digest("before-insert-drop"))

    class _InsertDrops:
        def __init__(self, conn):
            self._conn = conn

        def execute(self, sql, *args, **kwargs):
            if sql.startswith("INSERT INTO log_entries"):
                raise one._pg.OperationalError("server closed the connection")  # noqa: SLF001
            return self._conn.execute(sql, *args, **kwargs)

        def __getattr__(self, name):
            return getattr(self._conn, name)

    real = one._conn  # noqa: SLF001
    one._conn = _InsertDrops(real)  # noqa: SLF001
    reconnect = one._reconnect  # noqa: SLF001

    def reconnect_to_real():
        one._conn = real  # noqa: SLF001
        reconnect()

    one._reconnect = reconnect_to_real  # noqa: SLF001
    with pytest.raises(WriterBusy):
        svc.register_signed_statement_full(_digest("dropped"))
    assert two.size() == 1
    assert two.get_statement(_digest("dropped").hex()) is None
    with two.writer_lock(timeout_s=2.0):
        pass


@_pg_required
def test_pg_a_reconnect_while_taking_the_lock_waits_only_what_is_left():
    """The idle-connection retry shares the first try's budget: while another
    instance holds the lock, a first try that fails after part of the budget
    leaves the retry only the rest."""
    import time as _time

    one, two = _pg_pair()
    real = one._conn  # noqa: SLF001

    class _FirstTryDrops:
        def __init__(self, conn):
            self._conn = conn
            self.dropped = False

        def execute(self, sql, *args, **kwargs):
            if "pg_advisory_lock" in sql and not self.dropped:
                self.dropped = True
                _time.sleep(0.4)
                raise one._pg.OperationalError("server closed the connection")  # noqa: SLF001
            return self._conn.execute(sql, *args, **kwargs)

        def __getattr__(self, name):
            return getattr(self._conn, name)

    one._conn = _FirstTryDrops(real)  # noqa: SLF001
    with two.writer_lock():
        start = _time.monotonic()
        with pytest.raises(WriterBusy):
            with one.writer_lock(timeout_s=0.6):
                pass
        assert _time.monotonic() - start < 0.9


@_pg_required
def test_pg_a_drop_at_the_tip_write_rolls_the_whole_section_back_and_no_fork_is_signed():
    """Instance A's connection drops after its log entry and receipt are
    written but before its checkpoint tip moves. The section is one
    transaction, so all of it rolls back: no leaf, no receipt, the tip
    unchanged. Instance B's different successor of the same tip is then
    accepted, and A's retry is refused: the witness never signs both."""
    from capsule_anchor.anchoring.service import ContinuityMismatchError
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from .test_checkpoint_continuity import _Log, _proof_claim

    one, two = _pg_pair()
    attestor = AttestorService()
    a_svc, b_svc = AnchorerService(attestor=attestor, store=one), AnchorerService(attestor=attestor, store=two)
    key = Ed25519PrivateKey.generate()
    a, b = _Log("drop-tip"), _Log("drop-tip")
    base = a.grow_leaves(1)
    assert b.grow_leaves(1) == base
    a_svc.witness_checkpoint(_cp(key, a, base, 0, "2026-11-25T00:00:00Z"))
    size_a, size_b = a.grow_leaves(1), b.grow_leaves(2)
    cp_a = _cp(key, a, size_a, base, "2026-11-25T00:01:00Z", _proof_claim(a.proof(base, size_a)))
    cp_b = _cp(key, b, size_b, base, "2026-11-25T00:01:00Z", _proof_claim(b.proof(base, size_b)))
    leaves_before = two.size()

    real = one._conn  # noqa: SLF001

    class _TipWriteDrops:
        def __init__(self, conn):
            self._conn = conn

        def execute(self, sql, *args, **kwargs):
            if sql.startswith("INSERT INTO checkpoint_witnesses"):
                self._conn.close()  # the server goes away mid-section
                raise one._pg.OperationalError("server closed the connection")  # noqa: SLF001
            return self._conn.execute(sql, *args, **kwargs)

        def __getattr__(self, name):
            return getattr(self._conn, name)

    one._conn = _TipWriteDrops(real)  # noqa: SLF001
    with pytest.raises(WriterBusy):
        a_svc.witness_checkpoint(cp_a)
    assert two.size() == leaves_before, "the log entry rolled back"
    assert two.get_checkpoint_witness("drop-tip")["mmr_size"] == base
    assert two.get_checkpoint_record("drop-tip", size_a) is None

    b_svc.witness_checkpoint(cp_b)  # the other branch, accepted against the unchanged tip
    with pytest.raises(ContinuityMismatchError):
        a_svc.witness_checkpoint(cp_a)
    # A's cache rolled back with the section: it keeps registering cleanly.
    a_svc.register_signed_statement_full(_digest("after-drop"))
    assert a_svc.verify_log()
    assert [e.log_index for e in two.all_entries()] == list(range(two.size()))


def test_cached_tree_truncate_forgets_rolled_back_leaves():
    tree = CachedTree()
    leaves = [_leaf(n) for n in range(700)]
    for h in leaves[:600]:
        tree.append(h)
    tree.root(600)
    tree.truncate(300)
    assert tree.size == 300
    for h in leaves[300:700]:
        tree.append(h)
    assert tree.root(700) == ct.merkle_tree_hash(leaves)
    assert tree.root(512) == ct.merkle_tree_hash(leaves[:512])
