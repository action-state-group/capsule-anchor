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
from capsule_anchor.anchoring.service import CONTINUITY_GRADE_WITNESSED, AnchorerService, ct_leaf_hash
from capsule_anchor.anchoring.store import (
    InMemoryLogStore,
    LogIndexTaken,
    SqliteLogStore,
    WriterBusy,
)
from capsule_anchor.attestation.service import AttestorService

from .pg_isolation import TEST_DATABASE_URL


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


def test_cached_consistency_proof_equals_full_consistency_proof():
    tree = CachedTree()
    leaves = [_leaf(n) for n in range(600)]
    for h in leaves:
        tree.append(h)
    pairs = [(m, n) for n in range(1, 131) for m in range(1, n + 1)]
    rng = random.Random(132)
    big = [1, 2, 255, 256, 257, 300, 511, 512, 513, 599, 600]
    pairs += [(m, n) for n in big for m in big if m <= n]
    pairs += [tuple(sorted(rng.sample(range(1, 601), 2))) for _ in range(300)]
    for m, n in pairs:
        expected = ct.consistency_proof(m, n, leaves)
        assert tree.consistency_proof(m, n) == expected, (m, n)
        assert ct.verify_consistency_proof(m, n, tree.root(m), tree.root(n), expected), (m, n)


def test_cached_consistency_proof_refuses_sizes_out_of_range():
    tree = CachedTree()
    for n in range(5):
        tree.append(_leaf(n))
    for m, n in [(0, 3), (4, 3), (1, 6), (-1, 2)]:
        with pytest.raises(ValueError):
            tree.consistency_proof(m, n)


def test_service_consistency_proof_matches_the_full_computation_on_a_grown_log():
    svc = AnchorerService(attestor=AttestorService())
    for n in range(MEMO_MIN + 40):
        svc.register_signed_statement_full(_digest(f"proof-{n}"))
    leaves = svc._ct_leaves()  # noqa: SLF001
    size = len(leaves)
    for m in (0, 1, 7, MEMO_MIN - 1, MEMO_MIN, MEMO_MIN + 1, size - 1, size):
        proof = svc.consistency_proof(m, size)
        assert proof.first_root == ct.merkle_tree_hash(leaves[:m])
        assert proof.second_root == ct.merkle_tree_hash(leaves)
        expected = [] if m in (0, size) else ct.consistency_proof(m, size, leaves)
        assert proof.proof == expected, m
        assert svc.verify_consistency(proof), m
    with pytest.raises(ValueError):
        svc.consistency_proof(2, size + 1)


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
        self.largest_page = 0

    def entries_after(self, after_index, limit=None):
        self.read_from.append(after_index)
        page = super().entries_after(after_index, limit)
        self.largest_page = max(self.largest_page, len(page))
        return page

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

# These run only with CAPSULE_ANCHOR_TEST_DATABASE_URL set, each in an empty
# schema of its own there (see conftest.py), never against the application's
# CAPSULE_ANCHOR_DATABASE_URL.
_pg_required = pytest.mark.skipif(
    TEST_DATABASE_URL is None, reason="CAPSULE_ANCHOR_TEST_DATABASE_URL not set"
)


def _pg_pair():
    """Two stores, as two instances of the witness, over this test's schema."""
    from capsule_anchor.anchoring.store import PostgresLogStore

    url = os.environ["CAPSULE_ANCHOR_DATABASE_URL"]
    return PostgresLogStore(url), PostgresLogStore(url)


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


@_pg_required
def test_pg_a_retry_on_another_instance_never_gets_a_receipt_before_the_tip_moves():
    """capsule-anchor#120: instance A has stored checkpoint N's statement but
    not yet moved its tip (held here at the tree head, the step that was slow
    at v0.1.4). The client's retry of N reaches instance B, then N+1 (prev N)
    follows on B. B must not answer N's receipt until A's tip commits;
    otherwise N+1 is checked against the tip before N and refused with 409,
    as the hosted witness did to checkpoint 38 after 35's receipt."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from .test_checkpoint_continuity import _Log, _proof_claim

    one, two = _pg_pair()
    attestor = AttestorService()
    a_svc, b_svc = AnchorerService(attestor=attestor, store=one), AnchorerService(attestor=attestor, store=two)
    key = Ed25519PrivateKey.generate()
    log = _Log("retry-tip")
    s1 = log.grow_leaves(2)
    a_svc.witness_checkpoint(_cp(key, log, s1, 0, "2026-11-26T07:48:00Z"))
    s2 = log.grow_leaves(2)
    cp_n = _cp(key, log, s2, s1, "2026-11-26T07:49:00Z", _proof_claim(log.proof(s1, s2)))
    s3 = log.grow_leaves(2)
    cp_next = _cp(key, log, s3, s2, "2026-11-26T07:50:00Z", _proof_claim(log.proof(s2, s3)))

    reached, release = threading.Event(), threading.Event()
    sign_sth = a_svc._sign_and_persist_sth  # noqa: SLF001

    def held_sth():
        reached.set()
        release.wait(10)
        return sign_sth()

    a_svc._sign_and_persist_sth = held_sth  # noqa: SLF001
    out: dict = {}

    def first_attempt():
        out["a"] = a_svc.witness_checkpoint(cp_n)

    def retry_then_next():
        try:
            out["retry"] = b_svc.witness_checkpoint(cp_n)
            out["next"] = b_svc.witness_checkpoint(cp_next)
        except BaseException as exc:  # noqa: BLE001
            out["error"] = exc

    ta = threading.Thread(target=first_attempt)
    ta.start()
    tb = None
    try:
        assert reached.wait(10), "A never reached the tree head"
        tb = threading.Thread(target=retry_then_next)
        tb.start()
        tb.join(1.0)
        assert tb.is_alive(), f"B answered while A's tip was uncommitted: {out.get('error')!r}"
    finally:
        release.set()
        ta.join(30)
        if tb is not None:
            tb.join(30)
    assert "error" not in out, out["error"]
    assert out["retry"].receipt == out["a"].receipt  # one statement, one receipt
    assert out["next"].continuity_grade == CONTINUITY_GRADE_WITNESSED
    assert two.get_checkpoint_witness("retry-tip")["mmr_size"] == s3


def _chain(key, log_id):
    """A first checkpoint and two verified extensions, each one's prev the one before."""
    from .test_checkpoint_continuity import _Log, _proof_claim

    log = _Log(log_id)
    sizes = [log.grow_leaves(2) for _ in range(3)]
    cps = [_cp(key, log, sizes[0], 0, "2026-11-26T07:48:00Z")]
    for prev, size, ts in ((sizes[0], sizes[1], "07:49"), (sizes[1], sizes[2], "07:50")):
        cps.append(_cp(key, log, size, prev, f"2026-11-26T{ts}:00Z", _proof_claim(log.proof(prev, size))))
    return cps


def _continuity_assertion(receipt: bytes) -> dict | None:
    import cbor2
    from capsule_anchor.anchoring.service import _COSE_CONTINUITY_LABEL

    protected = cbor2.loads(cbor2.loads(receipt).value[0])
    return protected.get(_COSE_CONTINUITY_LABEL)


def _digest_hex(cp) -> str:
    from capsule_anchor.anchoring.service import _checkpoint_digest

    return _checkpoint_digest(cp)


def _store_service(tmp_path, db):
    if db == "memory":
        return AnchorerService()
    if db == "sqlite":
        return AnchorerService(db_path=str(tmp_path / "w.db"))
    return AnchorerService(store=_pg_pair()[0])


_EVERY_STORE = ["memory", "sqlite", pytest.param("postgres", marks=_pg_required)]


@pytest.mark.parametrize("db", _EVERY_STORE)
def test_a_receipt_stored_before_its_tip_failed_is_completed_by_the_retry(tmp_path, db):
    """capsule-anchor#120: checkpoint N's acceptance stores its receipt, then
    fails before its tip moves (these stores, like v0.1.4's Postgres store,
    commit each write on its own). The retry of N finds the receipt; it must
    also move the tip, or N+1 is refused although N's receipt was issued."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    svc = _store_service(tmp_path, db)
    first, n, n1 = _chain(Ed25519PrivateKey.generate(), "partial-tip")
    svc.witness_checkpoint(first)
    sign_sth = svc._sign_and_persist_sth  # noqa: SLF001

    def fails():
        raise RuntimeError("the tree head write failed")

    svc._sign_and_persist_sth = fails  # noqa: SLF001
    with pytest.raises(RuntimeError):
        svc.witness_checkpoint(n)
    svc._sign_and_persist_sth = sign_sth  # noqa: SLF001
    assert svc._store.get_checkpoint_witness("partial-tip")["mmr_size"] == first["mmr_size"]  # noqa: SLF001

    retry = svc.witness_checkpoint(n)
    assert retry.continuity_grade == CONTINUITY_GRADE_WITNESSED
    assert svc._store.get_checkpoint_witness("partial-tip")["mmr_size"] == n["mmr_size"]  # noqa: SLF001
    assert svc.witness_checkpoint(n1).continuity_grade == CONTINUITY_GRADE_WITNESSED
    # The older checkpoint resubmitted now keeps its receipt and moves nothing.
    assert svc.witness_checkpoint(n).receipt == retry.receipt
    assert svc._store.get_checkpoint_witness("partial-tip")["mmr_size"] == n1["mmr_size"]  # noqa: SLF001


def test_a_checkpoint_preregistered_on_register_moves_the_tip_when_posted():
    """N's digest was registered as a plain statement first. Posting N on
    /checkpoints answers that receipt; it must also move the tip to N, so N+1
    is not refused. The plain receipt carries no continuity assertion, so the
    answer claims no witnessed grade."""
    from capsule_anchor.anchoring.service import _checkpoint_digest
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    svc = AnchorerService()
    first, n, n1 = _chain(Ed25519PrivateKey.generate(), "prereg-tip")
    svc.witness_checkpoint(first)
    plain = svc.register_signed_statement_full(bytes.fromhex(_checkpoint_digest(n)))
    posted = svc.witness_checkpoint(n)
    assert (posted.receipt, posted.leaf_index) == (plain.receipt, plain.leaf_index)
    assert _continuity_assertion(posted.receipt) is None
    assert posted.continuity_grade is None  # never "witnessed" without the signed assertion
    assert svc._store.get_checkpoint_witness("prereg-tip")["mmr_size"] == n["mmr_size"]  # noqa: SLF001
    assert svc.witness_checkpoint(n1).continuity_grade == CONTINUITY_GRADE_WITNESSED


@pytest.mark.parametrize("db", _EVERY_STORE)
def test_a_record_left_without_a_grade_does_not_keep_the_tip_behind(tmp_path, db):
    """Before #120 a retry could record N with no grade while the first
    acceptance, which had stored N's receipt, then failed before its tip.
    The next retry moves the tip and answers the stored receipt with the
    grade it proves."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    svc = _store_service(tmp_path, db)
    first, n, n1 = _chain(Ed25519PrivateKey.generate(), "ungraded")
    svc.witness_checkpoint(first)
    sign_sth = svc._sign_and_persist_sth  # noqa: SLF001

    def fails():
        raise RuntimeError("the tree head write failed")

    svc._sign_and_persist_sth = fails  # noqa: SLF001
    with pytest.raises(RuntimeError):
        svc.witness_checkpoint(n)
    svc._sign_and_persist_sth = sign_sth  # noqa: SLF001
    if db == "postgres":
        return  # one transaction: the failed acceptance left nothing to complete
    stored = svc.register_signed_statement_full(bytes.fromhex(_digest_hex(n)))  # the cached receipt
    receipt = stored.receipt
    svc._record_checkpoint_read_surface(n, stored)  # noqa: SLF001 -- the old retry's record, grade None
    retry = svc.witness_checkpoint(n)
    assert retry.receipt == receipt
    assert retry.continuity_grade == CONTINUITY_GRADE_WITNESSED  # the stored receipt carries the assertion
    assert svc._store.get_checkpoint_witness("ungraded")["mmr_size"] == n["mmr_size"]  # noqa: SLF001
    assert svc.witness_checkpoint(n1).continuity_grade == CONTINUITY_GRADE_WITNESSED


def test_a_preregistered_checkpoint_that_does_not_extend_the_tip_is_refused():
    """Completing a cached checkpoint runs the same continuity check as a new
    one: a digest registered on /register moves no tip it would be refused
    as a new submission."""
    from capsule_anchor.anchoring.service import ContinuityMismatchError, _checkpoint_digest
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    svc = AnchorerService()
    first, _n, n1 = _chain(Ed25519PrivateKey.generate(), "prereg-gap")
    svc.witness_checkpoint(first)
    svc.register_signed_statement_full(bytes.fromhex(_checkpoint_digest(n1)))
    with pytest.raises(ContinuityMismatchError):
        svc.witness_checkpoint(n1)  # its prev is N, which this witness never accepted
    assert svc._store.get_checkpoint_witness("prereg-gap")["mmr_size"] == first["mmr_size"]  # noqa: SLF001


@pytest.mark.parametrize("db", _EVERY_STORE)
def test_a_second_signing_of_one_position_moves_the_tip_with_its_own_receipt(tmp_path, db):
    """N signed twice (same size and root, another issued_at) is two signing
    acts with two receipts. A's record, left with no grade, neither lends B
    its grade nor keeps B's retry from moving the tip, so B's successor is
    not refused. A's retry, now behind the tip, keeps its own receipt."""
    from capsule_anchor.anchoring.service import _checkpoint_digest
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from .test_checkpoint_continuity import _Log, _proof_claim

    svc = _store_service(tmp_path, db)
    key = Ed25519PrivateKey.generate()
    log = _Log("two-signings")
    s1, s2 = log.grow_leaves(2), log.grow_leaves(2)
    first = _cp(key, log, s1, 0, "2026-11-26T07:48:00Z")
    proof = _proof_claim(log.proof(s1, s2))
    n_a = _cp(key, log, s2, s1, "2026-11-26T07:49:00Z", proof)
    n_b = _cp(key, log, s2, s1, "2026-11-26T07:49:30Z", proof)
    s3 = log.grow_leaves(2)
    after_b = _cp(key, log, s3, s2, "2026-11-26T07:50:00Z", _proof_claim(log.proof(s2, s3)))
    assert _checkpoint_digest(n_a) != _checkpoint_digest(n_b)
    svc.witness_checkpoint(first)
    plain_a = svc.register_signed_statement_full(bytes.fromhex(_checkpoint_digest(n_a)))
    plain_b = svc.register_signed_statement_full(bytes.fromhex(_checkpoint_digest(n_b)))
    svc._record_checkpoint_read_surface(n_a, plain_a)  # noqa: SLF001 -- A's record, left with no grade

    got_b = svc.witness_checkpoint(n_b)
    assert (got_b.receipt, got_b.continuity_grade) == (plain_b.receipt, None)
    assert svc._store.get_checkpoint_witness("two-signings")["mmr_size"] == s2  # noqa: SLF001
    assert svc.witness_checkpoint(after_b).continuity_grade == CONTINUITY_GRADE_WITNESSED
    got_a = svc.witness_checkpoint(n_a)
    assert (got_a.receipt, got_a.continuity_grade) == (plain_a.receipt, None)


@pytest.mark.parametrize("db", _EVERY_STORE)
def test_another_signings_registered_record_does_not_hold_the_tip_back(tmp_path, db):
    """A proof-less signing A of N is recorded "registered" and leaves the tip
    at L. Signing B of N, its digest pre-registered, then posted with a
    proof: A's grade is not B's, so B is checked and moves the tip, and B's
    successor is accepted."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from .test_checkpoint_continuity import _Log, _proof_claim

    svc = _store_service(tmp_path, db)
    key = Ed25519PrivateKey.generate()
    log = _Log("registered-other")
    s1, s2 = log.grow_leaves(2), log.grow_leaves(2)
    svc.witness_checkpoint(_cp(key, log, s1, 0, "2026-11-26T07:48:00Z"))
    n_a = _cp(key, log, s2, s1, "2026-11-26T07:49:00Z")  # no proof
    n_b = _cp(key, log, s2, s1, "2026-11-26T07:49:30Z", _proof_claim(log.proof(s1, s2)))
    s3 = log.grow_leaves(2)
    after_b = _cp(key, log, s3, s2, "2026-11-26T07:50:00Z", _proof_claim(log.proof(s2, s3)))
    assert svc.witness_checkpoint(n_a).continuity_grade == "registered"
    svc.register_signed_statement_full(bytes.fromhex(_digest_hex(n_b)))
    got_b = svc.witness_checkpoint(n_b)
    assert got_b.continuity_grade is None  # its plain receipt proves no continuity
    assert svc._store.get_checkpoint_witness("registered-other")["mmr_size"] == s2  # noqa: SLF001
    assert svc.witness_checkpoint(after_b).continuity_grade == CONTINUITY_GRADE_WITNESSED


@_pg_required
def test_pg_a_retry_before_the_first_writers_record_keeps_the_witnessed_grade():
    """The read-surface record commits with the receipt and tip. A retry on
    another instance while the first is about to write its record waits for
    it, and both read back continuity-witnessed (before #120 the retry could
    store its own grade, None, first, and keep it)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    one, two = _pg_pair()
    attestor = AttestorService()
    a_svc, b_svc = AnchorerService(attestor=attestor, store=one), AnchorerService(attestor=attestor, store=two)
    first, n, _n1 = _chain(Ed25519PrivateKey.generate(), "record-race")
    a_svc.witness_checkpoint(first)
    reached, release = threading.Event(), threading.Event()
    record = a_svc._record_checkpoint_read_surface  # noqa: SLF001

    def held_record(cp, result):
        reached.set()
        release.wait(10)
        return record(cp, result)

    a_svc._record_checkpoint_read_surface = held_record  # noqa: SLF001
    out: dict = {}
    ta = threading.Thread(target=lambda: out.setdefault("a", a_svc.witness_checkpoint(n)))
    tb = threading.Thread(target=lambda: out.setdefault("b", b_svc.witness_checkpoint(n)))
    ta.start()
    try:
        assert reached.wait(10), "A never reached its record"
        tb.start()
        tb.join(1.0)
        assert tb.is_alive(), "B answered before A's record committed"
    finally:
        release.set()
        ta.join(30)
        if tb.ident is not None:
            tb.join(30)
    assert out["a"].continuity_grade == out["b"].continuity_grade == CONTINUITY_GRADE_WITNESSED
    assert b_svc.get_checkpoint_readback("record-race")["continuity_grade"] == CONTINUITY_GRADE_WITNESSED


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


# --- the sync reads the log in pages (capsule-anchor#132) ---------------------


def _grow_mixed_log(svc: AnchorerService, n: int) -> None:
    """Statements and countersigned roots: both leaf forms (ct_leaf_payload)."""
    for i in range(n):
        if i % 3 == 0:
            svc.anchor("tenant", hashlib.sha256(f"root-{i}".encode()).hexdigest(), (i, i))
        else:
            svc.register_signed_statement_full(_digest(f"page-{i}"))


def _assert_paged_sync_matches_full_read(make_store, monkeypatch, total: int = 23) -> None:
    from capsule_anchor.anchoring import service as service_module

    attestor = AttestorService()
    _grow_mixed_log(AnchorerService(attestor=attestor, store=make_store()), total)
    for page in (1, 4, 5, total - 1, total, total + 1):
        monkeypatch.setattr(service_module, "SYNC_PAGE_ROWS", page)
        full = [ct_leaf_hash(e) for e in make_store().all_entries()]
        fresh = AnchorerService(attestor=attestor, store=make_store())
        assert fresh.log_size() == len(full), page
        assert fresh._tree.leaves_hex(len(full)) == full, page  # noqa: SLF001
        assert fresh._last_entry == make_store().get_entry(len(full) - 1), page  # noqa: SLF001
        # The next append chains to the last entry the pages ended on.
        fresh.register_signed_statement_full(_digest(f"after-pages-{page}"))
        assert fresh.verify_log(), page


def test_paged_sync_builds_the_same_tree_in_memory(monkeypatch):
    store = InMemoryLogStore()
    _assert_paged_sync_matches_full_read(lambda: store, monkeypatch)


def test_paged_sync_builds_the_same_tree_on_sqlite(tmp_path, monkeypatch):
    path = str(tmp_path / "log.db")
    _assert_paged_sync_matches_full_read(lambda: SqliteLogStore(path), monkeypatch)


@_pg_required
def test_pg_paged_sync_builds_the_same_tree(monkeypatch):
    from capsule_anchor.anchoring.store import PostgresLogStore

    url = os.environ["CAPSULE_ANCHOR_DATABASE_URL"]
    _assert_paged_sync_matches_full_read(lambda: PostgresLogStore(url), monkeypatch)


def test_a_first_sync_holds_one_page_of_entries_not_the_log(monkeypatch):
    from capsule_anchor.anchoring import service as service_module

    monkeypatch.setattr(service_module, "SYNC_PAGE_ROWS", 7)
    store = _CountingStore()
    _grow_mixed_log(AnchorerService(store=store), 40)
    store.largest_page = 0
    store.read_from.clear()
    assert AnchorerService(store=store).log_size() == 40
    assert store.largest_page == 7
    assert store.read_from == [0, 7, 14, 21, 28, 35]
    assert store.full_reads == 0


class _Page(list):
    """A page that can be weakly referenced, to see when the sync lets go of it."""


class _PageWatchingStore(InMemoryLogStore):
    def __init__(self) -> None:
        super().__init__()
        self.previous = None
        self.overlaps = 0
        self.pages = 0

    def entries_after(self, after_index, limit=None):
        import weakref

        if self.previous is not None and self.previous() is not None:
            self.overlaps += 1  # the caller still holds the last page
        page = _Page(super().entries_after(after_index, limit))
        self.previous = weakref.ref(page)
        self.pages += 1
        return page


def test_a_sync_lets_go_of_each_page_before_reading_the_next(monkeypatch):
    from capsule_anchor.anchoring import service as service_module

    monkeypatch.setattr(service_module, "SYNC_PAGE_ROWS", 5)
    store = _PageWatchingStore()
    _grow_mixed_log(AnchorerService(store=store), 23)
    store.previous, store.overlaps, store.pages = None, 0, 0
    assert AnchorerService(store=store).log_size() == 23
    assert store.pages == 5
    assert store.overlaps == 0


def test_entries_after_honors_the_limit_on_every_store(tmp_path):
    stores = [InMemoryLogStore(), SqliteLogStore(str(tmp_path / "limit.db"))]
    if TEST_DATABASE_URL is not None:
        from capsule_anchor.anchoring.store import PostgresLogStore

        stores.append(PostgresLogStore(os.environ["CAPSULE_ANCHOR_DATABASE_URL"]))
    for store in stores:
        svc = AnchorerService(store=store)
        for i in range(6):
            svc.register_signed_statement_full(_digest(f"limit-{type(store).__name__}-{i}"))
        assert [e.log_index for e in store.entries_after(2, limit=3)] == [2, 3, 4]
        assert [e.log_index for e in store.entries_after(4, limit=10)] == [4, 5]
        assert [e.log_index for e in store.entries_after(1)] == [1, 2, 3, 4, 5]
        assert store.entries_after(6, limit=3) == []
