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

_PG_URL = os.environ.get("CAPSULE_ANCHOR_DATABASE_URL")
_pg_required = pytest.mark.skipif(not _PG_URL, reason="CAPSULE_ANCHOR_DATABASE_URL not set")


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
