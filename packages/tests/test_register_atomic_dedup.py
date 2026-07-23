"""Registering the same statement concurrently must land at exactly ONE leaf.

Regression test for the double-append race. The dedup check used to sit OUTSIDE
the append lock, so two concurrent submissions of the same NEW statement both
saw "not present" and both appended — putting one statement at two CT leaves
(observed live: a capsule reached the anchor via two near-simultaneous POSTs
and occupied leaves 180 AND 181). Registration must be exactly-once per
entry_hash under concurrency.

The race window in production is the I/O gap between the dedup SELECT and the
append. We reproduce it deterministically with a store that makes the first
caller wait until a second caller has also completed its dedup check:

* buggy (check OUTSIDE the lock): both callers check "absent", both append -> 2 leaves.
* fixed (check INSIDE the lock): the first caller holds the lock across
  check->append, so the second caller cannot check until the first has appended;
  it then sees the cached row and does NOT append -> 1 leaf. (The first caller's
  wait-for-second simply times out, harmlessly, because the second is blocked on
  the lock.)
"""
import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor

from capsule_anchor.anchoring.service import AnchorerService
from capsule_anchor.anchoring.store import InMemoryLogStore


class _CoordStore(InMemoryLogStore):
    """Forces the two dedup checks to interleave the way the network does."""

    def __init__(self) -> None:
        super().__init__()
        self._calls = 0
        self._call_lock = threading.Lock()
        self._second_checked = threading.Semaphore(0)

    def get_statement(self, entry_hash: str):
        with self._call_lock:
            self._calls += 1
            n = self._calls
        result = super().get_statement(entry_hash)
        if n == 1:
            # First caller pauses here until a second caller also reaches the
            # dedup check. If the code holds the append lock across this check
            # (the fix), the second caller is blocked on that lock and never
            # arrives, so we time out and proceed — correctly, exactly once.
            self._second_checked.acquire(timeout=1.5)
        else:
            self._second_checked.release()
        return result


def _leaf_count(svc: AnchorerService, entry_hash: str) -> int:
    leaves = svc._ct_leaves()  # noqa: SLF001 — white-box regression assertion
    target = hashlib.sha256(b"\x00" + bytes.fromhex(entry_hash)).hexdigest()
    return sum(1 for h in leaves if h == target)


def test_two_concurrent_submissions_register_once():
    svc = AnchorerService(store=_CoordStore())  # in-memory, ephemeral key
    statement = b"boundary-seal atomic dedup regression statement"
    entry_hash = hashlib.sha256(statement).hexdigest()

    with ThreadPoolExecutor(max_workers=2) as pool:
        f1 = pool.submit(svc.register_signed_statement, statement)
        f2 = pool.submit(svc.register_signed_statement, statement)
        r1, r2 = f1.result(), f2.result()

    # Both callers get the SAME leaf_index, and the log holds exactly one leaf.
    assert r1[2] == r2[2], f"different leaf_index -> double append: {r1[2]} vs {r2[2]}"
    assert _leaf_count(svc, entry_hash) == 1
    assert r1[1] == r2[1] == entry_hash


def test_distinct_statements_get_distinct_leaves():
    svc = AnchorerService()
    r1 = svc.register_signed_statement(b"alpha")
    r2 = svc.register_signed_statement(b"beta")
    assert r1[2] != r2[2]
    assert r2[3] > r1[3]  # tree_size grows


def test_repeat_after_completion_is_idempotent():
    svc = AnchorerService()
    a = svc.register_signed_statement(b"gamma")
    b = svc.register_signed_statement(b"gamma")
    assert a[1:] == b[1:]  # same entry_hash, leaf_index, tree_size
