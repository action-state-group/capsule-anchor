"""Profile witness registrations on a local Postgres seeded to N log entries.

capsule-anchor#132; the results are in docs/architecture/20-witness-scaling.md.

    python scripts/bench_witness.py seed <db_url> <N>
    psql <db_url> -c ANALYZE          # as autovacuum would in production
    python scripts/bench_witness.py run  <db_url> <label>

Use an empty throwaway database. The URL must name a local host, so this never
writes to a real witness. ``run`` prints one JSON object: the cold start (the
whole-log read a new instance does), 50 warm registrations broken down by step,
the read endpoints, the same reads behind four writer threads, and cProfile
summaries of registrations and of one consistency proof.
"""

from __future__ import annotations

import cProfile
import hashlib
import io
import json
import pstats
import resource
import statistics
import sys
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime

import psycopg
from psycopg.conninfo import conninfo_to_dict

from capsule_anchor.anchoring import service as service_module
from capsule_anchor.anchoring.service import _LOG_KIND_SCITT, AnchorerService, tree_head_payload
from capsule_anchor.anchoring.store import PostgresLogStore, _sig_to_json
from capsule_anchor.attestation.service import AttestorService


def _local_only(url: str) -> None:
    host = conninfo_to_dict(url).get("host", "")
    if host not in ("localhost", "127.0.0.1", "::1"):
        raise SystemExit(f"refusing a non-local database host {host!r}")


def _peak_rss_mib() -> float:
    # ru_maxrss is bytes on macOS and KiB on Linux.
    scale = 1 if sys.platform == "darwin" else 1024
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * scale / 2**20


def seed(url: str, n: int) -> None:
    """Write a valid hash-chained log of ``n`` entries and one stored
    receipt per entry, as the service writes them, with COPY."""
    PostgresLogStore(url).close()  # creates the schema
    attestor = AttestorService()
    crypto = attestor.crypto
    started = time.monotonic()
    now = datetime.now(UTC)
    prev: str | None = None
    hashes: list[str] = []
    with psycopg.connect(url) as conn, conn.cursor() as cur:
        with cur.copy(
            "COPY log_entries (log_index, logged_at, kind, payload_hash, log_signature, prev_log_hash) FROM STDIN"
        ) as copy:
            for i in range(n):
                payload_hash = crypto.sha256(hashlib.sha256(f"seed-{i}".encode()).digest())
                head = tree_head_payload(i, payload_hash, prev)
                copy.write_row((i, now, _LOG_KIND_SCITT, payload_hash, _sig_to_json(attestor.attest(head)), prev))
                hashes.append(payload_hash)
                prev = crypto.sha256(head)
        with cur.copy("COPY submitted_statements (entry_hash, receipt, leaf_index, tree_size) FROM STDIN") as copy:
            for i, payload_hash in enumerate(hashes):
                copy.write_row((payload_hash, b"\xa0" * 600, i, i + 1))
        conn.commit()
    print(f"seeded {n} entries in {time.monotonic() - started:.1f}s")


class _StepTimer:
    """Accumulates wall time per wrapped callable."""

    def __init__(self) -> None:
        self.totals: dict[str, float] = {}

    def wrap(self, obj: object, name: str) -> None:
        fn = getattr(obj, name)

        def timed(*args, **kwargs):
            t = time.perf_counter()
            try:
                return fn(*args, **kwargs)
            finally:
                self.totals[name] = self.totals.get(name, 0.0) + time.perf_counter() - t

        setattr(obj, name, timed)


def _pct(xs: list[float], p: float) -> float:
    xs = sorted(xs)
    return xs[min(len(xs) - 1, round(p / 100 * (len(xs) - 1)))]


def _median_ms(fn: Callable[[], object], reps: int = 5) -> float:
    times = []
    for _ in range(reps):
        t = time.perf_counter()
        fn()
        times.append(time.perf_counter() - t)
    return statistics.median(times) * 1e3


def _digest(label: str) -> bytes:
    return hashlib.sha256(f"{label}-{time.time_ns()}".encode()).digest()


def _profile(fn: Callable[[], object], sort: str, lines: int) -> list[str]:
    prof = cProfile.Profile()
    prof.enable()
    fn()
    prof.disable()
    buf = io.StringIO()
    pstats.Stats(prof, stream=buf).sort_stats(sort).print_stats(lines)
    return buf.getvalue().splitlines()[-(lines + 8):]


def run(url: str, label: str) -> None:
    out: dict = {"label": label}
    attestor = AttestorService()

    # 1. Cold start: a new instance's first sync reads the whole log.
    rss_before = _peak_rss_mib()
    store = PostgresLogStore(url)
    svc = AnchorerService(attestor=attestor, store=store)
    timer = _StepTimer()
    timer.wrap(store, "entries_after")
    t = time.perf_counter()
    out["tree_size"] = svc.log_size()
    out["cold_first_sync_s"] = time.perf_counter() - t
    out["cold_entries_after_s"] = timer.totals.get("entries_after", 0.0)
    out["cold_peak_rss_mib"] = {"before": rss_before, "after": _peak_rss_mib()}
    # The first root after the sync hashes every leaf once (the subtree memo
    # starts empty); later roots reuse it.
    t = time.perf_counter()
    svc.ct_root()
    out["cold_first_root_s"] = time.perf_counter() - t

    # 2. Warm registrations, broken down by step.
    timer = _StepTimer()
    for name in ("entries_after", "append_entry", "get_statement", "put_statement", "put_sth"):
        timer.wrap(store, name)
    timer.wrap(attestor, "attest")
    timer.wrap(svc._tree, "audit_path")  # noqa: SLF001
    timer.wrap(svc._tree, "root")  # noqa: SLF001
    timer.wrap(service_module, "build_cose_receipt")
    latencies, steps = [], []
    for _ in range(50):
        timer.totals.clear()
        t = time.perf_counter()
        svc.register_signed_statement_full(_digest(f"{label}-reg"))
        latencies.append(time.perf_counter() - t)
        steps.append(dict(timer.totals))
    out["registration_ms"] = {
        "p50": _pct(latencies, 50) * 1e3,
        "p95": _pct(latencies, 95) * 1e3,
        "max": max(latencies) * 1e3,
    }
    names = sorted({k for s in steps for k in s})
    out["registration_step_ms_median"] = {k: statistics.median(s.get(k, 0.0) for s in steps) * 1e3 for k in names}

    # 3. Reads.
    n = svc.log_size()
    out["consistency_proof_ms"] = {
        "1000_to_tip": _median_ms(lambda: svc.consistency_proof(1000, n)),
        "tip-10_to_tip": _median_ms(lambda: svc.consistency_proof(n - 10, n)),
    }
    out["inclusion_proof_ct_ms"] = _median_ms(lambda: svc.inclusion_proof_ct(n // 2))
    out["get_sth_ms"] = _median_ms(svc.get_sth)

    # 4. The same reads while four threads register on this instance.
    stop = threading.Event()
    writer_errors: list[BaseException] = []

    def writer() -> None:
        try:
            while not stop.is_set():
                svc.register_signed_statement_full(_digest(f"{label}-writer"))
        except BaseException as exc:  # noqa: BLE001 - reported below, never a silent measurement
            writer_errors.append(exc)
            stop.set()

    writers = [threading.Thread(target=writer) for _ in range(4)]
    for w in writers:
        w.start()
    sth_times, proof_times = [], []
    try:
        for _ in range(30):
            t = time.perf_counter()
            svc.get_sth()
            sth_times.append(time.perf_counter() - t)
        for _ in range(5):
            t = time.perf_counter()
            svc.consistency_proof(1000, svc.log_size())
            proof_times.append(time.perf_counter() - t)
    finally:
        stop.set()
        for w in writers:
            w.join()
    if writer_errors:
        # A writer that failed (WriterBusy, say) would leave fewer than four
        # writing: the "under 4 writers" figures would not mean that.
        raise RuntimeError(f"{len(writer_errors)} writer thread(s) failed") from writer_errors[0]
    out["under_4_writers_get_sth_ms"] = {"p50": _pct(sth_times, 50) * 1e3, "max": max(sth_times) * 1e3}
    out["under_4_writers_consistency_proof_ms"] = {"p50": _pct(proof_times, 50) * 1e3, "max": max(proof_times) * 1e3}

    # 5. cProfile summaries.
    def twenty_registrations() -> None:
        for _ in range(20):
            svc.register_signed_statement_full(_digest(f"{label}-profile"))

    out["cprofile_registrations"] = _profile(twenty_registrations, "cumulative", 25)
    out["cprofile_consistency_proof"] = _profile(lambda: svc.consistency_proof(1000, svc.log_size()), "tottime", 8)
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    if len(sys.argv) != 4 or sys.argv[1] not in ("seed", "run"):
        raise SystemExit(__doc__)
    _local_only(sys.argv[2])
    if sys.argv[1] == "seed":
        seed(sys.argv[2], int(sys.argv[3]))
    else:
        run(sys.argv[2], sys.argv[3])
