"""NANDA Anchor Load Harness — internal capacity test script.

Measures capsule anchor throughput (capsules/second) and HTTP latency
(p50/p95/p99) at configurable concurrency levels against a staging anchor.

NEVER run against anchor.agentactioncapsule.org with --concurrency > 5.
Use only against a local or staging instance (CAPSULE_ANCHOR_RATE_LIMIT raised).

Usage:
    # 1. Start the staging anchor (in another terminal):
    #    CAPSULE_ANCHOR_RATE_LIMIT=100000 capsule-anchor
    #    (or: python -m capsule_anchor.app)

    # 2. Run the harness:
    python load_harness.py --url http://localhost:8000/v1/digest \\
        --concurrency 50 --duration 30

    # Run a sweep (all levels):
    python load_harness.py --url http://localhost:8000/v1/digest --sweep

All output is to stdout + a JSON results file. Numbers are INTERNAL.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import statistics
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DEFAULT_URL = "http://localhost:8000/v1/digest"
DEFAULT_CONCURRENCY = 50
DEFAULT_DURATION = 30  # seconds


# ---------------------------------------------------------------------------
# HTTP worker
# ---------------------------------------------------------------------------

def _post_digest(endpoint: str, capsule_id: str, timeout: float = 10.0) -> tuple[bool, int, float]:
    """Synchronous HTTP POST to the anchor digest endpoint.

    Returns (success, http_status, latency_ms).
    """
    body = json.dumps({"capsule_id": capsule_id}, separators=(",", ":")).encode()
    req = urllib.request.Request(
        endpoint,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp.read()
            return True, resp.status, (time.perf_counter() - t0) * 1000
    except urllib.error.HTTPError as e:
        return False, e.code, (time.perf_counter() - t0) * 1000
    except Exception:
        return False, 0, (time.perf_counter() - t0) * 1000


async def _worker(
    endpoint: str,
    worker_id: int,
    stop_event: asyncio.Event,
    results: list,
    semaphore: asyncio.Semaphore,
) -> None:
    """Async worker that fires as fast as the semaphore allows until stop_event is set."""
    loop = asyncio.get_event_loop()
    seq = 0
    while not stop_event.is_set():
        # Unique capsule_id per submission (64-hex SHA-256)
        raw = f"load-test-worker-{worker_id}-seq-{seq}-{time.monotonic()}".encode()
        capsule_id = hashlib.sha256(raw).hexdigest()
        seq += 1
        async with semaphore:
            if stop_event.is_set():
                break
            success, status, latency_ms = await loop.run_in_executor(
                None, _post_digest, endpoint, capsule_id
            )
        results.append((success, status, latency_ms))


# ---------------------------------------------------------------------------
# Post-run verification
# ---------------------------------------------------------------------------

def _verify_anchor(base_url: str) -> dict:
    """Fetch the transparency-log and STH, spot-check 3 inclusion proofs."""
    base = base_url.rsplit("/v1/digest", 1)[0].rsplit("/transparency/", 1)[0]
    results: dict = {}
    try:
        with urllib.request.urlopen(f"{base}/anchor/sth", timeout=10) as r:
            sth = json.loads(r.read())
        results["tree_size"] = sth.get("tree_size", 0)
        results["sth_ok"] = True
    except Exception as e:
        results["sth_ok"] = False
        results["sth_error"] = str(e)
        return results

    # Spot-check 1 inclusion proof at the last entry
    tree_size = results["tree_size"]
    if tree_size > 0:
        leaf_index = tree_size - 1
        try:
            url = f"{base}/anchor/inclusion-proof-ct?leaf_index={leaf_index}&tree_size={tree_size}"
            with urllib.request.urlopen(url, timeout=10) as r:
                proof = json.loads(r.read())
            results["inclusion_proof_ok"] = (
                proof.get("leaf_index") == leaf_index
                and len(proof.get("audit_path", [])) >= 0
            )
        except Exception as e:
            results["inclusion_proof_ok"] = False
            results["inclusion_proof_error"] = str(e)
    return results


# ---------------------------------------------------------------------------
# Single run
# ---------------------------------------------------------------------------

async def run_once(
    endpoint: str,
    concurrency: int,
    duration: float,
    label: str = "",
) -> dict:
    results: list[tuple[bool, int, float]] = []
    stop_event = asyncio.Event()
    semaphore = asyncio.Semaphore(concurrency)

    workers = [
        asyncio.create_task(_worker(endpoint, i, stop_event, results, semaphore))
        for i in range(concurrency)
    ]

    t_start = time.perf_counter()
    print(f"  [{label}] Running {concurrency} concurrent workers for {duration}s …", flush=True)
    await asyncio.sleep(duration)
    stop_event.set()
    await asyncio.gather(*workers, return_exceptions=True)
    wall = time.perf_counter() - t_start

    successes = [(s, lat) for s, code, lat in results if s]
    failures = [(code, lat) for s, code, lat in results if not s]
    latencies = [lat for _, lat in successes]
    rate_limited = sum(1 for code, _ in failures if code == 429)

    stats: dict = {
        "label": label,
        "concurrency": concurrency,
        "duration_s": round(wall, 2),
        "total_requests": len(results),
        "successes": len(successes),
        "failures": len(failures),
        "rate_limited_429": rate_limited,
        "throughput_rps": round(len(successes) / wall, 2),
    }
    if latencies:
        latencies_sorted = sorted(latencies)
        stats["latency_ms"] = {
            "p50": round(statistics.median(latencies_sorted), 2),
            "p95": round(latencies_sorted[int(len(latencies_sorted) * 0.95)], 2),
            "p99": round(latencies_sorted[int(len(latencies_sorted) * 0.99)], 2),
            "max": round(max(latencies_sorted), 2),
            "mean": round(statistics.mean(latencies_sorted), 2),
        }
    print(
        f"  [{label}] done: {len(successes)}/{len(results)} ok, "
        f"{stats['throughput_rps']} rps, "
        f"p50={stats.get('latency_ms', {}).get('p50', '?')}ms "
        f"p99={stats.get('latency_ms', {}).get('p99', '?')}ms "
        f"429s={rate_limited}",
        flush=True,
    )
    return stats


# ---------------------------------------------------------------------------
# Sweep mode
# ---------------------------------------------------------------------------

SWEEP_LEVELS = [
    (1, 20, "warm-up"),
    (5, 30, "low"),
    (10, 60, "low-med"),
    (50, 60, "medium"),
    (100, 60, "high"),
    (200, 30, "burst"),
    (10, 20, "recovery"),
]


async def run_sweep(endpoint: str) -> list[dict]:
    all_results = []
    for concurrency, duration, label in SWEEP_LEVELS:
        result = await run_once(endpoint, concurrency, duration, label)
        all_results.append(result)
        # Short pause between levels to let the anchor settle
        await asyncio.sleep(2)
    return all_results


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def main(args: argparse.Namespace) -> None:
    print(f"Anchor Load Harness — {datetime.now(timezone.utc).isoformat()}")
    print(f"Target: {args.url}")
    print("INTERNAL — numbers not for external publication")
    print()

    if args.sweep:
        print("Running sweep across all concurrency levels …")
        all_stats = await run_sweep(args.url)
    else:
        all_stats = [await run_once(args.url, args.concurrency, args.duration, "single")]

    print()
    print("Post-run verification …")
    verify = _verify_anchor(args.url)
    print(f"  tree_size={verify.get('tree_size', '?')} sth_ok={verify.get('sth_ok')} "
          f"inclusion_proof_ok={verify.get('inclusion_proof_ok', 'skipped')}")

    output = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "endpoint": args.url,
        "runs": all_stats,
        "post_run_verify": verify,
    }
    out_path = args.output or f"load_results_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults written to {out_path} (INTERNAL)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NANDA Anchor Load Harness (INTERNAL)")
    parser.add_argument("--url", default=DEFAULT_URL, help="Anchor /v1/digest endpoint URL")
    parser.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY)
    parser.add_argument("--duration", type=float, default=DEFAULT_DURATION, help="Duration in seconds")
    parser.add_argument("--sweep", action="store_true", help="Run all concurrency levels")
    parser.add_argument("--output", default=None, help="Output JSON file path")
    args = parser.parse_args()
    asyncio.run(main(args))
