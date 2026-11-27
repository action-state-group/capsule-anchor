# SPDX-License-Identifier: Apache-2.0
"""Probe the hosted witness's /health, for .github/workflows/witness-monitor.yml (#109, ask 3).

Sends ``--samples`` GETs to ``<url>/health``, ``--gap`` seconds apart, each bounded by
``--timeout`` seconds, and prints one line per sample. Exits 1 when any sample got no 200
(an error status, a connection or TLS error, or a timeout), or when ``--slow-count`` or more
samples took longer than ``--limit`` seconds; otherwise 0. ``/health`` reads the log size and
the signed tree head from the store (packages/capsule_anchor/app.py, ``health``), so a stalled
database shows here too.

Only GETs: the probe adds no checkpoint to the witness's log.
"""

from __future__ import annotations

import argparse
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class Sample:
    status: int | None  # HTTP status, None when no response came back
    seconds: float
    error: str = ""  # why there was no response (connection, TLS, timeout)

    def line(self, n: int) -> str:
        got = str(self.status) if self.status is not None else f"no response ({self.error})"
        return f"probe {n}: {got} in {self.seconds:.2f} s"


def verdict(samples: list[Sample], limit: float, slow_count: int) -> tuple[bool, str]:
    """Whether the witness is healthy by these samples, and why not when it is not."""
    failed = [s for s in samples if s.status != 200]
    if failed:
        return False, f"{len(failed)} of {len(samples)} probes got no 200"
    slow = [s for s in samples if s.seconds > limit]
    if len(slow) >= slow_count:
        return False, f"{len(slow)} of {len(samples)} probes took longer than {limit:g} s"
    return True, f"{len(samples)} probes answered 200, {len(slow)} slower than {limit:g} s"


def fetch(url: str, timeout: float, clock: Callable[[], float] = time.monotonic) -> Sample:
    start = clock()
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:  # noqa: S310 (an https URL we name)
            r.read()
            return Sample(r.status, clock() - start)
    except urllib.error.HTTPError as e:
        return Sample(e.code, clock() - start)
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        reason = getattr(e, "reason", e)
        return Sample(None, clock() - start, f"{type(reason).__name__}: {reason}")


def main(argv: list[str] | None = None, get: Callable[[str, float], Sample] = fetch,
         sleep: Callable[[float], None] = time.sleep) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--url", default="https://witness.agentactioncapsule.org")
    p.add_argument("--samples", type=int, default=3)
    p.add_argument("--gap", type=float, default=10.0, help="seconds between samples")
    p.add_argument("--timeout", type=float, default=30.0, help="seconds one sample may take")
    p.add_argument("--limit", type=float, default=5.0, help="a sample slower than this is slow")
    p.add_argument("--slow-count", type=int, default=2, help="this many slow samples fail the run")
    a = p.parse_args(argv)
    if a.samples < 1 or a.slow_count < 1:
        p.error("--samples and --slow-count must be at least 1")
    samples = []
    for n in range(1, a.samples + 1):
        if n > 1:
            sleep(a.gap)
        s = get(f"{a.url.rstrip('/')}/health", a.timeout)
        samples.append(s)
        print(s.line(n), flush=True)
    ok, why = verdict(samples, a.limit, a.slow_count)
    print(("healthy: " if ok else "UNHEALTHY: ") + why)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
