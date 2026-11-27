# SPDX-License-Identifier: Apache-2.0
"""Probe the hosted witness's /health, for .github/workflows/witness-monitor.yml (#109, ask 3).

Sends ``--samples`` GETs to ``<url>/health``, ``--gap`` seconds apart, each bounded by
``--timeout`` seconds, and prints one line per sample. Exits 1 when any sample got no 200
(an error status, a connection or TLS error, or a timeout), or when ``--slow-count`` or more
samples took longer than ``--limit`` seconds, or when ``--max-tree-size`` is set and a sample's
``tree_size`` has reached it; otherwise 0. ``/health`` reads the log size and
the signed tree head from the store (packages/capsule_anchor/app.py, ``health``), so a stalled
database shows here too.

``--max-tree-size`` is a tripwire, not a health check: it reports when the log reaches a size
whose startup memory has not been measured (capsule-anchor#132; the workflow names the
threshold and the measurement to take before raising it).

Only GETs: the probe adds no checkpoint to the witness's log.
"""

from __future__ import annotations

import argparse
import http.client
import json
import sys
import threading
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
    tree_size: int | None = None  # /health's tree_size, when a 200 body carried one

    def line(self, n: int) -> str:
        got = str(self.status) if self.status is not None else f"no response ({self.error})"
        size = f", tree_size {self.tree_size}" if self.tree_size is not None else ""
        return f"probe {n}: {got} in {self.seconds:.2f} s{size}"


def verdict(samples: list[Sample], limit: float, slow_count: int,
            max_tree_size: int | None = None) -> tuple[bool, str]:
    """Whether the witness is healthy by these samples, and why not when it is not."""
    failed = [s for s in samples if s.status != 200]
    if failed:
        return False, f"{len(failed)} of {len(samples)} probes got no 200"
    slow = [s for s in samples if s.seconds > limit]
    if len(slow) >= slow_count:
        return False, f"{len(slow)} of {len(samples)} probes took longer than {limit:g} s"
    sizes = [s.tree_size for s in samples if s.tree_size is not None]
    if max_tree_size is not None and sizes and max(sizes) >= max_tree_size:
        return False, (f"tree_size {max(sizes)} reached the tripwire {max_tree_size}: measure the startup "
                       "memory at this size before raising it (https://github.com/action-state-group/capsule-anchor/issues/132)")
    return True, f"{len(samples)} probes answered 200, {len(slow)} slower than {limit:g} s"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect is an answer other than 200: never follow it to a page that might answer 200."""

    def redirect_request(self, *args, **kwargs):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


#: /health answers a few hundred bytes; the probe keeps at most this much of a body.
_BODY_CAP = 65536


def _get(url: str, timeout: float) -> tuple[int, bytes]:
    with _OPENER.open(url, timeout=timeout) as r:
        body = b""
        while chunk := r.read1(65536):
            if len(body) < _BODY_CAP:
                body += chunk[: _BODY_CAP - len(body)]
        if r.length:  # read1 ends quietly when the server closes before Content-Length
            raise http.client.IncompleteRead(b"", r.length)
        return r.status, body


def _tree_size(body: bytes) -> int | None:
    """``tree_size`` from a /health body, or None when it has none (the size is a tripwire
    reading, never a reason to call an answering witness unhealthy)."""
    try:
        size = json.loads(body).get("tree_size")
    except (ValueError, AttributeError, RecursionError):  # RecursionError: deeply nested JSON
        return None
    return size if isinstance(size, int) and not isinstance(size, bool) else None


def fetch(url: str, timeout: float, clock: Callable[[], float] = time.monotonic) -> Sample:
    """One GET, bounded by ``timeout`` seconds in all: connection, headers and the whole body.

    The request runs on a daemon thread, so a server that trickles its headers or body (each
    read within the socket timeout) still ends the sample at ``timeout``.
    """
    start = clock()
    got: list = []

    def run() -> None:
        try:
            got.append(_get(url, timeout))
        except urllib.error.HTTPError as e:
            got.append(e.code)
        except (urllib.error.URLError, http.client.HTTPException, TimeoutError, OSError) as e:
            got.append(getattr(e, "reason", e))

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(timeout)
    took = clock() - start
    if not got:
        return Sample(None, took, f"TimeoutError: no full answer in {timeout:g} s")
    if isinstance(got[0], tuple):
        status, body = got[0]
        return Sample(status, took, tree_size=_tree_size(body) if status == 200 else None)
    if isinstance(got[0], int):
        return Sample(got[0], took)
    return Sample(None, took, f"{type(got[0]).__name__}: {got[0]}")


def main(argv: list[str] | None = None, get: Callable[[str, float], Sample] = fetch,
         sleep: Callable[[float], None] = time.sleep) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--url", default="https://witness.agentactioncapsule.org")
    p.add_argument("--samples", type=int, default=3)
    p.add_argument("--gap", type=float, default=10.0, help="seconds between samples")
    p.add_argument("--timeout", type=float, default=30.0, help="seconds one sample may take")
    p.add_argument("--limit", type=float, default=5.0, help="a sample slower than this is slow")
    p.add_argument("--slow-count", type=int, default=2, help="this many slow samples fail the run")
    p.add_argument("--max-tree-size", type=int, default=None,
                   help="fail once a sample's tree_size reaches this (a memory tripwire; off by default)")
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
    ok, why = verdict(samples, a.limit, a.slow_count, a.max_tree_size)
    print(("healthy: " if ok else "UNHEALTHY: ") + why)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
