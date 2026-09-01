#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Burst/load sanity tool for the witness deployment.

Fires concurrent requests at POST /checkpoints and the read routes
(GET /health, GET /anchor/sth) at a configurable rate, and reports a status
code histogram + latency percentiles. Built to answer one question: at
plausible webinar-spike traffic, do per-submitter rate limits protect the
service without starving the one submitter identity actually demoing live
(the "demo identity")?

DO NOT RUN AGAINST PRODUCTION until [witness-external-submitter] (the
per-submitter allowlist + rate limit) has landed on origin/main -- before
that, /checkpoints has only a single GLOBAL rate limit, so a burst test
would just prove the global limiter works, not that one noisy submitter
can't crowd out the demo identity. This is a load-generation tool, not a
CI check -- it is never invoked automatically.

Usage:
    python3 deploy/burst_test.py \\
        --host https://witness.agentactioncapsule.org \\
        --demo-key-hex <64-hex-char Ed25519 seed, the allowlisted demo identity> \\
        --demo-log-id demo-webinar-2026-09-09 \\
        --noisy-submitters 5 --rate 20 --duration 30
"""
from __future__ import annotations

import argparse
import asyncio
import collections
import hashlib
import statistics
import time

import cbor2
import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from scitt_cose.statement import build_signed_statement

_CLL_CONTENT_TYPE = "application/cll-checkpoint+cbor"
_WIRE_KIND = "cll-checkpoint"


def _pem(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


def _peaks_for(seed: str, n: int = 1) -> list[bytes]:
    return [hashlib.sha256(f"{seed}-{i}".encode()).digest() for i in range(n)]


def _commitment(peak_hashes: list[bytes]) -> bytes:
    return cbor2.dumps(peak_hashes, canonical=True)


def build_checkpoint(key: Ed25519PrivateKey, *, log_id: str, mmr_size: int) -> bytes:
    """A freshly-signed, structurally valid COSE checkpoint for `log_id` at
    `mmr_size`. Mirrors packages/tests/test_checkpoints_and_register_witness_host.py's
    helper -- kept independent (never imports capsule-emit; see checkpoint_cose.py's
    boundary-rule docstring)."""
    claims = {
        "kind": _WIRE_KIND,
        "log_size": mmr_size,
        "commitment": _commitment(_peaks_for(f"{log_id}-{mmr_size}")),
        "prev_size": max(mmr_size - 1, 0),
        "prev_commitment": _commitment(_peaks_for(f"{log_id}-{mmr_size - 1}")) if mmr_size > 1 else b"",
        "issued_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    payload = cbor2.dumps(claims, canonical=True)
    kid = key.public_key().public_bytes_raw()
    return build_signed_statement(
        payload,
        alg="EdDSA",
        private_key_pem=_pem(key),
        issuer=log_id,
        subject=f"{log_id}#{mmr_size}",
        content_type=_CLL_CONTENT_TYPE,
        kid=kid,
    )


class Submitter:
    """One simulated log identity, submitting an incrementing checkpoint series."""

    def __init__(self, log_id: str, key_hex: str | None = None):
        self.log_id = log_id
        self.key = (
            Ed25519PrivateKey.from_private_bytes(bytes.fromhex(key_hex))
            if key_hex
            else Ed25519PrivateKey.generate()
        )
        self._next_size = 1

    def next_checkpoint(self) -> bytes:
        cp = build_checkpoint(self.key, log_id=self.log_id, mmr_size=self._next_size)
        self._next_size += 1
        return cp


async def _fire(client: httpx.AsyncClient, method: str, url: str, **kwargs) -> tuple[int, float]:
    start = time.monotonic()
    try:
        resp = await client.request(method, url, **kwargs)
        return resp.status_code, time.monotonic() - start
    except httpx.HTTPError as exc:
        print(f"  request error: {exc}")
        return -1, time.monotonic() - start


async def run_burst(args: argparse.Namespace) -> None:
    demo = Submitter(args.demo_log_id, args.demo_key_hex)
    noisy = [Submitter(f"noisy-{i}-{args.demo_log_id}") for i in range(args.noisy_submitters)]

    results: dict[str, list[tuple[int, float]]] = collections.defaultdict(list)
    end_at = time.monotonic() + args.duration
    interval = 1.0 / args.rate

    async with httpx.AsyncClient(timeout=10.0) as client:
        tasks = []

        async def submit_loop(submitter: Submitter, label: str) -> None:
            while time.monotonic() < end_at:
                body = submitter.next_checkpoint()
                code, latency = await _fire(
                    client,
                    "POST",
                    f"{args.host}/checkpoints",
                    content=body,
                    headers={"content-type": _CLL_CONTENT_TYPE},
                )
                results[label].append((code, latency))
                await asyncio.sleep(interval)

        async def read_loop() -> None:
            while time.monotonic() < end_at:
                for path in ("/health", "/anchor/sth"):
                    code, latency = await _fire(client, "GET", f"{args.host}{path}")
                    results[f"read {path}"].append((code, latency))
                await asyncio.sleep(interval)

        tasks.append(asyncio.create_task(submit_loop(demo, "demo identity")))
        for i, sub in enumerate(noisy):
            tasks.append(asyncio.create_task(submit_loop(sub, f"noisy submitter {i}")))
        tasks.append(asyncio.create_task(read_loop()))

        await asyncio.gather(*tasks)

    print(f"\n=== burst test: {args.duration}s, {1 + args.noisy_submitters} submitters, "
          f"{args.rate} req/s/actor against {args.host} ===\n")
    for label, samples in results.items():
        codes = collections.Counter(code for code, _ in samples)
        latencies = [lat for _, lat in samples]
        p50 = statistics.median(latencies) if latencies else 0.0
        p99 = statistics.quantiles(latencies, n=100)[98] if len(latencies) >= 100 else max(latencies, default=0.0)
        print(f"{label}: {len(samples)} requests, status codes {dict(codes)}, "
              f"p50={p50*1000:.0f}ms p99={p99*1000:.0f}ms")

    demo_codes = collections.Counter(code for code, _ in results.get("demo identity", []))
    demo_success = demo_codes.get(200, 0) + demo_codes.get(201, 0)
    demo_total = sum(demo_codes.values())
    print(f"\ndemo identity success rate: {demo_success}/{demo_total} "
          f"({100 * demo_success / demo_total:.1f}%)" if demo_total else "\ndemo identity: no requests sent")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", required=True, help="e.g. https://witness.agentactioncapsule.org")
    parser.add_argument("--demo-log-id", default="demo-webinar", help="log_id / CWT issuer for the demo identity")
    parser.add_argument("--demo-key-hex", default=None,
                         help="hex Ed25519 seed for the ALLOWLISTED demo identity (Task 1). "
                              "If omitted, a throwaway key is generated -- fine for a local/staging "
                              "run, useless against a real allowlist gate in prod.")
    parser.add_argument("--noisy-submitters", type=int, default=5,
                         help="unallowlisted identities generating background load")
    parser.add_argument("--rate", type=float, default=10.0, help="requests per second, PER actor")
    parser.add_argument("--duration", type=float, default=30.0, help="seconds")
    args = parser.parse_args()

    print("WARNING: this hits a live host. Do not run against production before")
    print("[witness-external-submitter] (per-submitter allowlist + rate limit) has")
    print("landed on origin/main -- see deploy/DEPLOY.md.\n")

    asyncio.run(run_burst(args))


if __name__ == "__main__":
    main()
