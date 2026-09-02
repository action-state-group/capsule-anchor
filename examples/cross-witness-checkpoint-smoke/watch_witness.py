# SPDX-License-Identifier: Apache-2.0
"""Cheap watcher: detect growth in the witness's public transparency log, as
a trigger to check whether a `trace-registry/v1` checkpoint has appeared --
so LEG 2 of the cross-witness smoke test (and the separate
`[trace-registry-first-checkpoint-conformance]` task) can fire without a
human remembering to poll by hand.

HONEST LIMITATION (read before wiring this to anything automated):

``POST /checkpoints`` is the STAGE-1, stateless witness route
(``capsule_anchor.anchoring.service.AnchorerService.witness_checkpoint``): it
dispatches a submitted checkpoint as a BARE SHA-256 digest through the same
path as any other digest registration, and deliberately discards the
checkpoint's own claims (``log_id``, ``mmr_size``, ``prev_size``, ...) before
storage -- see that method's docstring, "STAGE-2 SEAM". The public
transparency log (`GET /anchor/transparency-log`) records only
``{log_index, logged_at, kind, payload_hash, ...}`` where ``kind`` is one of
``countersigned_root | cert_issued | cert_revoked | scitt_statement`` --
there is no ``kind`` value for "checkpoint", and no field anywhere in the
public log ties an entry back to the submitter's ``log_id``. There is also no
GET-by-log_id or GET-by-issuer endpoint (only `GET /v1/inclusion/{digest}`,
which requires you to already know the exact digest -- i.e. requires having
seen the checkpoint's own bytes already).

Given that, THIS SCRIPT CANNOT reliably tell you "a trace-registry/v1
checkpoint just appeared" from the public read surface alone -- it can only
tell you "the log grew by N entries since the last check", which is a
NECESSARY but not SUFFICIENT signal (any digest registration through ANY
route -- /checkpoints, /register, /v1/digest, /transparency/register-statement
-- increments the same counter). Treat a growth event as "go check with
Imran / re-run leg 2 and see if it's theirs", not as positive proof.

A precise, log_id-scoped watcher requires a stored/queryable record keyed by
submitter identity -- which is what `[witness-enroll-trace-registry-key]`
and `[witness-external-submitter]`'s acceptance criteria ("MMR vs foreign
grade distinguishable in the stored/served checkpoint record") are expected
to add. Once that surface exists, replace this tree-size-delta heuristic with
a direct query against it.

Usage:
    # one-shot: compare current tree_size to a baseline, print + exit 0 if grown
    python watch_witness.py --baseline 582

    # polling loop: check every N seconds, print an ALERT line on growth,
    # update the baseline after each alert so it doesn't re-fire on the same growth
    python watch_witness.py --baseline 582 --interval 300 --loop
"""
from __future__ import annotations

import argparse
import time
from datetime import datetime, timezone

import httpx

DEFAULT_HOST = "https://witness.agentactioncapsule.org"


def log(msg: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"[{ts}] {msg}", flush=True)


def current_tree_size(host: str, client: httpx.Client) -> int:
    resp = client.get(f"{host}/anchor/sth")
    if resp.status_code == 503:
        return 0  # log is empty
    resp.raise_for_status()
    return resp.json()["tree_size"]


def check_once(host: str, baseline: int, client: httpx.Client) -> int:
    size = current_tree_size(host, client)
    if size > baseline:
        log(
            f"ALERT: tree_size grew {baseline} -> {size} (+{size - baseline}). "
            "This means SOMETHING new was registered -- not necessarily a "
            "trace-registry/v1 checkpoint (see this script's docstring for why "
            "that can't be distinguished from the public log alone). Check with "
            "Imran, or re-run leg 2 / the conformance check and see if a "
            "trace-registry/v1 checkpoint is now fetchable by its known digest."
        )
    else:
        log(f"no growth: tree_size={size} (baseline={baseline})")
    return size


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default=DEFAULT_HOST, help=f"witness base URL (default: {DEFAULT_HOST})")
    ap.add_argument("--baseline", type=int, required=True, help="tree_size to compare against (capture the current value with `curl {host}/anchor/sth` first)")
    ap.add_argument("--interval", type=int, default=300, help="seconds between checks in --loop mode (default: 300)")
    ap.add_argument("--loop", action="store_true", help="poll repeatedly instead of a single check")
    args = ap.parse_args()

    baseline = args.baseline
    with httpx.Client(timeout=30.0) as client:
        if not args.loop:
            size = check_once(args.host, baseline, client)
            return 0 if size == baseline else 2  # exit 2 signals "growth observed, go look"
        log(f"polling {args.host}/anchor/sth every {args.interval}s, baseline={baseline}")
        try:
            while True:
                size = check_once(args.host, baseline, client)
                if size > baseline:
                    baseline = size  # don't re-fire on the same growth every subsequent tick
                time.sleep(args.interval)
        except KeyboardInterrupt:
            log("stopped")
            return 0


if __name__ == "__main__":
    raise SystemExit(main())
