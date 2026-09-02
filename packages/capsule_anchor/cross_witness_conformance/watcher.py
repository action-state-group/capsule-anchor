# SPDX-License-Identifier: Apache-2.0
"""CLI: run the conformance + chain-continuity pipeline against a checkpoint
obtained out of band, remembering it so the NEXT run can check continuity
against it.

USAGE:
    python -m capsule_anchor.cross_witness_conformance.watcher <checkpoint-file>
        [--witness-base-url URL] [--state-file PATH] [--expected-grade GRADE]

Reads raw COSE_Sign1 checkpoint bytes from <checkpoint-file> (``-`` for
stdin), runs the full report (wire + enrolled identity/grade + witness
tie-back), and if a PREVIOUS checkpoint for the same log_id is on record,
also runs the chain-continuity check against it. Exit code is 0 only if no
check FAILed (an UNKNOWN -- e.g. "no previous checkpoint yet" -- does not
fail the run, but is always printed so it stays visible rather than
silently passing).

KNOWN GAP (see NOTES.md): witness.agentactioncapsule.org has no public
endpoint that lets a third party DISCOVER a checkpoint's bytes by log_id --
this command does not poll for or discover anything on its own. Something
else out of band (AgenTrust/Imran handing us the checkpoint, or a companion
discovery endpoint if one gets built) must supply the bytes. Once that
source exists, wire it in as a small producer that writes a file and
invokes this command -- the checking logic below is already complete and
should not need to change.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .checker import (
    DEFAULT_EXPECTED_GRADE,
    DEFAULT_EXPECTED_LOG_ID,
    ConformanceReport,
    check_chain_continuity,
    check_checkpoint_wire,
    check_witness_tie_back,
    make_http_getter,
)

DEFAULT_WITNESS_BASE_URL = "https://witness.agentactioncapsule.org"
DEFAULT_STATE_FILE = Path(".trace_registry_watch_state.json")


def _load_state(state_file: Path) -> dict | None:
    if not state_file.exists():
        return None
    return json.loads(state_file.read_text())


def _save_state(state_file: Path, claims: dict) -> None:
    state_file.write_text(json.dumps(claims, indent=2, sort_keys=True))


def run(
    cose_bytes: bytes,
    *,
    witness_base_url: str = DEFAULT_WITNESS_BASE_URL,
    state_file: Path = DEFAULT_STATE_FILE,
    expected_log_id: str = DEFAULT_EXPECTED_LOG_ID,
    expected_grade: str | None = DEFAULT_EXPECTED_GRADE,
    get=None,
) -> ConformanceReport:
    """`get` is injectable (a `TestClient(app).get`-shaped callable) so tests
    never touch the network; the CLI's `main()` leaves it `None` to get a
    real HTTP client against `witness_base_url`.
    """
    report = check_checkpoint_wire(
        cose_bytes, expected_log_id=expected_log_id, expected_grade=expected_grade
    )
    if report.claims is None:
        return report  # wire-invalid -- nothing further to check

    getter = get or make_http_getter(witness_base_url)
    report.merge(check_witness_tie_back(report.claims, get=getter))

    previous = _load_state(state_file)
    if previous is not None and previous.get("log_id") == report.claims["log_id"]:
        report.merge(check_chain_continuity(previous, report.claims))
    elif previous is not None:
        report.add(
            "chain_continuity",
            "UNKNOWN",
            f"stored previous checkpoint is for log_id {previous.get('log_id')!r}, this "
            f"one is {report.claims['log_id']!r} -- not comparable, treating this as first-seen",
        )
    else:
        report.add(
            "chain_continuity",
            "UNKNOWN",
            "no previous checkpoint on record for this log_id yet -- this is the first "
            "one seen by this watcher; continuity will be checked against it on the NEXT run",
        )

    if not report.has_failure:
        _save_state(state_file, report.claims)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("checkpoint_file", help="path to raw COSE_Sign1 checkpoint bytes, or '-' for stdin")
    parser.add_argument("--witness-base-url", default=DEFAULT_WITNESS_BASE_URL)
    parser.add_argument("--state-file", type=Path, default=DEFAULT_STATE_FILE)
    parser.add_argument("--expected-log-id", default=DEFAULT_EXPECTED_LOG_ID)
    parser.add_argument("--expected-grade", default=DEFAULT_EXPECTED_GRADE)
    args = parser.parse_args(argv)

    cose_bytes = sys.stdin.buffer.read() if args.checkpoint_file == "-" else Path(args.checkpoint_file).read_bytes()

    report = run(
        cose_bytes,
        witness_base_url=args.witness_base_url,
        state_file=args.state_file,
        expected_log_id=args.expected_log_id,
        expected_grade=args.expected_grade,
    )
    print(report.render())
    return 1 if report.has_failure else 0


if __name__ == "__main__":
    raise SystemExit(main())
