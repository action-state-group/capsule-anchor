#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Integrity check for a restored capsule-anchor Postgres log store.

Connects directly to a Postgres database (the restore target, NOT
necessarily the live service) and checks the append-only `log_entries`
table (PostgresLogStore, packages/capsule_anchor/anchoring/store.py) for
the properties a transparency log must preserve across a
restore: a contiguous, gap-free `log_index` sequence starting at 0/1, a
row count that meets or exceeds an expected floor, and a valid hash chain
(`prev_log_hash` of entry N matches the entry-head-hash of entry N-1).

This is deliberately independent of the FastAPI app / signing key -- a
restore drill should prove the DATA survived, not that the app happens to
start. Run this against BOTH the live instance (to establish the expected
floor) and the restored scratch instance (to confirm it matches), per
deploy/BACKUP-RESTORE.md.

Usage:
    python3 deploy/verify_restore.py "postgresql://user:pass@host:5432/capsule_anchor"
"""
from __future__ import annotations

import hashlib
import json
import sys


def _tree_head_payload(log_index: int, payload_hash: str, prev_log_hash: str | None) -> bytes:
    """Byte-for-byte mirror of AnchorerService/tree_head_payload's
    ``_canonical({"log_index", "payload_hash", "prev_log_hash"})`` -- sorted
    keys, compact separators. Must match exactly or every entry looks
    tampered even on an honest restore."""
    return json.dumps(
        {
            "log_index": log_index,
            "payload_hash": payload_hash,
            "prev_log_hash": prev_log_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _entry_head_hash(log_index: int, payload_hash: str, prev_log_hash: str | None) -> str:
    """Mirrors AnchorerService._entry_head_hash: sha256 hex digest of the
    entry's tree-head payload, chained to its predecessor."""
    return hashlib.sha256(_tree_head_payload(log_index, payload_hash, prev_log_hash)).hexdigest()


def verify(db_url: str) -> int:
    import psycopg

    with psycopg.connect(db_url) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT log_index, logged_at, kind, payload_hash, prev_log_hash "
            "FROM log_entries ORDER BY log_index ASC"
        )
        rows = [
            {
                "log_index": r[0],
                "logged_at": r[1],
                "kind": r[2],
                "payload_hash": r[3],
                "prev_log_hash": r[4],
            }
            for r in cur.fetchall()
        ]

    if not rows:
        print("FAIL: anchor_log_entries is empty.")
        return 1

    print(f"tree_size: {len(rows)}")
    print(f"first log_index: {rows[0]['log_index']}, last: {rows[-1]['log_index']}")

    prev_head_hash = None
    for i, row in enumerate(rows):
        if row["log_index"] != i:
            print(f"FAIL: log_index {row['log_index']} is not contiguous from 0 (expected {i}).")
            return 1
        if row["prev_log_hash"] != prev_head_hash:
            print(
                f"FAIL: hash chain broken at log_index {row['log_index']} "
                f"(prev_log_hash={row['prev_log_hash']!r}, expected={prev_head_hash!r})."
            )
            return 1
        prev_head_hash = _entry_head_hash(row["log_index"], row["payload_hash"], row["prev_log_hash"])

    print(f"PASS: {len(rows)} entries, contiguous log_index, unbroken hash chain.")
    print(f"latest_entry_head_hash: {prev_head_hash}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(verify(sys.argv[1]))
