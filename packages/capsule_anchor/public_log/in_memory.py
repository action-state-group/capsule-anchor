"""``InMemoryPublicLog`` -- default ``PublicLog`` for tests and local dev.

An in-process append-only record of submitted ``(payload, signature)`` pairs.
Satisfies ``contracts.protocols.PublicLog`` (verified via ``isinstance``).

This implementation is deliberately tiny: a list under a lock, plus a SHA-256
"location" id so receipts are stable across processes restarts when persisted.
It exists so the rest of the system can be exercised end-to-end without hitting
the real Rekor network -- the same boundary the production ``RekorPublicLog``
satisfies.

NO PLAINTEXT INVARIANT: callers are expected to pass content-free payloads
(Signed Tree Heads). This module does not enforce that semantically -- the
``attach_public_log`` wrapper is the integration point that *guarantees* only
STH bytes are ever submitted (see ``wrapper.py``).
"""

from __future__ import annotations

import hashlib
import threading
from datetime import datetime, timezone

from capsule_anchor.contracts.types import Signature


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class InMemoryPublicLog:
    """Append-only in-process ``PublicLog``."""

    _LOG_NAME = "in-memory"

    def __init__(self) -> None:
        self._lock = threading.RLock()
        # list of (payload_bytes, signature_hex, payload_sha256_hex, integrated_time)
        self._entries: list[tuple[bytes, str, str, str]] = []

    # --- PublicLog protocol -------------------------------------------------
    def submit(self, payload: bytes, sig: Signature) -> dict:
        """Append a content-free payload + its signature; return a receipt."""
        with self._lock:
            log_index = len(self._entries)
            payload_hash = hashlib.sha256(payload).hexdigest()
            integrated_time = _now_iso()
            self._entries.append(
                (bytes(payload), sig.signature, payload_hash, integrated_time)
            )
            return {
                "location": f"in-memory://{log_index}",
                "log_index": log_index,
                "integrated_time": integrated_time,
                "payload_sha256": payload_hash,
                "signature": sig.signature,
                "key_id": sig.key_id,
            }

    def verify(self, receipt: dict) -> bool:
        """True iff the receipt names an existing entry with matching hash + sig."""
        try:
            idx = int(receipt["log_index"])
        except (KeyError, TypeError, ValueError):
            return False
        with self._lock:
            if not (0 <= idx < len(self._entries)):
                return False
            _payload, sig_hex, payload_hash, integrated_time = self._entries[idx]
            if receipt.get("location") != f"in-memory://{idx}":
                return False
            if receipt.get("payload_sha256") != payload_hash:
                return False
            if receipt.get("signature") != sig_hex:
                return False
            if receipt.get("integrated_time") != integrated_time:
                return False
            return True

    def name(self) -> str:
        return self._LOG_NAME

    # --- introspection (test-only) -----------------------------------------
    def entries(self) -> list[tuple[bytes, str, str, str]]:
        """All entries, oldest-first. Test helper."""
        with self._lock:
            return list(self._entries)

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)
