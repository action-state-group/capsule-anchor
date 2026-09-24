"""``PublicLogPublisher`` -- the production wiring for a ``PublicLog`` backend.

This SUPERSEDES ``wrapper.attach_public_log``
as the path ``app.py`` actually runs: publishing happens on a timer against the
CURRENT Signed Tree Head, never inline on ``/checkpoints``, ``/register``, or
``/anchor/anchor`` -- a public-log outage must never fail a receipt to a caller.
``attach_public_log`` stays as the documented seam and is what tests use to
assert the wrapper's own invariant in isolation.

Failure isolation (step 4): ``publish_if_new`` NEVER raises. A failure is
logged at WARNING, counted, and persisted to ``public_log_failures`` for audit;
``degraded`` flips true after ``degraded_after`` consecutive failures (default
12 = one hour at the 5-minute default interval) so ``/health`` can surface it
without ever flipping the service's own ``ok`` to false.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from datetime import UTC, datetime

from capsule_anchor.anchoring.service import AnchorerService, sth_payload

logger = logging.getLogger(__name__)


class PublicLogPublisher:
    """Publishes the current STH to a ``PublicLog`` backend, at most once per
    ``tree_size``, with persisted idempotent dedup and failure isolation."""

    def __init__(
        self,
        anchorer: AnchorerService,
        public_log,
        store,
        *,
        degraded_after: int = 12,
    ) -> None:
        self._anchorer = anchorer
        self._public_log = public_log
        self._store = store
        self._degraded_after = degraded_after
        self._lock = threading.Lock()
        self._consecutive_failures = 0

    @property
    def backend_name(self) -> str:
        return self._public_log.name()

    def publish_if_new(self) -> bool:
        """Publish the current STH if its ``tree_size`` hasn't been published yet.

        Returns ``True`` on a fresh successful publish; ``False`` when skipped
        (empty log, or this ``tree_size`` was already published) or on
        failure. Never raises -- see the module docstring.
        """
        try:
            if self._anchorer._store.size() == 0:  # noqa: SLF001 -- same access app.py's refresh thread already uses
                return False
            sth = self._anchorer.get_sth()
            backend = self._public_log.name()
            if self._store.get_public_log_receipt(backend, sth.tree_size, sth.root_hash) is not None:
                return False
            payload = sth_payload(sth.tree_size, sth.root_hash, sth.timestamp)
            receipt = self._public_log.submit(payload, sth.signature)
        except Exception as exc:  # noqa: BLE001 -- never raise into a caller's path
            self._record_failure(exc)
            return False

        self._store.put_public_log_receipt(
            {
                "backend": backend,
                "sth_tree_size": sth.tree_size,
                "sth_root_hash": sth.root_hash,
                "sth_timestamp": sth.timestamp.isoformat(),
                "uuid": str(receipt.get("uuid") or receipt.get("location") or ""),
                "log_index": receipt.get("log_index"),
                "integrated_time": receipt.get("integrated_time"),
                "signed_entry_timestamp": receipt.get("signed_entry_timestamp"),
                "raw_response": json.dumps(receipt, default=str),
                "submitted_at": datetime.now(UTC).isoformat(),
            }
        )
        with self._lock:
            self._consecutive_failures = 0
        return True

    def _record_failure(self, exc: Exception) -> None:
        with self._lock:
            self._consecutive_failures += 1
            failures = self._consecutive_failures
        logger.warning(
            "public-log publish failed (backend=%s, consecutive_failures=%d): %s",
            self._public_log.name(),
            failures,
            exc,
        )
        try:
            self._store.put_public_log_failure(
                self._public_log.name(), datetime.now(UTC).isoformat(), str(exc)
            )
        except Exception:  # noqa: BLE001 -- the failure record itself must never raise
            logger.warning("failed to persist public-log failure record", exc_info=True)

    @property
    def degraded(self) -> bool:
        with self._lock:
            return self._consecutive_failures >= self._degraded_after

    @property
    def consecutive_failures(self) -> int:
        with self._lock:
            return self._consecutive_failures

    def close(self) -> None:
        close = getattr(self._public_log, "close", None)
        if callable(close):
            close()


def start_publisher_thread(publisher: PublicLogPublisher, interval_s: float) -> threading.Thread:
    """Start a daemon thread that calls ``publish_if_new`` every ``interval_s``
    seconds. Safe with N instances: dedup is enforced by the store's
    idempotent ``(backend, tree_size, root_hash)`` key, not by thread identity.
    """

    def _run() -> None:
        # Interval-only, same shape as app.py's ``_start_sth_refresh_thread``
        # -- no synchronous network call at startup (a real Rekor request
        # inside ``create_app()`` would make every test that enables the
        # rail dependent on network reachability). "Publish after key
        # rotation" reduces to today's FIRST interval tick following any
        # restart: no ``KeyProvider`` this service actually uses supports
        # in-process rotation (see ``signing_key.StaticKeyProvider``), so a
        # key change only ever happens via a redeploy/restart. If a future
        # KeyProvider implements ``rotate()`` in-process, its caller should
        # invoke ``publisher.publish_if_new()`` directly for a true
        # immediate publish.
        while True:
            time.sleep(interval_s)
            publisher.publish_if_new()

    t = threading.Thread(target=_run, daemon=True, name="public-log-publisher")
    t.start()
    return t
