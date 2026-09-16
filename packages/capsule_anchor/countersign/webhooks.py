# SPDX-License-Identifier: Apache-2.0
"""Webhook delivery of a countersignature entry back to the producer --
the same retry schedule, HMAC-over-JSON-body signing, and never-raises
delivery bookkeeping as this project's existing reference webhook
deliverer, ported into this module's own types
(``WebhookDelivery`` / ``WebhookSubscription``) with neutral header names.

Retry policy: 3 attempts with exponential backoff (1s, 4s, 16s). After the
last failure the delivery is recorded with ``status="failed"`` -- no
exception ever propagates out of ``deliver_webhook``.

Stdlib-only: ``urllib.request`` for the POST -- no HTTP client dependency
for a one-line outbound call.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

#: Backoff schedule (seconds): try at t=0, t=1, t=5, t=21 (three retries total).
_BACKOFF_SCHEDULE: tuple[float, ...] = (1.0, 4.0, 16.0)

#: Hook for tests to skip the real sleep without time mocking.
_SLEEP: Callable[[float], None] = time.sleep


@dataclass(frozen=True)
class WebhookSubscription:
    """Where a producer wants a countersignature entry delivered, and the
    shared secret used to sign it."""

    url: str
    secret: str


@dataclass
class WebhookDelivery:
    """Outcome of one delivery attempt sequence -- never raised, always
    returned, so a caller has ops visibility into the retry history."""

    url: str
    entry_hash: str
    attempts: int
    status: str  # "success" | "failed"
    last_status_code: int | None
    delivered_at: datetime


def hmac_sign(body: bytes, secret: str) -> str:
    """Return ``hmac-sha256=<hex>`` for ``body`` under ``secret``."""
    mac = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"hmac-sha256={mac}"


def _default_http_post(url: str, body: bytes, headers: dict[str, str], timeout: float) -> int:
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return int(resp.status)
    except urllib.error.HTTPError as exc:
        return int(exc.code)
    except (urllib.error.URLError, OSError):
        return 0  # network error -- treated as retryable


def deliver_webhook(
    subscription: WebhookSubscription,
    payload: dict[str, Any],
    *,
    entry_hash: str,
    http_post: Callable[[str, bytes, dict[str, str], float], int] | None = None,
    sleep: Callable[[float], None] | None = None,
    timeout: float = 5.0,
) -> WebhookDelivery:
    """POST ``payload`` (the ``countersignatures[]`` entry) to the
    subscription's webhook with retries.

    Returns a ``WebhookDelivery`` describing the outcome -- never raises.
    The caller records the delivery row for ops visibility.
    """
    poster = http_post or _default_http_post
    sleeper = sleep or _SLEEP
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = hmac_sign(body, subscription.secret)
    headers = {
        "Content-Type": "application/json",
        "X-Countersign-Signature": signature,
        "X-Countersign-Entry-Hash": entry_hash,
    }

    last_status: int = 0
    attempts = 0
    success = False
    # Try once, then back off + retry up to len(_BACKOFF_SCHEDULE) times.
    for i in range(len(_BACKOFF_SCHEDULE) + 1):
        if i > 0:
            sleeper(_BACKOFF_SCHEDULE[i - 1])
        attempts += 1
        try:
            last_status = poster(subscription.url, body, headers, timeout)
        except Exception:  # noqa: BLE001 -- defensive: never let webhook errors escape
            last_status = 0
        if 200 <= last_status < 300:
            success = True
            break

    return WebhookDelivery(
        url=subscription.url,
        entry_hash=entry_hash,
        attempts=attempts,
        status="success" if success else "failed",
        last_status_code=last_status if last_status else None,
        delivered_at=datetime.now(timezone.utc),
    )
