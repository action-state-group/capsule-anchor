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
import ipaddress
import json
import os
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import urlparse

#: Backoff schedule (seconds): try at t=0, t=1, t=5, t=21 (three retries total).
_BACKOFF_SCHEDULE: tuple[float, ...] = (1.0, 4.0, 16.0)

#: Hook for tests to skip the real sleep without time mocking.
_SLEEP: Callable[[float], None] = time.sleep

#: Optional operator egress allowlist: comma-separated hostnames. When set,
#: ONLY these hosts may receive a webhook -- in ADDITION to (never instead
#: of) the resolved-address checks below.
ENV_WEBHOOK_ALLOWED_HOSTS = "CAPSULE_ANCHOR_COUNTERSIGN_WEBHOOK_ALLOWED_HOSTS"

#: Hook for tests to fake DNS resolution without real network access.
#: Returns the raw IP-literal strings ``host`` resolves to.
_RESOLVE_HOST: Callable[[str], list[str]] = lambda host: [  # noqa: E731
    info[4][0] for info in socket.getaddrinfo(host, None)
]


class WebhookURLRefused(ValueError):
    """Raised by ``validate_webhook_url`` when a ``webhook_url`` fails the
    pre-delivery SSRF/egress checks. The caller (the router) turns this into
    a 422 BEFORE scheduling ``deliver_webhook`` -- a blocked destination
    never even reaches the background task."""


def _is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True for loopback, link-local (incl. the 169.254.169.254 / GCP+AWS
    cloud metadata address), RFC1918/ULA private ranges (incl.
    ``fd00:ec2::254``), and the other non-public reserved ranges
    ``ipaddress.is_private`` already folds in for both address families."""
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def _allowed_hosts(env: dict[str, str] | None) -> set[str] | None:
    e = os.environ if env is None else env
    raw = e.get(ENV_WEBHOOK_ALLOWED_HOSTS)
    if not raw:
        return None
    return {h.strip().lower() for h in raw.split(",") if h.strip()}


def validate_webhook_url(url: str, *, env: dict[str, str] | None = None) -> None:
    """Refuse a ``webhook_url`` that could route the outbound POST at
    ``deliver_webhook`` to a metadata endpoint, loopback, link-local, or
    RFC1918/ULA private address.

    Checks, in order: (1) scheme MUST be ``https``; (2) if
    ``CAPSULE_ANCHOR_COUNTERSIGN_WEBHOOK_ALLOWED_HOSTS`` is configured, the
    host must be on that allowlist; (3) the host is resolved and EVERY
    returned address is checked -- a host that resolves to even one blocked
    address is refused, closing the trivial bypass of pointing a hostname at
    both a public and a private/metadata address.

    Raises ``WebhookURLRefused`` on any failure; raises nothing on a URL
    that passes every check.
    """
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise WebhookURLRefused(f"webhook_url must use https (got {parsed.scheme!r})")

    host = parsed.hostname
    if not host:
        raise WebhookURLRefused("webhook_url has no host")

    allowlist = _allowed_hosts(env)
    if allowlist is not None and host.lower() not in allowlist:
        raise WebhookURLRefused(f"host {host!r} is not on the configured webhook allowlist")

    try:
        raw_ips = _RESOLVE_HOST(host)
    except socket.gaierror as exc:
        raise WebhookURLRefused(f"webhook_url host {host!r} does not resolve: {exc}") from exc
    if not raw_ips:
        raise WebhookURLRefused(f"webhook_url host {host!r} resolved to no addresses")

    for raw_ip in raw_ips:
        ip = ipaddress.ip_address(raw_ip.split("%", 1)[0])
        if _is_blocked_ip(ip):
            raise WebhookURLRefused(
                f"webhook_url host {host!r} resolves to a blocked address ({ip}) -- "
                "loopback, link-local, metadata, and RFC1918/ULA private ranges are refused"
            )


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
