# SPDX-License-Identifier: Apache-2.0
"""Webhook delivery of a countersignature entry back to the producer --
the same retry schedule, HMAC-over-JSON-body signing, and never-raises
delivery bookkeeping as this project's existing reference webhook
deliverer, ported into this module's own types
(``WebhookDelivery`` / ``WebhookSubscription``) with neutral header names.

Retry policy: 3 attempts with exponential backoff (1s, 4s, 16s). After the
last failure the delivery is recorded with ``status="failed"`` -- no
exception ever propagates out of ``deliver_webhook``.

Stdlib-only: ``http.client`` for the POST -- no HTTP client dependency for
a one-line outbound call, and deliberately NOT ``urllib.request``: its
opener re-resolves the hostname and auto-follows redirects, which is
exactly the delivery-time SSRF gap this module closes. Delivery dials a
freshly re-validated, pinned IP address rather than handing a hostname to
the stack to resolve on its own, and never follows a 3xx -- see
``_default_http_post`` for why (DNS-rebinding + open-redirect SSRF, closed
at delivery time, not just at admission time).
"""

from __future__ import annotations

import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import socket
import time
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

#: Hook for tests to fake the outbound connection without real network
#: access. Takes the original hostname (for the Host header and TLS
#: server_hostname), the pinned IP already vetted by ``_validate_and_pin``,
#: the port, and the timeout; returns an ``http.client.HTTPConnection``-like
#: object (``.request()`` / ``.getresponse()`` / ``.close()``).
_CONNECTION_FACTORY: Callable[[str, str, int, float], http.client.HTTPConnection] = (  # noqa: E731
    lambda host, ip, port, timeout: _PinnedHTTPSConnection(host, ip, port, timeout=timeout)
)


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


def _resolve_and_check(host: str) -> list[str]:
    """Resolve ``host`` and refuse it if ANY returned address is blocked.
    Returns the raw IP-literal strings on success. Shared by
    ``validate_webhook_url`` (admission time) and ``_validate_and_pin``
    (delivery time, called fresh before every connection attempt -- a
    hostname is never trusted from an earlier resolution)."""
    try:
        raw_ips = _RESOLVE_HOST(host)
    except socket.gaierror as exc:
        raise WebhookURLRefused(f"host {host!r} does not resolve: {exc}") from exc
    if not raw_ips:
        raise WebhookURLRefused(f"host {host!r} resolved to no addresses")

    for raw_ip in raw_ips:
        ip = ipaddress.ip_address(raw_ip.split("%", 1)[0])
        if _is_blocked_ip(ip):
            raise WebhookURLRefused(
                f"host {host!r} resolves to a blocked address ({ip}) -- "
                "loopback, link-local, metadata, and RFC1918/ULA private ranges are refused"
            )
    return [raw_ip.split("%", 1)[0] for raw_ip in raw_ips]


def _validate_and_pin(url: str, *, env: dict[str, str] | None = None) -> tuple[str, str, int]:
    """The full admission check (scheme, host, allowlist, resolved-address),
    re-run at the moment of dialing rather than trusted from an earlier
    call, plus the one addition delivery needs: the specific IP to connect
    to. Returns ``(hostname, pinned_ip, port)``.

    This is what closes the gap ``validate_webhook_url`` alone leaves open:
    a webhook is admitted once (at registration) but delivered later, on a
    retry schedule that spans up to ~21s -- plenty of time for a
    short-TTL DNS record to flip from a public answer (at admission) to a
    metadata/loopback/RFC1918 answer (at delivery), or for a redirect
    Location to name a different host entirely. Re-resolving AND
    re-checking right here, then connecting to that exact pinned address
    (never handing the hostname to the transport to re-resolve a third
    time), removes that TOCTOU window instead of re-opening it further down
    the stack.
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

    ips = _resolve_and_check(host)
    return host, ips[0], parsed.port or 443


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

    This is the ADMISSION-time check (run once, when a webhook_url is
    registered). ``_default_http_post`` runs the same check again, fresh,
    immediately before every delivery attempt and every redirect hop --
    this function alone does not protect against a DNS answer or a
    redirect that changes after registration.

    Raises ``WebhookURLRefused`` on any failure; raises nothing on a URL
    that passes every check.
    """
    _validate_and_pin(url, env=env)


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


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """An ``HTTPSConnection`` that dials ``pinned_ip`` directly instead of
    letting the socket layer re-resolve ``host`` -- the address
    ``_validate_and_pin`` already vetted is the ONLY address this
    connection will ever contact. TLS still verifies the server
    certificate against ``host`` (SNI + hostname check via
    ``server_hostname``), so a mismatched cert is refused exactly as
    normal; only the DNS lookup that could TOCTOU between vetting and
    dialing is removed."""

    def __init__(self, host: str, pinned_ip: str, port: int, *, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout)
        self._pinned_ip = pinned_ip

    def connect(self) -> None:
        sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def _default_http_post(url: str, body: bytes, headers: dict[str, str], timeout: float) -> int:
    """POST ``body`` to ``url`` over a connection dialed to a freshly
    re-validated, pinned IP address.

    Re-running the full admission check here (``_validate_and_pin``, not
    just trusting the check ``validate_webhook_url`` already ran once at
    registration) closes the TOCTOU window the retry schedule otherwise
    leaves open: a short-TTL DNS record can flip from a public answer (at
    admission) to a metadata/loopback/RFC1918 answer by the time delivery
    actually dials, up to ~21s later. And because this uses ``http.client``
    directly rather than ``urllib.request``'s opener, a 3xx response is
    handed straight back to ``deliver_webhook``'s retry loop as a failed
    attempt -- this function never inspects ``Location`` and never dials a
    second address, so a redirect naming a blocked host is never reached
    either.
    """
    try:
        host, ip, port = _validate_and_pin(url)
    except WebhookURLRefused:
        # The reason (which check failed) is deliberately not surfaced past this
        # point: deliver_webhook's contract is "never raises, only records a
        # WebhookDelivery" -- there is no channel back to the caller for it, and
        # this exact path (refused at DELIVERY time, e.g. DNS rebinding) is the
        # one this function exists to guard, so the 0 below is expected, not lost.
        return 0  # treated as a failed/retryable attempt, same as a network error

    parsed = urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    request_headers = dict(headers)
    request_headers.setdefault("Host", host)

    conn = _CONNECTION_FACTORY(host, ip, port, timeout)
    try:
        conn.request("POST", path, body=body, headers=request_headers)
        resp = conn.getresponse()
        status = int(resp.status)
        resp.read()
        return status
    except OSError:
        # Connection refused, timeout, TLS handshake/cert failure, etc.
        # deliver_webhook's contract is "never raises" -- the specific OSError
        # is not actionable to a caller that only ever sees success/failed, so
        # it is folded into the same "treat as a failed attempt" outcome the
        # retry loop already handles for a non-2xx status.
        return 0  # treated as retryable, same as a non-2xx response
    finally:
        conn.close()


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
