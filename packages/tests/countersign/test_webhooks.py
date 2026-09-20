"""deliver_webhook: retry schedule, HMAC signing, never raises -- ported
behavior, re-verified under this module's own types and header names.

Also: validate_webhook_url -- the pre-delivery SSRF/egress guard
([countersign-fixsoon-security] item 1, HARD GATE)."""

from __future__ import annotations

import pytest

import capsule_anchor.countersign.webhooks as webhooks_module
from capsule_anchor.countersign.webhooks import (
    ENV_WEBHOOK_ALLOWED_HOSTS,
    WebhookSubscription,
    WebhookURLRefused,
    deliver_webhook,
    hmac_sign,
    validate_webhook_url,
)


def test_hmac_sign_is_deterministic_and_secret_dependent():
    body = b'{"a":1}'
    sig1 = hmac_sign(body, "secret-a")
    sig2 = hmac_sign(body, "secret-a")
    sig3 = hmac_sign(body, "secret-b")
    assert sig1 == sig2
    assert sig1 != sig3
    assert sig1.startswith("hmac-sha256=")


def test_delivery_succeeds_on_first_attempt():
    calls = []

    def fake_post(url, body, headers, timeout):
        calls.append((url, headers))
        return 200

    sub = WebhookSubscription(url="https://producer.example/hook", secret="s3cr3t")
    delivery = deliver_webhook(
        sub, {"hello": "world"}, entry_hash="deadbeef", http_post=fake_post, sleep=lambda s: None
    )

    assert delivery.status == "success"
    assert delivery.attempts == 1
    assert delivery.last_status_code == 200
    assert len(calls) == 1
    _, headers = calls[0]
    assert headers["X-Countersign-Signature"].startswith("hmac-sha256=")
    assert headers["X-Countersign-Entry-Hash"] == "deadbeef"


def test_delivery_retries_and_records_failure_never_raises():
    attempts = []

    def always_fail(url, body, headers, timeout):
        attempts.append(1)
        return 500

    slept = []
    sub = WebhookSubscription(url="https://producer.example/hook", secret="s3cr3t")
    delivery = deliver_webhook(
        sub, {}, entry_hash="deadbeef", http_post=always_fail, sleep=lambda s: slept.append(s)
    )

    assert delivery.status == "failed"
    assert delivery.attempts == 4  # 1 try + 3 retries
    assert slept == [1.0, 4.0, 16.0]


def test_delivery_succeeds_after_retry():
    responses = iter([500, 500, 200])

    def flaky(url, body, headers, timeout):
        return next(responses)

    sub = WebhookSubscription(url="https://producer.example/hook", secret="s3cr3t")
    delivery = deliver_webhook(sub, {}, entry_hash="x", http_post=flaky, sleep=lambda s: None)

    assert delivery.status == "success"
    assert delivery.attempts == 3


def test_network_exception_never_propagates():
    def raises(url, body, headers, timeout):
        raise ConnectionError("boom")

    sub = WebhookSubscription(url="https://producer.example/hook", secret="s3cr3t")
    delivery = deliver_webhook(sub, {}, entry_hash="x", http_post=raises, sleep=lambda s: None)

    assert delivery.status == "failed"
    assert delivery.last_status_code is None


# --- validate_webhook_url: SSRF/egress guard ([countersign-fixsoon-security] item 1) ---


def test_non_https_scheme_is_refused():
    with pytest.raises(WebhookURLRefused, match="https"):
        validate_webhook_url("http://producer.example/hook")


def test_url_with_no_host_is_refused():
    with pytest.raises(WebhookURLRefused, match="no host"):
        validate_webhook_url("https:///hook")


@pytest.mark.parametrize(
    "blocked_ip",
    [
        "169.254.169.254",  # GCP/AWS cloud metadata
        "127.0.0.1",  # loopback
        "10.1.2.3",  # RFC1918
        "172.16.0.5",  # RFC1918
        "192.168.1.1",  # RFC1918
        "169.254.1.1",  # link-local
        "::1",  # IPv6 loopback
        "fd00:ec2::254",  # IPv6 ULA (AWS metadata)
        "fe80::1",  # IPv6 link-local
    ],
)
def test_blocked_address_classes_are_refused(monkeypatch, blocked_ip):
    monkeypatch.setattr(webhooks_module, "_RESOLVE_HOST", lambda host: [blocked_ip])
    with pytest.raises(WebhookURLRefused, match="blocked address"):
        validate_webhook_url("https://attacker-controlled.example/hook")


def test_public_https_url_is_allowed(monkeypatch):
    monkeypatch.setattr(webhooks_module, "_RESOLVE_HOST", lambda host: ["93.184.216.34"])
    validate_webhook_url("https://producer.example/hook")  # must not raise


def test_host_resolving_to_any_blocked_address_among_several_is_refused(monkeypatch):
    """A host with BOTH a public and a private A/AAAA record is refused --
    every resolved address is checked, not just the first."""
    monkeypatch.setattr(
        webhooks_module, "_RESOLVE_HOST", lambda host: ["93.184.216.34", "169.254.169.254"]
    )
    with pytest.raises(WebhookURLRefused, match="blocked address"):
        validate_webhook_url("https://mixed.example/hook")


def test_dns_resolution_failure_is_refused(monkeypatch):
    import socket

    def fail(host):
        raise socket.gaierror("name or service not known")

    monkeypatch.setattr(webhooks_module, "_RESOLVE_HOST", fail)
    with pytest.raises(WebhookURLRefused, match="does not resolve"):
        validate_webhook_url("https://nonexistent.invalid/hook")


def test_allowlist_rejects_a_host_not_on_it(monkeypatch):
    monkeypatch.setattr(webhooks_module, "_RESOLVE_HOST", lambda host: ["93.184.216.34"])
    with pytest.raises(WebhookURLRefused, match="allowlist"):
        validate_webhook_url(
            "https://producer.example/hook",
            env={ENV_WEBHOOK_ALLOWED_HOSTS: "trusted.example"},
        )


def test_allowlist_allows_a_host_on_it(monkeypatch):
    monkeypatch.setattr(webhooks_module, "_RESOLVE_HOST", lambda host: ["93.184.216.34"])
    validate_webhook_url(  # must not raise
        "https://Trusted.example/hook",
        env={ENV_WEBHOOK_ALLOWED_HOSTS: "trusted.example"},
    )


def test_allowlist_never_overrides_the_blocked_address_check(monkeypatch):
    """The allowlist is defense-in-depth, never a bypass: a host that is
    both allowlisted AND resolves to a blocked address is still refused."""
    monkeypatch.setattr(webhooks_module, "_RESOLVE_HOST", lambda host: ["169.254.169.254"])
    with pytest.raises(WebhookURLRefused, match="blocked address"):
        validate_webhook_url(
            "https://trusted.example/hook",
            env={ENV_WEBHOOK_ALLOWED_HOSTS: "trusted.example"},
        )


# --- _default_http_post: delivery-time SSRF (redirect + DNS-rebinding) ---
# ([countersign-fixsoon-security] item 1, HARD GATE -- bounced twice for
# validating only at admission and trusting the transport at delivery).


def test_delivery_time_dns_rebinding_is_refused_and_never_connects(monkeypatch):
    """A hostname that resolves to a public address at admission time
    (``validate_webhook_url``, called once at registration) but a blocked
    address at delivery time (DNS rebinding -- a short-TTL record flipping
    during the retry schedule's up-to-~21s span) is refused AT DELIVERY,
    and no connection is ever attempted."""
    answers = iter(["93.184.216.34", "169.254.169.254"])
    monkeypatch.setattr(webhooks_module, "_RESOLVE_HOST", lambda host: [next(answers)])

    connect_calls = []

    def spy_factory(host, ip, port, timeout):
        connect_calls.append((host, ip, port))
        raise AssertionError("must never connect once the delivery-time re-check refuses")

    monkeypatch.setattr(webhooks_module, "_CONNECTION_FACTORY", spy_factory)

    validate_webhook_url("https://rebinding.example/hook")  # admission: public, passes

    status = webhooks_module._default_http_post("https://rebinding.example/hook", b"{}", {}, 5.0)

    assert status == 0  # refused -- treated as a failed/retryable attempt, never raises
    assert connect_calls == []


class _FakeRedirectResponse:
    def __init__(self, status: int, location: str) -> None:
        self.status = status
        self._location = location

    def read(self) -> bytes:
        return b""

    def getheader(self, name: str, default=None):
        return self._location if name.lower() == "location" else default


class _FakeRedirectConnection:
    def __init__(self, host: str, ip: str, port: int, timeout: float) -> None:
        self.host = host
        self.ip = ip
        self.port = port

    def request(self, method, path, body=None, headers=None) -> None:
        pass

    def getresponse(self) -> _FakeRedirectResponse:
        return _FakeRedirectResponse(302, location="http://169.254.169.254/steal")

    def close(self) -> None:
        pass


def test_delivery_never_follows_a_redirect_to_a_blocked_address(monkeypatch):
    """The upstream endpoint responds 302 with a ``Location`` naming the
    cloud metadata address. ``_default_http_post`` must hand that status
    straight back to the retry loop -- never parse ``Location``, never
    dial a second connection. Exactly one connection (to the vetted, pinned
    address) proves no redirect-follow occurred."""
    monkeypatch.setattr(webhooks_module, "_RESOLVE_HOST", lambda host: ["93.184.216.34"])

    connections = []

    def factory(host, ip, port, timeout):
        conn = _FakeRedirectConnection(host, ip, port, timeout)
        connections.append(conn)
        return conn

    monkeypatch.setattr(webhooks_module, "_CONNECTION_FACTORY", factory)

    status = webhooks_module._default_http_post(
        "https://redirecting.example/hook", b"{}", {}, 5.0
    )

    assert status == 302  # returned as-is -- deliver_webhook's loop treats it as a failed attempt
    assert len(connections) == 1  # exactly one dial: the Location is never followed
    assert connections[0].ip == "93.184.216.34"
