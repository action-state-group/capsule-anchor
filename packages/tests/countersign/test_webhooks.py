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
