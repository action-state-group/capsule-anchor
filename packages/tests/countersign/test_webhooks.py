"""deliver_webhook: retry schedule, HMAC signing, never raises -- ported
behavior, re-verified under this module's own types and header names."""

from __future__ import annotations

from capsule_anchor.countersign.webhooks import (
    WebhookSubscription,
    deliver_webhook,
    hmac_sign,
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
