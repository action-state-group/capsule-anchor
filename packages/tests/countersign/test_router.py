"""End-to-end: the countersign router only mounts when both env switches
are set, and POST /countersign/register round-trips a withheld v2 Evidence
Bundle submission into ``{"countersignatures": [entry]}`` -- matching
``capsulectl countersign request``'s ``countersignSubmissionResponse``."""

from __future__ import annotations

from fastapi.testclient import TestClient

import capsule_anchor.countersign.router as router_module
from capsule_anchor.anchoring.router import _SlidingWindowLimiter
from capsule_anchor.app import create_app
from capsule_anchor.countersign.issuers import IssuerAllowlist
from capsule_anchor.countersign.router import configure_issuers

from .conftest import base_bundle_raw, sign_submission


def _submission(raw, key, *, profile_id="test/v0", **extra):
    rid, rkey, rsig = sign_submission(raw, key)
    body = {
        "bundle": raw,
        "window": "30d",
        "requester": {"id": rid, "key_id": rkey},
        "requester_signature": rsig,
    }
    if profile_id is not None:
        body["profile_id"] = profile_id
    body.update(extra)
    return body


def test_countersign_router_absent_by_default():
    """The witness's default (permissive) instance never gains this router."""
    client = TestClient(create_app())
    resp = client.post("/countersign/register", json={"bundle": {}})
    assert resp.status_code == 404


def test_countersign_router_absent_with_only_one_switch(monkeypatch):
    monkeypatch.setenv("CAPSULE_ANCHOR_COUNTERSIGN", "1")
    monkeypatch.delenv("CAPSULE_ANCHOR_REGISTRATION_POLICY", raising=False)
    client = TestClient(create_app())
    resp = client.post("/countersign/register", json={"bundle": {}})
    assert resp.status_code == 404

    monkeypatch.delenv("CAPSULE_ANCHOR_COUNTERSIGN", raising=False)
    monkeypatch.setenv("CAPSULE_ANCHOR_REGISTRATION_POLICY", "strict")
    client = TestClient(create_app())
    resp = client.post("/countersign/register", json={"bundle": {}})
    assert resp.status_code == 404


def _strict_client(monkeypatch, issuer_allowlist) -> TestClient:
    monkeypatch.setenv("CAPSULE_ANCHOR_REGISTRATION_POLICY", "strict")
    monkeypatch.setenv("CAPSULE_ANCHOR_COUNTERSIGN", "1")
    client = TestClient(create_app())
    # app.py already installs IssuerAllowlist.from_env_or_default() (empty
    # in tests, since no CAPSULE_ANCHOR_COUNTERSIGN_ISSUERS_FILE is set) --
    # swap in the fixture's allowlist so the test's requester_key is enrolled.
    configure_issuers(issuer_allowlist)
    return client


def test_valid_bundle_round_trips_to_a_signed_entry(monkeypatch, requester_key, issuer_allowlist):
    client = _strict_client(monkeypatch, issuer_allowlist)
    raw = base_bundle_raw()

    resp = client.post("/countersign/register", json=_submission(raw, requester_key))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert list(body.keys()) == ["countersignatures"]
    entry = body["countersignatures"][0]
    assert entry["receipt"]["entry_hash"]
    assert entry["statement"]["checks"]
    assert entry["independent"] is True  # the countersign instance's ephemeral key != requester's


def test_unconfigured_public_host_is_refused_not_did_web_none(monkeypatch, requester_key, issuer_allowlist):
    """A missing CAPSULE_ANCHOR_PUBLIC_HOST must fail closed -- never publish
    a broken ``did:web:None`` signer identity."""
    client = _strict_client(monkeypatch, issuer_allowlist)
    monkeypatch.delenv("CAPSULE_ANCHOR_PUBLIC_HOST", raising=False)
    raw = base_bundle_raw()
    resp = client.post("/countersign/register", json=_submission(raw, requester_key))
    assert resp.status_code == 503
    assert "CAPSULE_ANCHOR_PUBLIC_HOST" in resp.json()["detail"]


def test_unenrolled_issuer_is_refused_over_http(monkeypatch, requester_key):
    """No issuer allowlist configured (the empty default) -> every
    registration is refused, never silently accepted."""
    client = _strict_client(monkeypatch, issuer_allowlist=IssuerAllowlist())
    raw = base_bundle_raw()
    resp = client.post("/countersign/register", json=_submission(raw, requester_key))
    assert resp.status_code == 422
    assert "not enrolled" in resp.json()["detail"]


def test_payloads_present_is_refused_over_http(monkeypatch, requester_key, issuer_allowlist):
    """A required case: a bundle with any payload present -> refused."""
    client = _strict_client(monkeypatch, issuer_allowlist)
    raw = base_bundle_raw()
    raw["completeness"]["payloads_mode"] = "all"
    resp = client.post("/countersign/register", json=_submission(raw, requester_key))
    assert resp.status_code == 422
    assert "refused" in resp.json()["detail"]


def test_webhook_delivery_runs_as_a_background_task(monkeypatch, requester_key, issuer_allowlist):
    """A webhook subscription must never block the response -- it is
    scheduled via FastAPI's BackgroundTasks, not called inline before the
    response is built. Patch deliver_webhook to record the call rather than
    hitting the network, and the DNS resolver so the SSRF guard's host
    check resolves to a public address without real network access."""
    import capsule_anchor.countersign.router as router_module
    import capsule_anchor.countersign.webhooks as webhooks_module

    calls = []

    def fake_deliver(subscription, payload, *, entry_hash):
        calls.append((subscription.url, entry_hash))

    monkeypatch.setattr(router_module, "deliver_webhook", fake_deliver)
    monkeypatch.setattr(webhooks_module, "_RESOLVE_HOST", lambda host: ["93.184.216.34"])

    client = _strict_client(monkeypatch, issuer_allowlist)
    raw = base_bundle_raw()

    resp = client.post(
        "/countersign/register",
        json=_submission(raw, requester_key, webhook_url="https://producer.example/hook", webhook_secret="s3cr3t"),
    )
    assert resp.status_code == 200, resp.text
    entry = resp.json()["countersignatures"][0]
    assert calls == [("https://producer.example/hook", entry["receipt"]["entry_hash"])]


def test_webhook_url_targeting_metadata_ip_is_refused_before_scheduling(
    monkeypatch, requester_key, issuer_allowlist
):
    """SSRF guard, HARD GATE: a webhook_url whose host resolves to the cloud
    metadata address is refused with 422 BEFORE deliver_webhook is ever
    scheduled -- an enrolled issuer cannot use this endpoint to make the
    service fetch 169.254.169.254 on their behalf."""
    import capsule_anchor.countersign.router as router_module
    import capsule_anchor.countersign.webhooks as webhooks_module

    calls = []
    monkeypatch.setattr(
        router_module, "deliver_webhook", lambda *a, **kw: calls.append((a, kw))
    )
    monkeypatch.setattr(webhooks_module, "_RESOLVE_HOST", lambda host: ["169.254.169.254"])

    client = _strict_client(monkeypatch, issuer_allowlist)
    raw = base_bundle_raw()

    resp = client.post(
        "/countersign/register",
        json=_submission(
            raw, requester_key, webhook_url="https://attacker.example/hook", webhook_secret="s3cr3t"
        ),
    )
    assert resp.status_code == 422, resp.text
    assert "webhook_url refused" in resp.json()["detail"]
    assert calls == []


def test_webhook_url_over_plain_http_is_refused(monkeypatch, requester_key, issuer_allowlist):
    """SSRF guard: scheme MUST be https."""
    client = _strict_client(monkeypatch, issuer_allowlist)
    raw = base_bundle_raw()

    resp = client.post(
        "/countersign/register",
        json=_submission(
            raw, requester_key, webhook_url="http://producer.example/hook", webhook_secret="s3cr3t"
        ),
    )
    assert resp.status_code == 422, resp.text
    assert "webhook_url refused" in resp.json()["detail"]


def test_unknown_profile_is_refused(monkeypatch, requester_key, issuer_allowlist):
    client = _strict_client(monkeypatch, issuer_allowlist)
    raw = base_bundle_raw()
    resp = client.post("/countersign/register", json=_submission(raw, requester_key, profile_id="nonexistent/v9"))
    assert resp.status_code == 422
    assert "no policy module" in resp.json()["detail"]


def test_missing_profile_id_runs_generic_checks_only(monkeypatch, requester_key, issuer_allowlist):
    """capsulectl's current ``countersignSubmission`` wire shape has no
    ``profile_id`` field at all -- a submission that never names one must
    still succeed (the five generic checks only, no profile-specific
    coverage), never be refused. Refusing here would reject 100% of real
    capsulectl requests today."""
    client = _strict_client(monkeypatch, issuer_allowlist)
    raw = base_bundle_raw()
    resp = client.post("/countersign/register", json=_submission(raw, requester_key, profile_id=None))
    assert resp.status_code == 200, resp.text
    entry = resp.json()["countersignatures"][0]
    assert entry["statement"]["checks"]
    assert "profile" not in entry["statement"]


def test_requester_key_mismatch_is_refused(monkeypatch, requester_key, issuer_allowlist):
    """A requester_signature that verifies under a DIFFERENT key than the
    one the issuer allowlist pins for that requester id is refused -- the
    trust anchor's own pinned key always wins, never a caller-supplied one."""
    client = _strict_client(monkeypatch, issuer_allowlist)
    raw = base_bundle_raw()
    body = _submission(raw, requester_key)
    body["requester"]["key_id"] = "ff" * 32
    resp = client.post("/countersign/register", json=body)
    assert resp.status_code == 422
    assert "does not match the key" in resp.json()["detail"]


# --- item 2: unbounded body on /countersign/register ---


def test_oversized_body_is_refused_with_413_before_parse(monkeypatch, issuer_allowlist):
    """A body over MAX_STATEMENT_BYTES is refused with 413 BEFORE
    JSON-decode -- proven here by sending bytes that aren't even valid JSON;
    a 413 (not a 422 JSON-decode error) shows the size check ran first."""
    client = _strict_client(monkeypatch, issuer_allowlist)
    oversized = b"x" * (router_module.MAX_STATEMENT_BYTES + 1)
    resp = client.post(
        "/countersign/register", content=oversized, headers={"Content-Type": "application/json"}
    )
    assert resp.status_code == 413, resp.text
    assert "too large" in resp.json()["detail"]


def test_body_at_the_cap_is_not_refused_for_size(monkeypatch, issuer_allowlist):
    """A body exactly AT the cap must not be refused for size -- only
    STRICTLY over. It still fails JSON-decode here (not a real submission),
    proving the size gate itself is exact rather than off-by-one strict."""
    client = _strict_client(monkeypatch, issuer_allowlist)
    at_cap = b"x" * router_module.MAX_STATEMENT_BYTES
    resp = client.post(
        "/countersign/register", content=at_cap, headers={"Content-Type": "application/json"}
    )
    assert resp.status_code != 413, resp.text


# --- item 3: no rate limit on /countersign/register ---


def test_rate_limit_exceeded_returns_429(monkeypatch, issuer_allowlist):
    client = _strict_client(monkeypatch, issuer_allowlist)
    monkeypatch.setattr(
        router_module, "_COUNTERSIGN_POST_LIMITER", _SlidingWindowLimiter(max_calls=1, window_s=60.0)
    )
    first = client.post("/countersign/register", json={})
    assert first.status_code != 429, first.text

    second = client.post("/countersign/register", json={})
    assert second.status_code == 429, second.text
    assert "rate limit" in second.json()["detail"]


def test_rate_limit_is_a_separate_budget_per_instance(monkeypatch, issuer_allowlist):
    """A fresh limiter always starts open -- confirms the gate is a
    per-instance sliding window, not a global flag stuck from a prior test."""
    client = _strict_client(monkeypatch, issuer_allowlist)
    monkeypatch.setattr(
        router_module, "_COUNTERSIGN_POST_LIMITER", _SlidingWindowLimiter(max_calls=300, window_s=60.0)
    )
    resp = client.post("/countersign/register", json={})
    assert resp.status_code != 429, resp.text
