"""End-to-end: the countersign router only mounts when both env switches
are set, and POST /countersign/register round-trips a withheld bundle into
a signed, receipted countersignatures[] entry."""

from __future__ import annotations

from fastapi.testclient import TestClient

from capsule_anchor.app import create_app
from capsule_anchor.countersign.issuers import IssuerAllowlist
from capsule_anchor.countersign.router import configure_issuers

from .conftest import base_bundle_raw, finalize_bundle


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
    # swap in the fixture's allowlist so the test's producer_key is enrolled.
    configure_issuers(issuer_allowlist)
    return client


def test_valid_bundle_round_trips_to_a_signed_entry(monkeypatch, producer_key, issuer_allowlist):
    client = _strict_client(monkeypatch, issuer_allowlist)
    raw = finalize_bundle(base_bundle_raw(producer_key), producer_key)

    resp = client.post("/countersign/register", json={"bundle": raw})
    assert resp.status_code == 200, resp.text
    entry = resp.json()
    assert entry["over"] == raw["digest"]
    assert entry["receipt"]["entry_hash"]
    assert entry["statement"]["checks"]
    assert entry["independent"] is True  # the countersign instance's ephemeral key != producer's


def test_unenrolled_issuer_is_refused_over_http(monkeypatch, producer_key):
    """No issuer allowlist configured (the empty default) -> every
    registration is refused, never silently accepted."""
    client = _strict_client(monkeypatch, issuer_allowlist=IssuerAllowlist())
    raw = finalize_bundle(base_bundle_raw(producer_key), producer_key)
    resp = client.post("/countersign/register", json={"bundle": raw})
    assert resp.status_code == 422
    assert "not enrolled" in resp.json()["detail"]


def test_payloads_present_is_refused_over_http(monkeypatch, producer_key, issuer_allowlist):
    """A required case: a bundle with any payload present -> refused."""
    client = _strict_client(monkeypatch, issuer_allowlist)
    raw = base_bundle_raw(producer_key)
    raw["payloads"] = "all"
    resp = client.post("/countersign/register", json={"bundle": raw})
    assert resp.status_code == 422
    assert "refused" in resp.json()["detail"]


def test_webhook_delivery_runs_as_a_background_task(monkeypatch, producer_key, issuer_allowlist):
    """A webhook subscription must never block the response -- it is
    scheduled via FastAPI's BackgroundTasks, not called inline before the
    response is built. Patch deliver_webhook to record the call rather than
    hitting the network."""
    import capsule_anchor.countersign.router as router_module

    calls = []

    def fake_deliver(subscription, payload, *, entry_hash):
        calls.append((subscription.url, entry_hash))

    monkeypatch.setattr(router_module, "deliver_webhook", fake_deliver)

    client = _strict_client(monkeypatch, issuer_allowlist)
    raw = finalize_bundle(base_bundle_raw(producer_key), producer_key)

    resp = client.post(
        "/countersign/register",
        json={
            "bundle": raw,
            "webhook_url": "https://producer.example/hook",
            "webhook_secret": "s3cr3t",
        },
    )
    assert resp.status_code == 200, resp.text
    entry = resp.json()
    assert calls == [("https://producer.example/hook", entry["receipt"]["entry_hash"])]


def test_unknown_profile_is_refused(monkeypatch, producer_key, issuer_allowlist):
    client = _strict_client(monkeypatch, issuer_allowlist)
    raw = finalize_bundle(base_bundle_raw(producer_key), producer_key)
    resp = client.post(
        "/countersign/register",
        json={"bundle": raw, "profile_id": "nonexistent/v9"},
    )
    assert resp.status_code == 422
    assert "no policy module" in resp.json()["detail"]
