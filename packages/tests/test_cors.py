"""Tests for read-only CORS on public log endpoints."""
from fastapi.testclient import TestClient

from capsule_anchor.app import create_app

SITE_ORIGIN = "https://agentactioncapsule.org"
OTHER_ORIGIN = "https://evil.example.com"


def _client() -> TestClient:
    return TestClient(create_app())


def test_sth_get_cors_headers_present():
    client = _client()
    resp = client.get("/anchor/sth", headers={"Origin": SITE_ORIGIN})
    assert resp.headers.get("access-control-allow-origin") == SITE_ORIGIN


def test_transparency_log_get_cors_headers_present():
    client = _client()
    resp = client.get("/anchor/transparency-log", headers={"Origin": SITE_ORIGIN})
    assert resp.headers.get("access-control-allow-origin") == SITE_ORIGIN


def test_sth_preflight_ok():
    client = _client()
    resp = client.options(
        "/anchor/sth",
        headers={
            "Origin": SITE_ORIGIN,
            "Access-Control-Request-Method": "GET",
        },
    )
    assert resp.status_code == 200
    assert resp.headers.get("access-control-allow-origin") == SITE_ORIGIN


def test_transparency_log_preflight_ok():
    client = _client()
    resp = client.options(
        "/anchor/transparency-log",
        headers={
            "Origin": SITE_ORIGIN,
            "Access-Control-Request-Method": "GET",
        },
    )
    assert resp.status_code == 200
    assert resp.headers.get("access-control-allow-origin") == SITE_ORIGIN


def test_unknown_origin_no_cors():
    client = _client()
    resp = client.get("/anchor/sth", headers={"Origin": OTHER_ORIGIN})
    assert "access-control-allow-origin" not in resp.headers


def test_register_statement_cors_does_not_allow_post():
    """Cross-origin POST to write path must be blocked.

    CORSMiddleware with allow_methods=["GET"] returns only GET in
    access-control-allow-methods; browsers see POST is absent and refuse to
    send the cross-origin POST. That is the enforced security boundary.
    """
    client = _client()
    resp = client.options(
        "/transparency/register-statement",
        headers={
            "Origin": SITE_ORIGIN,
            "Access-Control-Request-Method": "POST",
        },
    )
    allowed = resp.headers.get("access-control-allow-methods", "")
    assert "POST" not in allowed.upper(), (
        f"write path preflight must not include POST; got: {allowed!r}"
    )


def test_anchor_write_cors_does_not_allow_post():
    """POST /anchor/anchor write path must not be cross-origin accessible."""
    client = _client()
    resp = client.options(
        "/anchor/anchor",
        headers={
            "Origin": SITE_ORIGIN,
            "Access-Control-Request-Method": "POST",
        },
    )
    allowed = resp.headers.get("access-control-allow-methods", "")
    assert "POST" not in allowed.upper(), (
        f"write path preflight must not include POST; got: {allowed!r}"
    )
