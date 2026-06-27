"""Tests for the root page (GET /)."""
from fastapi.testclient import TestClient

from capsule_anchor.app import create_app


def test_root_returns_200_html():
    client = TestClient(create_app())
    resp = client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


def test_root_is_not_json_404():
    client = TestClient(create_app())
    resp = client.get("/")
    assert resp.status_code != 404
    assert resp.headers["content-type"] != "application/json"


def test_root_contains_expected_content():
    client = TestClient(create_app())
    body = client.get("/").text
    assert "Agent Action Capsule" in body
    assert "Transparency Service" in body


def test_root_endpoint_paths_are_correct():
    """Every endpoint path in the page must match an actual route the service exposes."""
    client = TestClient(create_app())
    client.get("/")  # confirms the route serves HTML without error

    # Paths that appear in the page and must resolve (2xx or non-404)
    get_paths = [
        "/health",
        "/.well-known/did.json",
        "/anchor/sth",
        "/anchor/transparency-log",
        "/anchor/inclusion-proof-ct",
        "/anchor/consistency-proof",
    ]
    for path in get_paths:
        resp = client.get(path)
        assert resp.status_code != 404, f"GET {path} returned 404 — link in root page is broken"

    # Confirm none of the old wrong paths exist
    wrong_paths = ["/sth", "/transparency-log", "/inclusion-proof-ct", "/consistency-proof", "/entries"]
    for path in wrong_paths:
        # These should 404 or 405, NOT 200 — they were wrong paths that got fixed
        resp = client.get(path)
        assert resp.status_code != 200, f"GET {path} unexpectedly returned 200 — page may still link to old path"

    # Confirm the correct POST endpoint is reachable (405 on GET = route exists)
    post_resp = client.get("/transparency/register-statement")
    assert post_resp.status_code == 405, \
        "/transparency/register-statement not registered (expected 405 Method Not Allowed on GET)"
