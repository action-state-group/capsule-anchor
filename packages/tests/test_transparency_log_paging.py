"""GET /anchor/transparency-log returns one bounded page per response
(capsule-anchor#133), on every store: in memory, SQLite and Postgres (the
last only with CAPSULE_ANCHOR_TEST_DATABASE_URL set; see conftest.py)."""
from __future__ import annotations

import hashlib
import os
import re
import urllib.parse

import pytest
from capsule_anchor.anchoring import router as router_mod
from capsule_anchor.anchoring.service import AnchorerService
from capsule_anchor.app import create_app
from fastapi import FastAPI
from fastapi.testclient import TestClient

from .pg_isolation import TEST_DATABASE_URL

PAGE_MAX = 5
URL = "/anchor/transparency-log"
SITE_ORIGIN = "https://agentactioncapsule.org"


@pytest.fixture(params=["memory", "sqlite", "postgres"])
def svc(request, tmp_path):
    if request.param == "memory":
        return AnchorerService()
    if request.param == "sqlite":
        return AnchorerService(db_path=str(tmp_path / "log.db"))
    if TEST_DATABASE_URL is None:
        pytest.skip("CAPSULE_ANCHOR_TEST_DATABASE_URL not set")
    from capsule_anchor.anchoring.store import PostgresLogStore

    return AnchorerService(store=PostgresLogStore(os.environ["CAPSULE_ANCHOR_DATABASE_URL"]))


@pytest.fixture
def client(svc, monkeypatch):
    # A small page keeps each test's log short; the route reads the module
    # constant on every call.
    monkeypatch.setattr(router_mod, "TRANSPARENCY_LOG_PAGE_MAX", PAGE_MAX)
    monkeypatch.setattr(router_mod, "_SERVICE", svc)
    app = FastAPI()
    app.include_router(router_mod.get_router())
    return TestClient(app)


def _append(svc: AnchorerService, n: int, capsule_id: str | None = None) -> None:
    root = hashlib.sha256(f"root-{n}".encode()).hexdigest()
    svc.anchor("tenant", root, (n, n), capsule_id=capsule_id)


def _next(resp) -> str | None:
    link = resp.headers.get("link")
    if link is None:
        return None
    m = re.fullmatch(r'<([^>]*)>; rel="next"', link)
    assert m, link
    return m.group(1)


def _follow(client: TestClient, url: str) -> tuple[list[dict], int]:
    """Read pages from ``url`` until no next link; return entries and page count."""
    out: list[dict] = []
    pages = 0
    while True:
        resp = client.get(url)
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert isinstance(body, list)
        out.extend(body)
        pages += 1
        ref = _next(resp)
        if ref is None:
            return out, pages
        # Resolve the reference the way a client does, against this request.
        url = urllib.parse.urljoin(str(resp.request.url), ref)


def _all(svc: AnchorerService) -> list[dict]:
    return [e.model_dump(mode="json") for e in svc.transparency_log()]


def test_no_limit_returns_one_page_and_a_next_link(svc, client):
    for n in range(PAGE_MAX + 2):
        _append(svc, n)
    resp = client.get(URL)
    assert [e["log_index"] for e in resp.json()] == list(range(PAGE_MAX))
    assert _next(resp) == f"?after_index={PAGE_MAX}&limit={PAGE_MAX}"


def test_following_next_reads_the_whole_log_byte_identical(svc, client):
    for n in range(3 * PAGE_MAX + 1):
        _append(svc, n)
    entries, pages = _follow(client, URL)
    assert pages == 4
    assert entries == _all(svc)


def test_exact_multiple_of_the_page_ends_without_an_empty_page(svc, client):
    for n in range(2 * PAGE_MAX):
        _append(svc, n)
    entries, pages = _follow(client, URL)
    assert pages == 2
    assert entries == _all(svc)


def test_a_short_page_at_the_tip_has_no_next(svc, client):
    for n in range(3):
        _append(svc, n)
    resp = client.get(URL)
    assert len(resp.json()) == 3
    assert "link" not in resp.headers


def test_after_index_at_and_past_the_tip(svc, client):
    for n in range(3):
        _append(svc, n)
    for after in (3, 10):
        resp = client.get(URL, params={"after_index": after})
        assert resp.status_code == 200
        assert resp.json() == []
        assert "link" not in resp.headers
    resp = client.get(URL, params={"after_index": 2})
    assert [e["log_index"] for e in resp.json()] == [2]
    assert "link" not in resp.headers


def test_limit_smaller_than_the_page(svc, client):
    for n in range(4):
        _append(svc, n)
    resp = client.get(URL, params={"limit": 2})
    assert [e["log_index"] for e in resp.json()] == [0, 1]
    assert _next(resp) == "?after_index=2&limit=2"
    entries, pages = _follow(client, f"{URL}?limit=2")
    assert pages == 2
    assert entries == _all(svc)


def test_limit_above_the_maximum_is_capped(svc, client):
    for n in range(PAGE_MAX + 1):
        _append(svc, n)
    resp = client.get(URL, params={"limit": PAGE_MAX * 100})
    assert len(resp.json()) == PAGE_MAX
    assert _next(resp) == f"?after_index={PAGE_MAX}&limit={PAGE_MAX}"


@pytest.mark.parametrize("limit", [0, -1])
def test_limit_below_one_is_400(client, limit):
    assert client.get(URL, params={"limit": limit}).status_code == 400


def test_appends_between_pages_are_neither_lost_nor_repeated(svc, client):
    for n in range(PAGE_MAX + 1):
        _append(svc, n)
    first = client.get(URL)
    _append(svc, 100)
    url = urllib.parse.urljoin(str(first.request.url), _next(first))
    rest, _ = _follow(client, url)
    assert first.json() + rest == _all(svc)
    # At the tip, a later poll from the last log_index + 1 picks up new entries.
    _append(svc, 101)
    resp = client.get(URL, params={"after_index": rest[-1]["log_index"] + 1})
    assert [e["log_index"] for e in resp.json()] == [PAGE_MAX + 2]


def test_capsule_filter_pages_and_the_next_link_keeps_it(svc, client):
    # Interleave two capsules so a dropped filter would show the other one.
    for n in range(4 * PAGE_MAX):
        _append(svc, n, capsule_id="cap-a" if n % 2 == 0 else "cap-b")
    entries, pages = _follow(client, f"{URL}?capsule_id=cap-a")
    assert pages == 2
    assert [e["log_index"] for e in entries] == list(range(0, 4 * PAGE_MAX, 2))
    resp = client.get(URL, params={"capsule_id": "cap-a", "after_index": 3, "limit": 2})
    assert [e["log_index"] for e in resp.json()] == [4, 6]
    assert _next(resp) == "?after_index=7&limit=2&capsule_id=cap-a"


def test_store_reads_are_bounded(svc, client, monkeypatch):
    """The route asks the store for one row past the page, never the log."""
    for n in range(3 * PAGE_MAX):
        _append(svc, n, capsule_id="cap")
    seen = []
    store = svc._store
    after, for_capsule = store.entries_after, store.entries_for_capsule

    def spy_after(after_index, limit=None):
        seen.append(limit)
        return after(after_index, limit=limit)

    def spy_capsule(capsule_id, after_index=0, limit=None):
        seen.append(limit)
        return for_capsule(capsule_id, after_index, limit)

    monkeypatch.setattr(store, "entries_after", spy_after)
    monkeypatch.setattr(store, "entries_for_capsule", spy_capsule)
    client.get(URL)
    client.get(URL, params={"capsule_id": "cap"})
    assert seen == [PAGE_MAX + 1, PAGE_MAX + 1]


def test_next_link_resolves_under_a_proxy_prefix(svc, monkeypatch):
    monkeypatch.setattr(router_mod, "TRANSPARENCY_LOG_PAGE_MAX", PAGE_MAX)
    monkeypatch.setattr(router_mod, "_SERVICE", svc)
    app = FastAPI(root_path="/witness")
    app.include_router(router_mod.get_router())
    for n in range(PAGE_MAX + 1):
        _append(svc, n)
    resp = TestClient(app).get(URL)
    target = urllib.parse.urljoin(
        "https://witness.example/witness/anchor/transparency-log", _next(resp)
    )
    assert target == (
        "https://witness.example/witness/anchor/transparency-log"
        f"?after_index={PAGE_MAX}&limit={PAGE_MAX}"
    )


def test_cors_exposes_the_link_header_to_the_site():
    resp = TestClient(create_app()).get(URL, headers={"Origin": SITE_ORIGIN})
    exposed = resp.headers.get("access-control-expose-headers", "")
    assert "link" in exposed.lower()
