"""Tests for the root page (GET /), the [O4-endpoint-consolidation-ship]
disclosure page. The link check parses the page's own `href`/`src`
attributes rather than a hand-maintained path list, so a new or edited link
in the HTML is covered automatically instead of silently going untested.
"""
from html.parser import HTMLParser
from urllib.parse import urlparse

from capsule_anchor.app import create_app
from fastapi.testclient import TestClient


class _LinkCollector(HTMLParser):
    """Collects every `href`/`src` value in the document, in order."""

    def __init__(self):
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag, attrs):
        for name, value in attrs:
            if name in ("href", "src") and value:
                self.links.append(value)


def _links_in(html: str) -> list[str]:
    parser = _LinkCollector()
    parser.feed(html)
    return parser.links


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


def test_root_declares_witness_as_the_canonical_name():
    """[O4] witness.agentactioncapsule.org must be named as canonical on the
    page itself; anchor.agentactioncapsule.org must still be present too --
    preserved, not deleted (§2a.5's shared-operator caveat, narrowed not
    removed: the hosted witness is still one operator)."""
    body = TestClient(create_app()).get("/").text
    assert "witness.agentactioncapsule.org" in body
    assert "anchor.agentactioncapsule.org" in body


def test_root_page_links_all_resolve():
    """Every host-relative link (`href="/..."`) in the disclosure page must
    match a real route -- parsed from the page itself, not a fixed list.
    External links (http(s)://...) must at least be well-formed absolute
    URLs; no live network call is made against them (would be flaky in CI)."""
    client = TestClient(create_app())
    body = client.get("/").text
    links = _links_in(body)
    assert links, "no links found in root page -- parser or page broken"

    internal_checked = 0
    for link in links:
        if link.startswith("#") or link.startswith("mailto:"):
            continue
        parsed = urlparse(link)
        if parsed.scheme:
            # External link: must be well-formed (scheme + host), never checked live.
            assert parsed.netloc, f"malformed external link in root page: {link!r}"
            continue
        # Host-relative link: must resolve to a real route. POST-only routes
        # correctly 405 on GET -- that still proves the route is registered.
        internal_checked += 1
        resp = client.get(link)
        assert resp.status_code != 404, f"link {link!r} in root page does not resolve (404)"
    assert internal_checked >= 6, "expected the root page to still link its own API endpoints"


def test_root_endpoint_paths_are_host_relative():
    """[O4] the page's own API links must be host-relative, so the same HTML
    is correct whether served from witness.agentactioncapsule.org or
    anchor.agentactioncapsule.org -- an absolute anchor.* link here would
    silently steer a witness.* visitor back to the legacy host."""
    body = TestClient(create_app()).get("/").text
    links = _links_in(body)
    for link in links:
        assert "anchor.agentactioncapsule.org" not in link, (
            f"root page link {link!r} hardcodes the anchor.* host instead of "
            "being host-relative"
        )


def test_root_no_longer_links_old_wrong_paths():
    client = TestClient(create_app())
    body = client.get("/").text
    links = set(_links_in(body))
    wrong_paths = {"/sth", "/transparency-log", "/inclusion-proof-ct", "/consistency-proof", "/entries"}
    assert not (links & wrong_paths), f"root page still links old wrong path(s): {links & wrong_paths}"
