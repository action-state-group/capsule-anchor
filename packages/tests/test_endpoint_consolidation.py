"""[O4-endpoint-consolidation-ship]: witness.agentactioncapsule.org is now the
canonical name for this service, served alongside the preserved
anchor.agentactioncapsule.org (frozen decision: "serve ALL hostnames, NO
301-on-POST"). No `Host` header ever gates or changes read/write behavior --
DNS for the witness.* CNAME is what decides which requests physically arrive
here, not this service.
"""
from capsule_anchor.app import create_app
from fastapi.testclient import TestClient


def test_health_served_regardless_of_host_header():
    client = TestClient(create_app())
    for host in ("anchor.agentactioncapsule.org", "witness.agentactioncapsule.org", "localhost"):
        resp = client.get("/health", headers={"Host": host})
        assert resp.status_code == 200, f"GET /health rejected for Host={host!r}"


def test_register_statement_post_never_redirected_regardless_of_host():
    """A POST must always be served directly -- never a redirect -- on any
    hostname. An empty/invalid body still proves this: a redirect would come
    back as 3xx; direct handling comes back as a 4xx validation error."""
    client = TestClient(create_app(), follow_redirects=False)
    for host in ("anchor.agentactioncapsule.org", "witness.agentactioncapsule.org"):
        resp = client.post(
            "/transparency/register-statement",
            json={"signed_statement_b64": ""},
            headers={"Host": host},
        )
        assert not (300 <= resp.status_code < 400), (
            f"POST /transparency/register-statement was redirected for Host={host!r} "
            f"(got {resp.status_code}) -- POST must never be redirected"
        )
