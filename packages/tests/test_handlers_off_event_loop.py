"""The two async write handlers run their blocking registration in the thread
pool, so a write that waits (on the writer lock, on Postgres) does not stop
the instance's event loop from answering other requests (capsule-anchor#132).

Each test holds one registration blocked inside the service and checks that
``GET /`` (a route that takes no service lock) answers meanwhile. When the
handler ran the registration on the event loop itself, ``GET /`` waited the
whole hold.
"""

from __future__ import annotations

import threading
import time

from fastapi.testclient import TestClient

from capsule_anchor.app import create_app

#: How long a blocked registration is held at most; the check needs GET / to
#: answer well inside it.
HOLD_S = 5.0


def _get_root_while_held(client: TestClient, post, entered: threading.Event, release: threading.Event) -> float:
    """Run ``post`` in a thread until the service holds it, then time GET /.

    ``client`` must be entered (``with client:``): only then do its requests
    share one event loop, as an instance's requests do. A client used without
    ``with`` runs each request on a loop of its own, and the check would pass
    whatever the handler does."""
    assert client.portal is not None, "enter the TestClient so its requests share one event loop"
    results: dict = {}
    poster = threading.Thread(target=lambda: results.setdefault("post", post()))
    poster.start()
    try:
        assert entered.wait(HOLD_S), "the registration never reached the service"
        started = time.monotonic()
        assert client.get("/").status_code == 200
        return time.monotonic() - started
    finally:
        release.set()
        poster.join(HOLD_S * 2)
        assert not poster.is_alive()


def test_get_root_answers_while_a_checkpoint_registration_is_blocked(monkeypatch):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from capsule_anchor.anchoring import router

    from .test_checkpoints_and_register_witness_host import _checkpoint_cose, _peaks_for

    client = TestClient(create_app())
    entered, release = threading.Event(), threading.Event()
    real = router.get_service().witness_checkpoint

    def held(cp):
        entered.set()
        release.wait(HOLD_S)
        return real(cp)

    monkeypatch.setattr(router.get_service(), "witness_checkpoint", held)
    body = _checkpoint_cose(Ed25519PrivateKey.generate(), log_id="held-log", mmr_size=3, new_peaks=_peaks_for("held"))

    def post():
        return client.post("/checkpoints", content=body, headers={"Content-Type": "application/cll-checkpoint+cbor"})

    with client:
        elapsed = _get_root_while_held(client, post, entered, release)
    assert elapsed < HOLD_S / 2, f"GET / waited {elapsed:.2f}s behind a blocked registration"
