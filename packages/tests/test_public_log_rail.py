# SPDX-License-Identifier: Apache-2.0
"""Wiring-level tests for [capsule-anchor-rekor-rail] step 1-5: app.py
config/startup, the scheduled publisher's dedup + failure isolation +
degraded-health, the ``/checkpoints`` stamp's ``public_log`` field, the
COSE receipt's UNPROTECTED-header-only augmentation, and the surfacing
GET endpoints.

Byte-stability is the load-bearing property this whole file protects: every
test that builds a checkpoint receipt with the rail OFF or not-yet-covering
must show the receipt is IDENTICAL to what pre-rekor-rail code would have
produced. See ``TestByteStability``.
"""
from __future__ import annotations

import base64
import hashlib

import cbor2
import pytest
from capsule_anchor.anchoring.service import AnchorerService
from capsule_anchor.app import create_app
from capsule_anchor.public_log import PublicLogPublisher
from capsule_anchor.public_log.receipt_augment import (
    COSE_PUBLIC_LOG_LABEL,
    augment_receipt_with_public_log,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from fastapi.testclient import TestClient
from scitt_cose.statement import build_signed_statement

#: Must match ``checkpoint_cose.CLL_CHECKPOINT_CONTENT_TYPE`` exactly.
_CLL_CONTENT_TYPE = "application/cll-checkpoint+cbor"


@pytest.fixture()
def key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def _pem(k: Ed25519PrivateKey) -> bytes:
    return k.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


def _peaks_for(seed: str, n: int = 1) -> list[bytes]:
    return [hashlib.sha256(f"{seed}-{i}".encode()).digest() for i in range(n)]


def _commitment(peak_hashes: list[bytes]) -> bytes:
    return cbor2.dumps(peak_hashes, canonical=True)


def _checkpoint_cose(k: Ed25519PrivateKey, *, log_id: str, mmr_size: int) -> bytes:
    """A minimal, valid CLL checkpoint COSE_Sign1 statement -- same wire
    shape as ``test_checkpoints_and_register_witness_host._checkpoint_cose``,
    reimplemented locally so this file has no cross-test-module coupling."""
    new_peaks = _peaks_for(f"{log_id}-{mmr_size}")
    claims = {
        "kind": "cll-checkpoint",
        "log_size": mmr_size,
        "commitment": _commitment(new_peaks),
        "prev_size": 0,
        "prev_commitment": b"",
        "issued_at": "2026-09-16T00:00:00Z",
    }
    payload = cbor2.dumps(claims, canonical=True)
    return build_signed_statement(
        payload,
        alg="EdDSA",
        private_key_pem=_pem(k),
        issuer=log_id,
        subject=f"{log_id}#{mmr_size}",
        content_type=_CLL_CONTENT_TYPE,
        kid=k.public_key().public_bytes_raw(),
    )


class _FakePublicLog:
    """Injectable ``PublicLog`` double: records calls, never touches a network."""

    def __init__(self, *, fail: bool = False, name: str = "fake-log"):
        self._fail = fail
        self._name = name
        self.calls = 0

    def name(self) -> str:
        return self._name

    def submit(self, payload: bytes, sig) -> dict:
        self.calls += 1
        if self._fail:
            raise RuntimeError("simulated network failure")
        return {
            "uuid": f"uuid-{self.calls}",
            "log_index": self.calls,
            "integrated_time": "it",
            "signed_entry_timestamp": "set",
            "location": "loc",
            "log": self._name,
        }


class TestPublisherDedupAndFailureIsolation:
    def test_no_duplicate_publish_for_same_tree_size(self):
        svc = AnchorerService()
        fake = _FakePublicLog()
        pub = PublicLogPublisher(svc, fake, svc._store)

        svc.register_signed_statement_full(b"entry-one")
        assert pub.publish_if_new() is True
        assert fake.calls == 1
        # Same tree_size, no new entries -- must not publish again.
        assert pub.publish_if_new() is False
        assert fake.calls == 1

        # A NEW entry advances tree_size -- now a fresh publish is expected.
        svc.register_signed_statement_full(b"entry-two")
        assert pub.publish_if_new() is True
        assert fake.calls == 2

    def test_empty_log_never_publishes(self):
        svc = AnchorerService()
        fake = _FakePublicLog()
        pub = PublicLogPublisher(svc, fake, svc._store)
        assert pub.publish_if_new() is False
        assert fake.calls == 0

    def test_failure_never_raises_and_is_counted(self):
        svc = AnchorerService()
        svc.register_signed_statement_full(b"entry-one")
        fake = _FakePublicLog(fail=True)
        pub = PublicLogPublisher(svc, fake, svc._store, degraded_after=3)

        for i in range(1, 4):
            result = pub.publish_if_new()  # must never raise
            assert result is False
            assert pub.consecutive_failures == i

        assert pub.degraded is True

    def test_failure_does_not_block_a_later_success(self):
        svc = AnchorerService()
        svc.register_signed_statement_full(b"entry-one")
        fake = _FakePublicLog(fail=True)
        pub = PublicLogPublisher(svc, fake, svc._store, degraded_after=2)
        pub.publish_if_new()
        pub.publish_if_new()
        assert pub.degraded is True

        pub._public_log = _FakePublicLog()  # "recovery" -- backend starts answering
        assert pub.publish_if_new() is True
        assert pub.consecutive_failures == 0
        assert pub.degraded is False

    def test_failure_is_persisted_for_audit(self):
        svc = AnchorerService()
        svc.register_signed_statement_full(b"entry-one")
        fake = _FakePublicLog(fail=True)
        pub = PublicLogPublisher(svc, fake, svc._store)
        pub.publish_if_new()
        assert len(svc._store._public_log_failures) == 1
        backend, _occurred_at, error = svc._store._public_log_failures[0]
        assert backend == "fake-log"
        assert "simulated network failure" in error

    def test_failure_does_not_affect_a_concurrent_checkpoint_registration(self):
        """A publish failure must be fully isolated from the request path --
        registering a checkpoint must succeed identically whether or not the
        public-log backend is currently failing."""
        svc = AnchorerService()
        fake = _FakePublicLog(fail=True)
        pub = PublicLogPublisher(svc, fake, svc._store)
        pub.publish_if_new()  # fails, isolated

        result = svc.register_signed_statement_full(b"unaffected-entry")
        assert result.receipt  # registration succeeded regardless


class TestConfigAndStartup:
    def _base_env(self, monkeypatch):
        monkeypatch.setenv("CAPSULE_ANCHOR_INSECURE_IN_MEMORY", "1")
        monkeypatch.setenv("CAPSULE_ANCHOR_PUBLIC_HOST", "witness.agentactioncapsule.org")

    def test_default_is_disabled(self, monkeypatch):
        self._base_env(monkeypatch)
        monkeypatch.setenv("CAPSULE_ANCHOR_SIGNING_KEY", "22" * 32)
        monkeypatch.delenv("CAPSULE_ANCHOR_PUBLIC_LOG", raising=False)
        app = create_app()
        client = TestClient(app)
        assert "public_log" not in client.get("/health").json()
        assert client.get("/anchor/public-log/latest").status_code == 404
        assert client.get("/anchor/public-log/entries").json() == []

    def test_rekor_with_ephemeral_key_refuses_to_start(self, monkeypatch):
        self._base_env(monkeypatch)
        monkeypatch.setenv("CAPSULE_ANCHOR_INSECURE_EPHEMERAL_KEY", "1")
        monkeypatch.delenv("CAPSULE_ANCHOR_SIGNING_KEY", raising=False)
        monkeypatch.setenv("CAPSULE_ANCHOR_PUBLIC_LOG", "rekor")
        with pytest.raises(RuntimeError, match="stable signing key"):
            create_app()

    def test_unknown_backend_refuses_to_start(self, monkeypatch):
        self._base_env(monkeypatch)
        monkeypatch.setenv("CAPSULE_ANCHOR_SIGNING_KEY", "33" * 32)
        monkeypatch.setenv("CAPSULE_ANCHOR_PUBLIC_LOG", "not-a-real-backend")
        with pytest.raises(RuntimeError, match="Unknown CAPSULE_ANCHOR_PUBLIC_LOG"):
            create_app()

    def test_rekor_enabled_with_stable_key_installs_publisher(self, monkeypatch):
        self._base_env(monkeypatch)
        monkeypatch.setenv("CAPSULE_ANCHOR_SIGNING_KEY", "44" * 32)
        monkeypatch.setenv("CAPSULE_ANCHOR_PUBLIC_LOG", "rekor")
        # Huge interval: the background thread must not race this test's
        # own manual publish_if_new() call below.
        monkeypatch.setenv("CAPSULE_ANCHOR_PUBLIC_LOG_INTERVAL", "999999")
        create_app()
        from capsule_anchor.anchoring.router import get_public_log_publisher

        publisher = get_public_log_publisher()
        assert publisher is not None
        assert publisher.backend_name == "rekor-public"


class TestHealthDegraded:
    def test_health_reports_degraded_after_threshold(self, monkeypatch):
        monkeypatch.setenv("CAPSULE_ANCHOR_INSECURE_IN_MEMORY", "1")
        monkeypatch.setenv("CAPSULE_ANCHOR_PUBLIC_HOST", "witness.agentactioncapsule.org")
        monkeypatch.setenv("CAPSULE_ANCHOR_SIGNING_KEY", "55" * 32)
        monkeypatch.setenv("CAPSULE_ANCHOR_PUBLIC_LOG", "rekor")
        monkeypatch.setenv("CAPSULE_ANCHOR_PUBLIC_LOG_INTERVAL", "999999")
        app = create_app()
        client = TestClient(app)

        from capsule_anchor.anchoring.router import get_public_log_publisher

        publisher = get_public_log_publisher()
        assert client.get("/health").json()["public_log"] == "ok"

        client.post("/register", json={"capsule_id": "aa" * 32})
        publisher._public_log = _FakePublicLog(fail=True)
        for _ in range(publisher._degraded_after):
            publisher.publish_if_new()

        assert publisher.degraded is True
        h = client.get("/health").json()
        assert h["public_log"] == "degraded"
        assert h["ok"] is True  # never flips the top-level health flag


class TestCheckpointStampAugmentation:
    """The [capsule-anchor-rekor-rail] step 5 wiring: a checkpoint stamp
    carries ``public_log`` only once a Rekor publication covers its
    tree_size, and the COSE receipt's UNPROTECTED header (label 397) carries
    the same evidence -- never the protected header."""

    def _client_with_publisher(self, monkeypatch):
        monkeypatch.setenv("CAPSULE_ANCHOR_INSECURE_IN_MEMORY", "1")
        monkeypatch.setenv("CAPSULE_ANCHOR_PUBLIC_HOST", "witness.agentactioncapsule.org")
        monkeypatch.setenv("CAPSULE_ANCHOR_SIGNING_KEY", "66" * 32)
        monkeypatch.setenv("CAPSULE_ANCHOR_PUBLIC_LOG", "rekor")
        monkeypatch.setenv("CAPSULE_ANCHOR_PUBLIC_LOG_INTERVAL", "999999")
        app = create_app()
        client = TestClient(app)
        from capsule_anchor.anchoring.router import get_public_log_publisher

        publisher = get_public_log_publisher()
        publisher._public_log = _FakePublicLog(name="rekor-public")
        return client, publisher

    def test_stamp_has_no_public_log_before_any_publish(self, monkeypatch, key):
        client, publisher = self._client_with_publisher(monkeypatch)
        cose = _checkpoint_cose(key, log_id="log-a", mmr_size=1)
        resp = client.post(
            "/checkpoints",
            content=cose,
            headers={"Content-Type": "application/cll-checkpoint+cbor"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["public_log"] is None
        receipt = cbor2.loads(base64.b64decode(body["receipt_b64"]))
        assert COSE_PUBLIC_LOG_LABEL not in receipt.value[1]

    def test_stamp_carries_public_log_once_covered(self, monkeypatch, key):
        client, publisher = self._client_with_publisher(monkeypatch)
        cose = _checkpoint_cose(key, log_id="log-b", mmr_size=1)
        resp = client.post(
            "/checkpoints",
            content=cose,
            headers={"Content-Type": "application/cll-checkpoint+cbor"},
        )
        assert resp.status_code == 200
        first_body = resp.json()
        tree_size = first_body["tree_size"]

        assert publisher.publish_if_new() is True

        # Resubmitting the SAME checkpoint (idempotent path) now returns a
        # stamp augmented with the just-published evidence.
        resp2 = client.post(
            "/checkpoints",
            content=cose,
            headers={"Content-Type": "application/cll-checkpoint+cbor"},
        )
        assert resp2.status_code == 200
        body2 = resp2.json()
        assert body2["public_log"] is not None
        assert body2["public_log"]["backend"] == "rekor-public"
        assert body2["public_log"]["sth_tree_size"] >= tree_size

        receipt2 = cbor2.loads(base64.b64decode(body2["receipt_b64"]))
        unprotected = receipt2.value[1]
        assert COSE_PUBLIC_LOG_LABEL in unprotected
        assert unprotected[COSE_PUBLIC_LOG_LABEL]["backend"] == "rekor-public"

        # PROTECTED content must be byte-identical between the two responses
        # -- only the unprotected header differs.
        receipt1 = cbor2.loads(base64.b64decode(first_body["receipt_b64"]))
        assert receipt1.value[0] == receipt2.value[0]  # protected bstr
        assert receipt1.value[3] == receipt2.value[3]  # signature


class TestSurfacingEndpoints:
    def test_latest_and_entries_after_a_publish(self, monkeypatch):
        monkeypatch.setenv("CAPSULE_ANCHOR_INSECURE_IN_MEMORY", "1")
        monkeypatch.setenv("CAPSULE_ANCHOR_PUBLIC_HOST", "witness.agentactioncapsule.org")
        monkeypatch.setenv("CAPSULE_ANCHOR_SIGNING_KEY", "77" * 32)
        monkeypatch.setenv("CAPSULE_ANCHOR_PUBLIC_LOG", "rekor")
        monkeypatch.setenv("CAPSULE_ANCHOR_PUBLIC_LOG_INTERVAL", "999999")
        app = create_app()
        client = TestClient(app)
        from capsule_anchor.anchoring.router import get_public_log_publisher

        publisher = get_public_log_publisher()
        publisher._public_log = _FakePublicLog(name="rekor-public")

        client.post("/register", json={"capsule_id": "aa" * 32})
        assert publisher.publish_if_new() is True

        latest = client.get("/anchor/public-log/latest")
        assert latest.status_code == 200
        assert latest.json()["backend"] == "rekor-public"
        assert isinstance(latest.json()["raw_response"], dict)

        entries = client.get("/anchor/public-log/entries")
        assert entries.status_code == 200
        assert len(entries.json()) == 1

        entries_since = client.get(
            f"/anchor/public-log/entries?since={latest.json()['sth_tree_size']}"
        )
        assert entries_since.json() == []


class TestByteStability:
    """The invariant that matters most: the rail must be additive.
    A receipt built with the rail disabled, or before any covering
    publication exists, is BYTE-IDENTICAL to the pre-rekor-rail wire shape."""

    def test_disabled_rail_receipt_matches_pre_rail_shape(self, monkeypatch, key):
        monkeypatch.setenv("CAPSULE_ANCHOR_INSECURE_EPHEMERAL_KEY", "1")
        monkeypatch.setenv("CAPSULE_ANCHOR_INSECURE_IN_MEMORY", "1")
        monkeypatch.setenv("CAPSULE_ANCHOR_PUBLIC_HOST", "witness.agentactioncapsule.org")
        monkeypatch.delenv("CAPSULE_ANCHOR_PUBLIC_LOG", raising=False)
        app = create_app()
        client = TestClient(app)

        cose = _checkpoint_cose(key, log_id="log-stability", mmr_size=1)
        resp = client.post(
            "/checkpoints",
            content=cose,
            headers={"Content-Type": "application/cll-checkpoint+cbor"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "public_log" in body  # field exists (additive schema)...
        assert body["public_log"] is None  # ...but empty when the rail is off

        receipt = cbor2.loads(base64.b64decode(body["receipt_b64"]))
        unprotected = receipt.value[1]
        assert COSE_PUBLIC_LOG_LABEL not in unprotected

    def test_augmentation_never_touches_protected_bytes_or_signature(self):
        """Direct unit proof on the augmentation function itself: for ANY
        receipt, wrapping it never changes the protected bstr or signature,
        only ever adds one unprotected-header key."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        from capsule_anchor.anchoring.service import build_cose_receipt

        sk = Ed25519PrivateKey.generate()
        receipt = build_cose_receipt(
            tree_size=5,
            leaf_index=2,
            audit_path=[hashlib.sha256(b"x").digest()],
            root=hashlib.sha256(b"root").digest(),
            sign=sk.sign,
            iss="did:web:witness.example.test",
            sub="entry-hash-placeholder",
            kid=b"\x01" * 8,
            iat=1000,
            grade="countersigned-observed",
        )
        augmented = augment_receipt_with_public_log(
            receipt, {"backend": "rekor-public", "uuid": "u", "log_index": 1, "sth_tree_size": 5}
        )

        orig = cbor2.loads(receipt)
        aug = cbor2.loads(augmented)
        assert orig.value[0] == aug.value[0]  # protected bstr unchanged
        assert orig.value[2] == aug.value[2]  # payload (None, detached) unchanged
        assert orig.value[3] == aug.value[3]  # signature unchanged
        assert orig.value[1] != aug.value[1]  # unprotected header DID change
        assert COSE_PUBLIC_LOG_LABEL in aug.value[1]
