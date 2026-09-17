# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the Rekor ``PublicLog`` backend ([capsule-anchor-rekor-rail]
step 7): ``RekorBundle.build`` golden vector, ``RekorPublicLog.submit``/``verify``
against an injected ``httpx.MockTransport``, and the ``attach_public_log``
wrapper's no-plaintext invariant.

The one opt-in LIVE test against ``rekor.sigstore.dev`` is gated behind
``CAPSULE_ANCHOR_TEST_LIVE_REKOR=1`` and skipped otherwise -- it never runs in
normal CI, only in a manual/CI-manual run against the real public instance.
"""
from __future__ import annotations

import base64
import hashlib
import os
import subprocess
import tempfile
from datetime import UTC, datetime

import httpx
import pytest
from capsule_anchor.anchoring.service import sth_payload
from capsule_anchor.contracts.types import Signature
from capsule_anchor.public_log.in_memory import InMemoryPublicLog
from capsule_anchor.public_log.rekor import RekorBundle, RekorPublicLog, _ed25519_raw_to_pem
from capsule_anchor.public_log.wrapper import attach_public_log
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

_AUTHORITY_SEED = b"\x01" * 32


def _authority_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(_AUTHORITY_SEED)


def _sig(hex_sig: str, key_id: str = "deadbeefcafef00d") -> Signature:
    return Signature(
        signature=hex_sig, key_id=key_id, alg="ed25519", created_at=datetime.now(UTC)
    )


class TestRekorBundleGoldenVector:
    def test_build_produces_expected_shape(self):
        key = _authority_key()
        raw_pubkey = key.public_key().public_bytes_raw()
        payload = sth_payload(3, "aa" * 32, datetime(2026, 9, 16, tzinfo=UTC))
        signature_bytes = key.sign(payload)
        sig = _sig(signature_bytes.hex())

        body = RekorBundle.build(payload, sig, raw_pubkey)

        assert body["apiVersion"] == "0.0.1"
        assert body["kind"] == "hashedrekord"
        assert body["spec"]["data"]["hash"]["algorithm"] == "sha256"
        assert body["spec"]["data"]["hash"]["value"] == hashlib.sha256(payload).hexdigest()
        assert base64.b64decode(body["spec"]["signature"]["content"]) == signature_bytes
        decoded_pubkey_pem = base64.b64decode(body["spec"]["signature"]["publicKey"]["content"])
        assert decoded_pubkey_pem == _ed25519_raw_to_pem(raw_pubkey)

    def test_pem_spki_matches_openssl(self):
        """The hand-assembled SPKI DER must be byte-identical to what
        ``openssl pkey -pubout`` derives for the SAME raw Ed25519 key --
        proves the hard-coded ASN.1 prefix is correct, not merely
        self-consistent."""
        key = _authority_key()
        raw_pubkey = key.public_key().public_bytes_raw()
        priv_pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())

        with tempfile.TemporaryDirectory() as d:
            priv_path = os.path.join(d, "key.pem")
            pub_path = os.path.join(d, "pub.pem")
            with open(priv_path, "wb") as f:
                f.write(priv_pem)
            subprocess.run(
                ["openssl", "pkey", "-in", priv_path, "-pubout", "-out", pub_path],
                check=True,
                capture_output=True,
            )
            with open(pub_path, "rb") as f:
                openssl_pem = f.read()

        assert _ed25519_raw_to_pem(raw_pubkey) == openssl_pem

    def test_rejects_non_32_byte_pubkey(self):
        with pytest.raises(ValueError):
            _ed25519_raw_to_pem(b"\x00" * 31)


class TestRekorPublicLogSubmit:
    def _log(self, handler) -> RekorPublicLog:
        transport = httpx.MockTransport(handler)
        client = httpx.Client(transport=transport)
        key = _authority_key()
        return RekorPublicLog(
            authority_pubkey=key.public_key().public_bytes_raw(), httpx_client=client
        )

    def test_submit_maps_canned_201_response(self):
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path == "/api/v1/log/entries"
            return httpx.Response(
                201,
                json={
                    "24296fb24b8ad77a": {
                        "logIndex": 42,
                        "integratedTime": 1758000000,
                        "verification": {"signedEntryTimestamp": "c2V0LWJ5dGVz"},
                    }
                },
            )

        log = self._log(handler)
        key = _authority_key()
        payload = sth_payload(1, "bb" * 32, datetime(2026, 9, 16, tzinfo=UTC))
        sig = _sig(key.sign(payload).hex())

        receipt = log.submit(payload, sig)
        assert receipt["uuid"] == "24296fb24b8ad77a"
        assert receipt["log_index"] == 42
        assert receipt["integrated_time"] == 1758000000
        assert receipt["signed_entry_timestamp"] == "c2V0LWJ5dGVz"
        assert receipt["log"] == "rekor-public"

    def test_submit_raises_on_500(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="internal error")

        log = self._log(handler)
        key = _authority_key()
        payload = sth_payload(1, "cc" * 32, datetime(2026, 9, 16, tzinfo=UTC))
        sig = _sig(key.sign(payload).hex())

        with pytest.raises(RuntimeError, match="Rekor submit failed"):
            log.submit(payload, sig)

    def test_submit_raises_on_empty_response(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(201, json={})

        log = self._log(handler)
        key = _authority_key()
        payload = sth_payload(1, "dd" * 32, datetime(2026, 9, 16, tzinfo=UTC))
        sig = _sig(key.sign(payload).hex())

        with pytest.raises(RuntimeError, match="empty response"):
            log.submit(payload, sig)


class TestRekorPublicLogVerify:
    def _log(self, handler) -> RekorPublicLog:
        transport = httpx.MockTransport(handler)
        client = httpx.Client(transport=transport)
        key = _authority_key()
        return RekorPublicLog(
            authority_pubkey=key.public_key().public_bytes_raw(), httpx_client=client
        )

    def test_verify_true_when_set_present_and_matches(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={"u1": {"verification": {"signedEntryTimestamp": "abc"}}},
            )

        log = self._log(handler)
        assert log.verify({"uuid": "u1", "signed_entry_timestamp": "abc"}) is True

    def test_verify_false_when_set_mismatches(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={"u1": {"verification": {"signedEntryTimestamp": "abc"}}},
            )

        log = self._log(handler)
        assert log.verify({"uuid": "u1", "signed_entry_timestamp": "different"}) is False

    def test_verify_false_when_uuid_missing_from_receipt(self):
        log = self._log(lambda r: httpx.Response(200, json={}))
        assert log.verify({}) is False

    def test_verify_false_on_404(self):
        log = self._log(lambda r: httpx.Response(404))
        assert log.verify({"uuid": "u1"}) is False

    def test_verify_false_on_missing_set(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"u1": {"verification": {}}})

        log = self._log(handler)
        assert log.verify({"uuid": "u1"}) is False


class TestAttachPublicLogWrapper:
    """``attach_public_log``'s own invariant tests -- this is the seam the
    scheduled publisher (``scheduler.py``) supersedes for production, but the
    wrapper stays the documented, directly-testable no-plaintext boundary."""

    def _anchorer(self):
        from capsule_anchor.anchoring.service import AnchorerService

        return AnchorerService()

    def test_double_attach_raises(self):
        anchorer = self._anchorer()
        attach_public_log(anchorer, InMemoryPublicLog())
        with pytest.raises(RuntimeError, match="already attached"):
            attach_public_log(anchorer, InMemoryPublicLog())

    def test_receipt_proof_populated(self):
        anchorer = self._anchorer()
        public_log = InMemoryPublicLog()
        attach_public_log(anchorer, public_log)

        receipt = anchorer.anchor("tenant-1", "aa" * 32, (0, 10))

        assert "public_log" in receipt.proof
        assert receipt.proof["public_log"]["backend"] == "in-memory"
        assert len(public_log) == 1

    def test_invariant_only_sth_payload_bytes_leave(self):
        """The exact bytes submitted to the public log must equal
        ``sth_payload(tree_size, root_hash, timestamp)`` for the anchorer's
        OWN current STH -- nothing else (no tenant root_hash, no capsule
        content) ever reaches ``public_log.submit``."""
        anchorer = self._anchorer()
        public_log = InMemoryPublicLog()
        attach_public_log(anchorer, public_log)

        anchorer.anchor("tenant-1", "bb" * 32, (0, 5))

        assert len(public_log) == 1
        submitted_payload, _sig_hex, _hash, _integrated = public_log.entries()[0]
        sth = anchorer.get_sth()
        expected = sth_payload(sth.tree_size, sth.root_hash, sth.timestamp)
        assert submitted_payload == expected
        # And the tenant's own root_hash never appears in the submitted bytes.
        assert b"bb" * 32 not in submitted_payload or "bb" * 32 == sth.root_hash


@pytest.mark.skipif(
    os.environ.get("CAPSULE_ANCHOR_TEST_LIVE_REKOR") != "1",
    reason="opt-in live test against rekor.sigstore.dev -- set CAPSULE_ANCHOR_TEST_LIVE_REKOR=1",
)
class TestLiveRekor:
    """Real network call against the public Sigstore Rekor instance. Never
    runs in normal CI -- for manual verification that the wire shape this
    module builds is actually accepted by the real service."""

    def test_submit_and_verify_against_real_rekor(self):
        key = Ed25519PrivateKey.generate()
        log = RekorPublicLog(authority_pubkey=key.public_key().public_bytes_raw())
        payload = sth_payload(1, "ee" * 32, datetime.now(UTC))
        sig = _sig(key.sign(payload).hex())
        try:
            receipt = log.submit(payload, sig)
            assert log.verify(receipt) is True
        finally:
            log.close()
