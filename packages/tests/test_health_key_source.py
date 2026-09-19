# SPDX-License-Identifier: Apache-2.0
"""``/health`` must report only the signing key's SOURCE SCHEME
(``"env"`` | ``"file"`` | ``"generated"``), never the key-file PATH
([countersign-fixsoon-security] item 4, NOTE).

``signing_key.load_signing_key`` returns ``source=f"file:{key_file}"`` for
the file case -- the raw value a naive ``/health`` handler would leak."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from capsule_anchor.app import create_app
from capsule_anchor.signing_key import signing_key_seed_hex


def test_health_signing_key_source_is_scheme_only_for_file(monkeypatch, tmp_path):
    key_file = tmp_path / "secret-mount" / "signing-key.hex"
    key_file.parent.mkdir()
    key_file.write_text(signing_key_seed_hex(Ed25519PrivateKey.generate()))

    monkeypatch.setenv("CAPSULE_ANCHOR_INSECURE_IN_MEMORY", "1")
    monkeypatch.delenv("CAPSULE_ANCHOR_SIGNING_KEY", raising=False)
    monkeypatch.setenv("CAPSULE_ANCHOR_SIGNING_KEY_FILE", str(key_file))

    client = TestClient(create_app())
    source = client.get("/health").json()["signing_key_source"]
    assert source == "file"
    assert "/" not in source
    assert str(key_file) not in source


def test_health_signing_key_source_is_scheme_only_for_env(monkeypatch):
    monkeypatch.setenv("CAPSULE_ANCHOR_INSECURE_IN_MEMORY", "1")
    monkeypatch.delenv("CAPSULE_ANCHOR_SIGNING_KEY_FILE", raising=False)
    monkeypatch.setenv("CAPSULE_ANCHOR_SIGNING_KEY", signing_key_seed_hex(Ed25519PrivateKey.generate()))

    client = TestClient(create_app())
    source = client.get("/health").json()["signing_key_source"]
    assert source == "env"
    assert "/" not in source


def test_health_signing_key_source_is_scheme_only_for_generated(monkeypatch):
    monkeypatch.setenv("CAPSULE_ANCHOR_INSECURE_IN_MEMORY", "1")
    monkeypatch.setenv("CAPSULE_ANCHOR_INSECURE_EPHEMERAL_KEY", "1")
    monkeypatch.delenv("CAPSULE_ANCHOR_SIGNING_KEY", raising=False)
    monkeypatch.delenv("CAPSULE_ANCHOR_SIGNING_KEY_FILE", raising=False)

    client = TestClient(create_app())
    source = client.get("/health").json()["signing_key_source"]
    assert source == "generated"
    assert "/" not in source
