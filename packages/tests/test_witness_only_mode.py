"""Tests for the WITNESS_ONLY deployment mode.

WITNESS_ONLY=1 turns capsule-anchor into a genuinely checkpoint-only
deployment: only ``POST /v1/checkpoint``, ``GET /health``/``healthz``/
``livez``, ``GET /.well-known/*``, and ``GET /anchor/authority-pubkey`` are
served. Every other route -- including every open-registration surface
(``/v1/digest``, ``/transparency/register-statement``, ``/v1/inclusion/*``,
``/anchor/*`` browse/inspect routes) -- is refused with a single named
rejection. Unset (the default), every route works exactly as before:
this mode must be strictly additive/backward compatible.
"""
from __future__ import annotations

import hashlib
import json

from capsule_anchor.app import create_app
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient


def _signing_body(cp: dict) -> bytes:
    fields = (
        "v",
        "kind",
        "log_id",
        "mmr_size",
        "root",
        "prev_size",
        "prev_root",
        "key_id",
        "timestamp",
    )
    body = {k: cp[k] for k in fields}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def _digest(cp: dict) -> str:
    return hashlib.sha256(_signing_body(cp)).hexdigest()


def _checkpoint(key: Ed25519PrivateKey, *, log_id: str) -> dict:
    cp = {
        "v": 1,
        "kind": "mmr_checkpoint",
        "log_id": log_id,
        "mmr_size": 100,
        "root": "a" * 64,
        "prev_size": 0,
        "prev_root": "",
        "key_id": key.public_key().public_bytes_raw().hex(),
        "timestamp": "2026-08-26T00:00:00Z",
    }
    digest = _digest(cp)
    cp["signature"] = key.sign(digest.encode("ascii")).hex()
    return cp


def test_witness_only_rejects_digest_but_serves_checkpoint(monkeypatch):
    monkeypatch.setenv("WITNESS_ONLY", "1")
    client = TestClient(create_app())
    key = Ed25519PrivateKey.generate()

    digest_resp = client.post("/v1/digest", json={"capsule_id": "b" * 64})
    assert digest_resp.status_code in (403, 404), digest_resp.text
    assert "witness" in digest_resp.json()["detail"].lower()

    cp = _checkpoint(key, log_id="log-witness-only-A")
    checkpoint_resp = client.post("/v1/checkpoint", json=cp)
    assert checkpoint_resp.status_code == 200, checkpoint_resp.text


def test_witness_only_rejects_open_registration_and_browse_routes(monkeypatch):
    monkeypatch.setenv("WITNESS_ONLY", "1")
    client = TestClient(create_app())

    rejected = [
        ("POST", "/transparency/register-statement", {"signed_statement_b64": ""}),
        ("GET", "/v1/inclusion/" + "c" * 64, None),
        ("GET", "/anchor/transparency-log", None),
        ("GET", "/anchor/sth", None),
    ]
    for method, path, body in rejected:
        resp = client.request(method, path, json=body)
        assert resp.status_code in (403, 404), f"{method} {path} -> {resp.status_code}: {resp.text}"
        assert "witness" in resp.json()["detail"].lower()


def test_witness_only_serves_health_and_well_known_and_pubkey(monkeypatch):
    monkeypatch.setenv("WITNESS_ONLY", "1")
    client = TestClient(create_app())

    assert client.get("/health").status_code == 200
    assert client.get("/.well-known/did.json").status_code == 200
    assert client.get("/anchor/authority-pubkey").status_code == 200


def test_witness_only_unset_serves_every_route_as_before(monkeypatch):
    monkeypatch.delenv("WITNESS_ONLY", raising=False)
    client = TestClient(create_app())
    key = Ed25519PrivateKey.generate()

    digest_resp = client.post("/v1/digest", json={"capsule_id": "d" * 64})
    assert digest_resp.status_code == 200, digest_resp.text

    cp = _checkpoint(key, log_id="log-witness-only-B")
    checkpoint_resp = client.post("/v1/checkpoint", json=cp)
    assert checkpoint_resp.status_code == 200, checkpoint_resp.text
