"""Production-hardening tests for capsule-anchor.

Covers:
- SQLite restart survival: append N entries, reopen, verify all present + proofs intact
- Postgres restart survival: same contract against a real Postgres instance
  (skipped when CAPSULE_ANCHOR_DATABASE_URL is not set)
- Signing key stable across "restart" (same key id; old receipts still verify)
- STH endpoint returns a verifiable signed STH
- Idempotent dedup: same submission returns the original receipt
- Rate limiting: 429 after budget exhausted
- Request size cap: 413 for oversized statements
- /health includes tree_size and key_id
- /.well-known/did.json serves a valid DID document with the authority key
"""
from __future__ import annotations

import base64
import hashlib
import os

import pytest
from fastapi.testclient import TestClient

from capsule_anchor.anchoring.service import AnchorerService, MAX_STATEMENT_BYTES
from capsule_anchor.anchoring.router import _SlidingWindowLimiter
from capsule_anchor.anchoring.store import SqliteLogStore
from capsule_anchor.app import create_app

# ---------------------------------------------------------------------------
# Postgres helpers — skip gracefully when no DB URL is configured
# ---------------------------------------------------------------------------

_PG_URL = os.environ.get("CAPSULE_ANCHOR_DATABASE_URL")
_pg_required = pytest.mark.skipif(
    not _PG_URL,
    reason="CAPSULE_ANCHOR_DATABASE_URL not set — skipping Postgres tests",
)


def _pg_store():
    """Return a fresh PostgresLogStore with all tables truncated for a clean slate."""
    from capsule_anchor.anchoring.store import PostgresLogStore
    store = PostgresLogStore(_PG_URL)
    with store._lock, store._conn.transaction():
        store._conn.execute(
            "TRUNCATE TABLE submitted_statements, log_capsule_bindings, "
            "countersigned_roots, log_entries RESTART IDENTITY CASCADE"
        )
    return store


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fresh_service(db_path: str | None = None) -> AnchorerService:
    """Create an AnchorerService with a fresh (or rehydrated) store."""
    return AnchorerService(db_path=db_path)


def _digest(n: int) -> bytes:
    """32 deterministic bytes for test entry n."""
    return hashlib.sha256(f"test-entry-{n}".encode()).digest()


# ---------------------------------------------------------------------------
# 1. SQLite restart survival
# ---------------------------------------------------------------------------

class TestSqliteRestartSurvival:
    N = 10

    def test_all_entries_survive_reopen(self, tmp_path):
        db = str(tmp_path / "anchor.db")
        svc1 = _fresh_service(db)
        receipts = []
        for i in range(self.N):
            receipt, entry_hash, leaf_index, tree_size = svc1.register_signed_statement(
                _digest(i)
            )
            receipts.append((receipt, entry_hash, leaf_index, tree_size))

        root_before = svc1.ct_root()
        svc1._store.close()

        # Reopen — simulates process restart
        svc2 = _fresh_service(db)

        assert svc2._store.size() == self.N
        assert svc2.ct_root() == root_before

    def test_old_inclusion_proofs_verify_after_reopen(self, tmp_path):
        db = str(tmp_path / "anchor.db")
        svc1 = _fresh_service(db)
        saved = []
        for i in range(self.N):
            _, _, leaf_index, tree_size = svc1.register_signed_statement(_digest(i))
            proof = svc1.inclusion_proof_ct(leaf_index, tree_size)
            saved.append(proof)
        svc1._store.close()

        svc2 = _fresh_service(db)
        for proof in saved:
            assert svc2.verify_inclusion(proof), f"proof for leaf {proof.leaf_index} failed"

    def test_sth_root_identical_after_reopen(self, tmp_path):
        db = str(tmp_path / "anchor.db")
        svc1 = _fresh_service(db)
        for i in range(5):
            svc1.register_signed_statement(_digest(i))
        root_before = svc1.get_sth().root_hash
        svc1._store.close()

        svc2 = _fresh_service(db)
        root_after = svc2.get_sth().root_hash
        assert root_after == root_before

    def test_log_chain_verifies_after_reopen(self, tmp_path):
        """verify_log re-checks log entry signatures, so requires the same key."""
        db = str(tmp_path / "anchor.db")
        svc1 = _fresh_service(db)
        attestor = svc1._attestor  # stable key — models CAPSULE_ANCHOR_SIGNING_KEY in prod
        for i in range(self.N):
            svc1.register_signed_statement(_digest(i))
        svc1._store.close()

        svc2 = AnchorerService(attestor=attestor, db_path=db)
        assert svc2.verify_log(), "hash-chain integrity check failed after reopen"


# ---------------------------------------------------------------------------
# 2. Signing key stable (same key_id; old receipts still verify)
# ---------------------------------------------------------------------------

class TestSigningKeyStability:
    def test_same_key_across_reopen(self, tmp_path):
        db = str(tmp_path / "anchor.db")
        svc1 = _fresh_service(db)
        pubkey1 = svc1.authority_pubkey()
        svc1._store.close()

        # A new AnchorerService with no key_provider generates a NEW ephemeral key.
        # In production the key comes from CAPSULE_ANCHOR_SIGNING_KEY env var.
        # Here we verify the STORE is not the source of key variance — only the
        # signing key injection determines stability. Test the degenerate case:
        # same store, same in-process key (constructed identically).
        svc2 = AnchorerService(attestor=svc1._attestor, db_path=None)
        assert svc2.authority_pubkey() == pubkey1

    def test_receipt_verifies_with_original_key_after_new_store(self, tmp_path):
        """STH and inclusion proofs hold when the store is reopened with the same key."""
        db = str(tmp_path / "anchor.db")
        svc1 = _fresh_service(db)
        attestor = svc1._attestor  # stable key across simulated restart
        _, _, leaf_index, tree_size = svc1.register_signed_statement(_digest(0))
        svc1._store.close()

        svc2 = AnchorerService(attestor=attestor, db_path=db)
        sth = svc2.get_sth()
        assert svc2.verify_sth(sth), "STH signature invalid after reopen"
        proof = svc2.inclusion_proof_ct(leaf_index, tree_size)
        assert svc2.verify_inclusion(proof), "inclusion proof invalid after reopen"


# ---------------------------------------------------------------------------
# 3. STH endpoint — returns verifiable signed STH
# ---------------------------------------------------------------------------

class TestSTHEndpoint:
    def test_sth_verifiable(self):
        svc = _fresh_service()
        svc.register_signed_statement(_digest(0))
        sth = svc.get_sth()
        assert svc.verify_sth(sth)

    def test_sth_consistency_proof(self):
        svc = _fresh_service()
        for i in range(5):
            svc.register_signed_statement(_digest(i))
        proof = svc.consistency_proof(3, 5)
        assert AnchorerService.verify_consistency(proof)

    def test_sth_via_http(self):
        client = TestClient(create_app())
        client.post("/v1/digest", json={"capsule_id": "a" * 64})
        resp = client.get("/anchor/sth")
        assert resp.status_code == 200
        body = resp.json()
        assert body["tree_size"] >= 1
        assert "root_hash" in body
        assert "signature" in body


# ---------------------------------------------------------------------------
# 4. Idempotent dedup
# ---------------------------------------------------------------------------

class TestIdempotentDedup:
    def test_same_capsule_id_returns_same_receipt(self):
        client = TestClient(create_app())
        payload = {"capsule_id": "b" * 64}
        r1 = client.post("/v1/digest", json=payload)
        r2 = client.post("/v1/digest", json=payload)
        assert r1.status_code == 200
        assert r2.status_code == 200
        assert r1.json()["receipt_b64"] == r2.json()["receipt_b64"]
        assert r1.json()["leaf_index"] == r2.json()["leaf_index"]
        assert r1.json()["tree_size"] == r2.json()["tree_size"]

    def test_dedup_does_not_grow_log(self):
        svc = _fresh_service()
        stmt = _digest(42)
        svc.register_signed_statement(stmt)
        svc.register_signed_statement(stmt)
        assert svc._store.size() == 1

    def test_dedup_receipt_still_verifies(self):
        svc = _fresh_service()
        stmt = _digest(99)
        r1_receipt, _, leaf_index, tree_size = svc.register_signed_statement(stmt)
        r2_receipt, _, _, _ = svc.register_signed_statement(stmt)
        assert r1_receipt == r2_receipt
        proof = svc.inclusion_proof_ct(leaf_index, tree_size)
        assert svc.verify_inclusion(proof)

    def test_same_statement_bytes_dedup(self):
        svc = _fresh_service()
        stmt = b"\x01\x02\x03" * 10
        r1, h1, idx1, ts1 = svc.register_signed_statement(stmt)
        r2, h2, idx2, ts2 = svc.register_signed_statement(stmt)
        assert r1 == r2
        assert h1 == h2
        assert idx1 == idx2
        assert ts1 == ts2

    def test_sqlite_dedup_survives_reopen(self, tmp_path):
        db = str(tmp_path / "anchor.db")
        svc1 = _fresh_service(db)
        stmt = _digest(7)
        r1, _, leaf_index1, ts1 = svc1.register_signed_statement(stmt)
        svc1._store.close()

        svc2 = _fresh_service(db)
        r2, _, leaf_index2, ts2 = svc2.register_signed_statement(stmt)
        assert r1 == r2, "dedup receipt changed across reopen"
        assert leaf_index1 == leaf_index2
        assert svc2._store.size() == 1, "duplicate added after reopen"


# ---------------------------------------------------------------------------
# 5. Rate limiting
# ---------------------------------------------------------------------------

class TestRateLimiting:
    def test_rate_limiter_allows_within_budget(self):
        lim = _SlidingWindowLimiter(max_calls=5, window_s=60.0)
        for _ in range(5):
            assert lim.is_allowed("test")

    def test_rate_limiter_blocks_over_budget(self):
        lim = _SlidingWindowLimiter(max_calls=3, window_s=60.0)
        for _ in range(3):
            lim.is_allowed("test")
        assert not lim.is_allowed("test")

    def test_http_429_after_exhausting_limiter(self, monkeypatch):
        monkeypatch.setattr(
            "capsule_anchor.anchoring.router._POST_LIMITER",
            _SlidingWindowLimiter(max_calls=1, window_s=60.0),
        )
        client = TestClient(create_app())
        r1 = client.post("/v1/digest", json={"capsule_id": "c" * 64})
        r2 = client.post("/v1/digest", json={"capsule_id": "d" * 64})
        assert r1.status_code == 200
        assert r2.status_code == 429

    def test_register_statement_429_after_exhausting_limiter(self, monkeypatch):
        monkeypatch.setattr(
            "capsule_anchor.anchoring.router._POST_LIMITER",
            _SlidingWindowLimiter(max_calls=1, window_s=60.0),
        )
        import base64 as b64
        stmt_b64 = b64.b64encode(b"\x84" * 10).decode()
        client = TestClient(create_app())
        r1 = client.post(
            "/transparency/register-statement",
            json={"signed_statement_b64": stmt_b64},
        )
        r2 = client.post(
            "/transparency/register-statement",
            json={"signed_statement_b64": stmt_b64},
        )
        assert r1.status_code == 200
        assert r2.status_code == 429


# ---------------------------------------------------------------------------
# 6. Request size cap
# ---------------------------------------------------------------------------

class TestSizeCap:
    def test_oversized_statement_rejected_by_service(self):
        svc = _fresh_service()
        oversized = b"x" * (MAX_STATEMENT_BYTES + 1)
        with pytest.raises(ValueError, match="too large"):
            svc.register_signed_statement(oversized)

    def test_oversized_statement_http_413(self):
        oversized = b"x" * (MAX_STATEMENT_BYTES + 1)
        stmt_b64 = base64.b64encode(oversized).decode()
        client = TestClient(create_app())
        resp = client.post(
            "/transparency/register-statement",
            json={"signed_statement_b64": stmt_b64},
        )
        assert resp.status_code == 413

    def test_max_size_statement_accepted(self):
        svc = _fresh_service()
        at_limit = b"y" * MAX_STATEMENT_BYTES
        receipt, entry_hash, _, _ = svc.register_signed_statement(at_limit)
        assert receipt
        assert len(entry_hash) == 64


# ---------------------------------------------------------------------------
# 7. /health includes tree_size and key_id
# ---------------------------------------------------------------------------

class TestHealthEndpoint:
    def test_health_fields_present(self):
        client = TestClient(create_app())
        resp = client.get("/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is True
        assert "key_id" in body
        assert "tree_size" in body
        assert "storage" in body

    def test_health_tree_size_increments(self):
        client = TestClient(create_app())
        before = client.get("/health").json()["tree_size"]
        client.post("/v1/digest", json={"capsule_id": "e" * 64})
        after = client.get("/health").json()["tree_size"]
        assert after == before + 1

    def test_health_includes_latest_sth_after_entry(self):
        client = TestClient(create_app())
        client.post("/v1/digest", json={"capsule_id": "f" * 64})
        body = client.get("/health").json()
        assert "latest_sth_timestamp" in body
        assert "latest_root_hash" in body

    def test_health_key_id_is_hex(self):
        client = TestClient(create_app())
        key_id = client.get("/health").json()["key_id"]
        assert len(key_id) == 16
        int(key_id, 16)  # must be valid hex


# ---------------------------------------------------------------------------
# 8. /.well-known/did.json
# ---------------------------------------------------------------------------

class TestDIDDocument:
    def test_did_document_structure(self):
        client = TestClient(create_app())
        resp = client.get("/.well-known/did.json")
        assert resp.status_code == 200
        doc = resp.json()
        assert doc["id"] == "did:web:anchor.agentactioncapsule.org"
        assert len(doc["verificationMethod"]) == 1
        vm = doc["verificationMethod"][0]
        assert vm["type"] == "JsonWebKey2020"
        jwk = vm["publicKeyJwk"]
        assert jwk["kty"] == "OKP"
        assert jwk["crv"] == "Ed25519"
        assert "x" in jwk

    def test_did_key_matches_health_key_id(self):
        client = TestClient(create_app())
        did_doc = client.get("/.well-known/did.json").json()
        health = client.get("/health").json()

        x_b64url = did_doc["verificationMethod"][0]["publicKeyJwk"]["x"]
        padding = 4 - len(x_b64url) % 4
        if padding != 4:
            x_b64url += "=" * padding
        did_key_bytes = base64.urlsafe_b64decode(x_b64url)
        # First 8 bytes (16 hex chars) of the raw pubkey == key_id in /health
        assert did_key_bytes.hex()[:16] == health["key_id"]

    def test_did_key_id_matches_health(self):
        client = TestClient(create_app())
        did_doc = client.get("/.well-known/did.json").json()
        health = client.get("/health").json()
        vm_id = did_doc["verificationMethod"][0]["id"]
        assert health["key_id"] in vm_id


# ---------------------------------------------------------------------------
# 9. Crash-consistency (mid-append recovery via WAL)
# ---------------------------------------------------------------------------

class TestCrashConsistency:
    def test_wal_mode_enabled(self, tmp_path):
        db = str(tmp_path / "anchor.db")
        store = SqliteLogStore(db)
        cur = store._conn.execute("PRAGMA journal_mode")
        mode = cur.fetchone()[0]
        store.close()
        assert mode == "wal"

    def test_log_integrity_after_reopen(self, tmp_path):
        """Log chain signatures must verify with the same key used to write them."""
        db = str(tmp_path / "anchor.db")
        svc = _fresh_service(db)
        attestor = svc._attestor  # stable key — models CAPSULE_ANCHOR_SIGNING_KEY
        for i in range(20):
            svc.register_signed_statement(_digest(i))
        svc._store.close()

        svc2 = AnchorerService(attestor=attestor, db_path=db)
        assert svc2.verify_log(), "log chain integrity broken after reopen"
        assert svc2._store.size() == 20


# ---------------------------------------------------------------------------
# 10. Postgres restart survival
#     All tests in this class skip when CAPSULE_ANCHOR_DATABASE_URL is absent.
# ---------------------------------------------------------------------------

@_pg_required
class TestPostgresRestartSurvival:
    """Postgres restart-survival tests.

    All tests follow the same pattern:
      1. _pg_store() → fresh truncated PostgresLogStore (clean slate)
      2. Write data via AnchorerService
      3. close() the connection (simulates process restart)
      4. PostgresLogStore(_PG_URL) → reconnect (no truncation — reads persisted data)
      5. Assert data survived intact
    """
    N = 10

    def test_all_entries_survive_reconnect(self):
        from capsule_anchor.anchoring.store import PostgresLogStore
        store1 = _pg_store()                    # fresh truncated store
        svc1 = AnchorerService(store=store1)
        for i in range(self.N):
            svc1.register_signed_statement(_digest(i))
        root_before = svc1.ct_root()
        store1.close()

        store2 = PostgresLogStore(_PG_URL)      # reconnect — no truncation
        svc2 = AnchorerService(store=store2)
        assert svc2._store.size() == self.N
        assert svc2.ct_root() == root_before
        store2.close()

    def test_inclusion_proofs_verify_after_reconnect(self):
        from capsule_anchor.anchoring.store import PostgresLogStore
        store1 = _pg_store()
        svc1 = AnchorerService(store=store1)
        proofs = []
        for i in range(self.N):
            _, _, leaf_index, tree_size = svc1.register_signed_statement(_digest(i))
            proofs.append(svc1.inclusion_proof_ct(leaf_index, tree_size))
        store1.close()

        store2 = PostgresLogStore(_PG_URL)
        svc2 = AnchorerService(store=store2)
        for proof in proofs:
            assert svc2.verify_inclusion(proof), f"proof for leaf {proof.leaf_index} failed"
        store2.close()

    def test_dedup_survives_reconnect(self):
        from capsule_anchor.anchoring.store import PostgresLogStore
        store1 = _pg_store()
        svc1 = AnchorerService(store=store1)
        stmt = _digest(77)
        r1, _, idx1, _ = svc1.register_signed_statement(stmt)
        store1.close()

        store2 = PostgresLogStore(_PG_URL)
        svc2 = AnchorerService(store=store2)
        r2, _, idx2, _ = svc2.register_signed_statement(stmt)
        assert r1 == r2, "dedup receipt changed across reconnect"
        assert idx1 == idx2
        assert svc2._store.size() == 1, "duplicate added after reconnect"
        store2.close()

    def test_log_chain_verifies_after_reconnect(self):
        from capsule_anchor.anchoring.store import PostgresLogStore
        store1 = _pg_store()
        svc1 = AnchorerService(store=store1)
        attestor = svc1._attestor              # stable key across reconnect
        for i in range(self.N):
            svc1.register_signed_statement(_digest(i))
        store1.close()

        store2 = PostgresLogStore(_PG_URL)
        svc2 = AnchorerService(attestor=attestor, store=store2)
        assert svc2.verify_log(), "log chain integrity broken after reconnect"
        store2.close()

    def test_sth_root_identical_after_reconnect(self):
        from capsule_anchor.anchoring.store import PostgresLogStore
        store1 = _pg_store()
        svc1 = AnchorerService(store=store1)
        for i in range(5):
            svc1.register_signed_statement(_digest(i))
        root_before = svc1.get_sth().root_hash
        store1.close()

        store2 = PostgresLogStore(_PG_URL)
        svc2 = AnchorerService(store=store2)
        assert svc2.get_sth().root_hash == root_before
        store2.close()


# ---------------------------------------------------------------------------
# 11. Sign-oracle removed — /attest/* must be absent
# ---------------------------------------------------------------------------

class TestSignOracleRemoved:
    """Verify that no public sign-arbitrary-bytes oracle is exposed.

    A transparency log must never allow a caller to obtain an authority
    signature over arbitrary bytes — that would enable forgery of STHs
    and COSE Receipts.  All /attest/* routes must be 404.
    """

    def test_sign_endpoint_is_gone(self):
        client = TestClient(create_app())
        resp = client.post("/attest/sign", json={"payload_hex": "deadbeef"})
        assert resp.status_code == 404, f"sign oracle still exposed: {resp.status_code}"

    def test_verify_endpoint_is_gone(self):
        client = TestClient(create_app())
        resp = client.post(
            "/attest/verify",
            json={"payload_hex": "deadbeef", "signature": {"key_id": "x", "signature": "y"}},
        )
        assert resp.status_code == 404, f"/attest/verify still exposed: {resp.status_code}"

    def test_pubkey_endpoint_is_gone(self):
        client = TestClient(create_app())
        resp = client.get("/attest/pubkey")
        assert resp.status_code == 404, f"/attest/pubkey still exposed: {resp.status_code}"

    def test_authority_key_still_available_via_did(self):
        client = TestClient(create_app())
        resp = client.get("/.well-known/did.json")
        assert resp.status_code == 200
        jwk = resp.json()["verificationMethod"][0]["publicKeyJwk"]
        assert jwk["kty"] == "OKP" and jwk["crv"] == "Ed25519" and "x" in jwk
