"""The per-test Postgres isolation itself (capsule-anchor#114).

Runs only with ``CAPSULE_ANCHOR_TEST_DATABASE_URL`` set; see ``conftest.py``.
"""
from __future__ import annotations

import os
import time

import pytest
from capsule_anchor.app import create_app
from fastapi.testclient import TestClient

from .pg_isolation import (
    SCHEMA_PREFIX,
    TEST_DATABASE_URL,
    close_for_good,
    create_test_schema,
    drop_test_schema,
)

pytestmark = pytest.mark.skipif(
    TEST_DATABASE_URL is None,
    reason="CAPSULE_ANCHOR_TEST_DATABASE_URL not set — skipping Postgres tests",
)


def _connect(url):
    import psycopg

    return psycopg.connect(url, autocommit=True)


def test_each_test_starts_on_an_empty_schema_of_its_own():
    url = os.environ["CAPSULE_ANCHOR_DATABASE_URL"]
    with _connect(url) as conn:
        schema = conn.execute("SELECT current_schema()").fetchone()[0]
        tables = conn.execute(
            "SELECT count(*) FROM pg_tables WHERE schemaname = %s", (schema,)
        ).fetchone()[0]
    assert schema.startswith(SCHEMA_PREFIX)
    assert tables == 0


def test_the_app_under_test_writes_into_the_tests_schema():
    client = TestClient(create_app())
    assert client.post("/v1/digest", json={"capsule_id": "7" * 64}).status_code == 200
    with _connect(os.environ["CAPSULE_ANCHOR_DATABASE_URL"]) as conn:
        assert conn.execute("SELECT count(*) FROM log_entries").fetchone()[0] == 1


def test_a_closed_store_cannot_reconnect_and_holds_no_connection():
    """An app's STH refresh thread calls store.size() whenever it wakes; once
    teardown closed the store, that call must fail, not open a connection."""
    from capsule_anchor.anchoring.store import PostgresLogStore

    store = PostgresLogStore(os.environ["CAPSULE_ANCHOR_DATABASE_URL"])
    backend_pid = store._conn.info.backend_pid
    close_for_good(store)
    with pytest.raises(RuntimeError, match="closed at teardown"):
        store.size()
    assert store._conn.closed
    with _connect(TEST_DATABASE_URL) as conn:
        # The server ends a backend shortly after its client goes away.
        deadline = time.monotonic() + 5
        while conn.execute(
            "SELECT count(*) FROM pg_stat_activity WHERE pid = %s", (backend_pid,)
        ).fetchone()[0]:
            assert time.monotonic() < deadline, "the closed store's backend is still connected"
            time.sleep(0.05)


def test_schema_cycle_leaves_other_schemas_alone():
    keep, _ = create_test_schema(TEST_DATABASE_URL)
    try:
        with _connect(TEST_DATABASE_URL) as conn:
            conn.execute(f'CREATE TABLE "{keep}".sentinel (v int)')
            conn.execute(f'INSERT INTO "{keep}".sentinel VALUES (1)')
        schema, _ = create_test_schema(TEST_DATABASE_URL)
        drop_test_schema(TEST_DATABASE_URL, schema)
        with _connect(TEST_DATABASE_URL) as conn:
            assert conn.execute(f'SELECT v FROM "{keep}".sentinel').fetchall() == [(1,)]
            assert conn.execute(
                "SELECT count(*) FROM pg_namespace WHERE nspname = %s", (schema,)
            ).fetchone()[0] == 0
    finally:
        drop_test_schema(TEST_DATABASE_URL, keep)


def test_drop_refuses_a_schema_this_suite_did_not_create():
    with pytest.raises(ValueError, match="did not create"):
        drop_test_schema(TEST_DATABASE_URL, "public")


def test_a_schema_url_keeps_the_pgoptions_settings(monkeypatch):
    """scripts/check.sh bounds statements through PGOPTIONS; the schema URL's
    own options parameter must not drop that bound."""
    monkeypatch.setenv("PGOPTIONS", "-c statement_timeout=1500ms")
    schema, url = create_test_schema(TEST_DATABASE_URL)
    try:
        with _connect(url) as conn:
            assert conn.execute("SHOW statement_timeout").fetchone()[0] == "1500ms"
            assert conn.execute("SELECT current_schema()").fetchone()[0] == schema
    finally:
        drop_test_schema(TEST_DATABASE_URL, schema)
