"""The per-test Postgres isolation itself (capsule-anchor#114).

Runs only with ``CAPSULE_ANCHOR_TEST_DATABASE_URL`` set; see ``conftest.py``.
"""
from __future__ import annotations

import os
import uuid

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


def _connections_to_test_database() -> int:
    with _connect(TEST_DATABASE_URL) as conn:
        return conn.execute(
            "SELECT count(*) FROM pg_stat_activity "
            "WHERE datname = current_database() AND pid <> pg_backend_pid()"
        ).fetchone()[0]


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

    before = _connections_to_test_database()
    store = PostgresLogStore(os.environ["CAPSULE_ANCHOR_DATABASE_URL"])
    assert _connections_to_test_database() == before + 1
    close_for_good(store)
    with pytest.raises(RuntimeError, match="closed at teardown"):
        store.size()
    assert _connections_to_test_database() == before


def test_schema_cycle_leaves_everything_else_in_the_database_alone():
    sentinel = f"sentinel_{uuid.uuid4().hex}"
    with _connect(TEST_DATABASE_URL) as conn:
        conn.execute(f"CREATE TABLE public.{sentinel} (v int)")
        conn.execute(f"INSERT INTO public.{sentinel} VALUES (1)")
    try:
        schema, _ = create_test_schema(TEST_DATABASE_URL)
        drop_test_schema(TEST_DATABASE_URL, schema)
        with _connect(TEST_DATABASE_URL) as conn:
            assert conn.execute(f"SELECT v FROM public.{sentinel}").fetchall() == [(1,)]
            assert conn.execute(
                "SELECT count(*) FROM pg_namespace WHERE nspname = %s", (schema,)
            ).fetchone()[0] == 0
    finally:
        with _connect(TEST_DATABASE_URL) as conn:
            conn.execute(f"DROP TABLE public.{sentinel}")


def test_drop_refuses_a_schema_this_suite_did_not_create():
    with pytest.raises(ValueError, match="did not create"):
        drop_test_schema(TEST_DATABASE_URL, "public")
