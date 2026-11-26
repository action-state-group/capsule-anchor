"""Test environment defaults.

Sets the explicit dev escape hatches so existing tests can call create_app()
without a real Postgres URL or a configured signing key.  The fail-closed
tests in TestFailClosed use monkeypatch to temporarily remove these variables.

Postgres: the suite never uses a ``CAPSULE_ANCHOR_DATABASE_URL`` inherited
from the shell, which may name a real witness database. Set
``CAPSULE_ANCHOR_TEST_DATABASE_URL`` to a database for tests instead; each
test then runs against an empty schema of its own there
(``_postgres_schema_per_test`` below, capsule-anchor#114).
"""
import os

import pytest

from .pg_isolation import (
    TEST_DATABASE_URL,
    close_for_good,
    create_test_schema,
    drop_test_schema,
)

os.environ.setdefault("CAPSULE_ANCHOR_INSECURE_EPHEMERAL_KEY", "1")
os.environ.setdefault("CAPSULE_ANCHOR_INSECURE_IN_MEMORY", "1")
# The canonical public host, matching the real deployed value -- there is no
# safe default (see [anchor-did-from-host]), so tests must set one explicitly.
os.environ.setdefault("CAPSULE_ANCHOR_PUBLIC_HOST", "witness.agentactioncapsule.org")
# Every create_app() starts an STH refresh thread that outlives its test; keep
# it asleep for the length of a run so it never signs into a later test.
os.environ.setdefault("CAPSULE_ANCHOR_STH_REFRESH_INTERVAL", "86400")
os.environ.pop("CAPSULE_ANCHOR_DATABASE_URL", None)


@pytest.fixture(autouse=True)
def _postgres_schema_per_test(monkeypatch):
    """With a test database set, run each test against a fresh empty schema.

    Without this, state from one test reaches the next (a tree head signed
    under an earlier test's key, a log bound to an earlier test's checkpoint
    key), and every app the suite builds keeps its connection open until
    Postgres refuses new clients.
    """
    if TEST_DATABASE_URL is None:
        yield
        return

    from capsule_anchor.anchoring.store import PostgresLogStore

    schema, schema_url = create_test_schema(TEST_DATABASE_URL)
    monkeypatch.setenv("CAPSULE_ANCHOR_DATABASE_URL", schema_url)
    opened = []
    original_init = PostgresLogStore.__init__

    def _tracking_init(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        opened.append(self)

    monkeypatch.setattr(PostgresLogStore, "__init__", _tracking_init)
    try:
        yield
    finally:
        for store in opened:
            close_for_good(store)
        drop_test_schema(TEST_DATABASE_URL, schema)
