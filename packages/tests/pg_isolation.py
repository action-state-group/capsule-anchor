"""Per-test Postgres isolation for the suite.

Postgres-backed tests run only when ``CAPSULE_ANCHOR_TEST_DATABASE_URL`` names
a database. Each test then gets a schema of its own in that database, created
empty before the test and dropped after it, and the app under test reaches it
through ``CAPSULE_ANCHOR_DATABASE_URL`` (see ``conftest.py``). Nothing outside
the schemas created here is read, changed or deleted.
"""
from __future__ import annotations

import os
import uuid

#: The database for Postgres-backed tests, or None to run them in memory only.
TEST_DATABASE_URL = os.environ.get("CAPSULE_ANCHOR_TEST_DATABASE_URL") or None

SCHEMA_PREFIX = "capsule_anchor_test_"


def create_test_schema(database_url: str) -> tuple[str, str]:
    """Create an empty schema; return its name and a URL whose search_path is it.

    The store names its tables without a schema, so the search_path decides
    where they are created and read.
    """
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import make_conninfo

    schema = f"{SCHEMA_PREFIX}{uuid.uuid4().hex}"
    with psycopg.connect(database_url, autocommit=True) as conn:
        conn.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
    # An explicit options parameter replaces libpq's PGOPTIONS default, so keep
    # whatever PGOPTIONS sets (scripts/check.sh bounds statements with it).
    options = " ".join(filter(None, [os.environ.get("PGOPTIONS"), f"-c search_path={schema}"]))
    return schema, make_conninfo(database_url, options=options)


def drop_test_schema(database_url: str, schema: str) -> None:
    """Drop a schema made by ``create_test_schema`` and everything in it."""
    import psycopg
    from psycopg import sql

    if not schema.startswith(SCHEMA_PREFIX):
        raise ValueError(f"refusing to drop a schema this suite did not create: {schema!r}")
    with psycopg.connect(database_url, autocommit=True) as conn:
        conn.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))


def close_for_good(store) -> None:
    """Close a PostgresLogStore so that nothing can reopen it.

    The store reconnects on a closed connection (its idle-timeout policy), so
    an app's background thread that wakes after the test would otherwise open
    a new connection and write into whatever runs next.
    """
    def _refuse_reconnect() -> None:
        raise RuntimeError("this test's PostgresLogStore was closed at teardown")

    store._reconnect = _refuse_reconnect
    store.close()
