"""Append-only storage backends for the transparency log.

Three backends behind one interface:

* ``InMemoryLogStore`` — volatile default. Keeps exact prior in-memory behaviour;
  no deps, no disk; used in local dev and all CI tests that skip Postgres.
* ``SqliteLogStore`` — durable on-disk store (stdlib sqlite3). Useful for
  local durability testing; not the production path.
* ``PostgresLogStore`` — durable Cloud SQL / Postgres store (psycopg v3). The
  production backend; inject via ``CAPSULE_ANCHOR_DATABASE_URL``. Requires the
  [postgres] extra: ``pip install 'capsule-anchor[postgres]'``.

All backends implement the same interface:
  append_entry / all_entries / entries_after / size
  put_root / get_root
  put_capsule_id / get_capsule_id / entries_for_capsule
  put_statement / get_statement
  close

Only the storage of records lives here; all crypto / chain / CT semantics stay
in service.py and ct.py.
"""

from __future__ import annotations

import sqlite3
import threading
from datetime import datetime

from capsule_anchor.contracts.types import (
    CountersignedRoot,
    Signature,
    TransparencyLogEntry,
)


def _sig_to_json(sig: Signature) -> str:
    return sig.model_dump_json()


def _sig_from_json(raw: str) -> Signature:
    return Signature.model_validate_json(raw)


class InMemoryLogStore:
    """Volatile append-only store. Preserves the original in-memory behaviour."""

    def __init__(self) -> None:
        self._log: list[TransparencyLogEntry] = []
        self._roots: dict[tuple[str, str], CountersignedRoot] = {}
        # Phase 3 (tail-add): sidecar map log_index -> capsule_id, written when
        # an anchor request carried a capsule binding. Not part of the entry
        # itself (TransparencyLogEntry shape is frozen by contracts.types).
        self._capsule_ids: dict[int, str] = {}
        # Idempotent dedup: entry_hash -> (receipt_bytes, leaf_index, tree_size)
        self._statements: dict[str, tuple[bytes, int, int]] = {}

    # --- log ---
    def append_entry(self, entry: TransparencyLogEntry) -> None:
        self._log.append(entry)

    def all_entries(self) -> list[TransparencyLogEntry]:
        return list(self._log)

    def entries_after(self, after_index: int) -> list[TransparencyLogEntry]:
        return [e for e in self._log if e.log_index >= after_index]

    def size(self) -> int:
        return len(self._log)

    # --- countersigned roots ---
    def put_root(self, root: CountersignedRoot) -> None:
        self._roots[(root.tenant_id, root.root_hash)] = root

    def get_root(self, tenant_id: str, root_hash: str) -> CountersignedRoot | None:
        return self._roots.get((tenant_id, root_hash))

    # --- capsule binding (Phase 3 tail-add) ---
    def put_capsule_id(self, log_index: int, capsule_id: str) -> None:
        self._capsule_ids[log_index] = capsule_id

    def get_capsule_id(self, log_index: int) -> str | None:
        return self._capsule_ids.get(log_index)

    def entries_for_capsule(self, capsule_id: str) -> list[TransparencyLogEntry]:
        idxs = {i for i, c in self._capsule_ids.items() if c == capsule_id}
        return [e for e in self._log if e.log_index in idxs]

    # --- idempotent statement dedup ---
    def put_statement(
        self, entry_hash: str, receipt_bytes: bytes, leaf_index: int, tree_size: int
    ) -> None:
        self._statements[entry_hash] = (receipt_bytes, leaf_index, tree_size)

    def get_statement(self, entry_hash: str) -> tuple[bytes, int, int] | None:
        return self._statements.get(entry_hash)


class SqliteLogStore:
    """Durable append-only store backed by a single sqlite file.

    Append-only is enforced structurally: ``log_index`` is the PRIMARY KEY and
    we only ever INSERT (never UPDATE/DELETE) log rows. Reopening the path
    rehydrates the full log + roots, so an auditor (or the authority after a
    restart) sees identical state.
    """

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._lock = threading.Lock()
        # check_same_thread=False: appends are already serialized by the
        # service-level lock; this lets the (shared) connection be reused.
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._init_schema()

    def _init_schema(self) -> None:
        with self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS log_entries (
                    log_index     INTEGER PRIMARY KEY,
                    logged_at     TEXT NOT NULL,
                    kind          TEXT NOT NULL,
                    payload_hash  TEXT NOT NULL,
                    log_signature TEXT NOT NULL,
                    prev_log_hash TEXT
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS countersigned_roots (
                    tenant_id        TEXT NOT NULL,
                    root_hash        TEXT NOT NULL,
                    seq_from         INTEGER NOT NULL,
                    seq_to           INTEGER NOT NULL,
                    attested_at      TEXT NOT NULL,
                    countersignature TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, root_hash)
                )
                """
            )
            # Phase 3: capsule binding sidecar (additive).
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS log_capsule_bindings (
                    log_index  INTEGER PRIMARY KEY,
                    capsule_id TEXT NOT NULL
                )
                """
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_log_capsule_bindings_capsule "
                "ON log_capsule_bindings(capsule_id)"
            )
            # Idempotent dedup: one row per unique submitted statement.
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS submitted_statements (
                    entry_hash   TEXT PRIMARY KEY,
                    receipt      BLOB NOT NULL,
                    leaf_index   INTEGER NOT NULL,
                    tree_size    INTEGER NOT NULL
                )
                """
            )

    # --- row <-> model ---
    @staticmethod
    def _row_to_entry(row: tuple) -> TransparencyLogEntry:
        return TransparencyLogEntry(
            log_index=row[0],
            logged_at=datetime.fromisoformat(row[1]),
            kind=row[2],
            payload_hash=row[3],
            log_signature=_sig_from_json(row[4]),
            prev_log_hash=row[5],
        )

    # --- log ---
    def append_entry(self, entry: TransparencyLogEntry) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO log_entries "
                "(log_index, logged_at, kind, payload_hash, log_signature, "
                " prev_log_hash) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    entry.log_index,
                    entry.logged_at.isoformat(),
                    entry.kind,
                    entry.payload_hash,
                    _sig_to_json(entry.log_signature),
                    entry.prev_log_hash,
                ),
            )

    def all_entries(self) -> list[TransparencyLogEntry]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT log_index, logged_at, kind, payload_hash, log_signature, "
                "prev_log_hash FROM log_entries ORDER BY log_index ASC"
            )
            return [self._row_to_entry(r) for r in cur.fetchall()]

    def entries_after(self, after_index: int) -> list[TransparencyLogEntry]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT log_index, logged_at, kind, payload_hash, log_signature, "
                "prev_log_hash FROM log_entries WHERE log_index >= ? "
                "ORDER BY log_index ASC",
                (after_index,),
            )
            return [self._row_to_entry(r) for r in cur.fetchall()]

    def size(self) -> int:
        with self._lock:
            cur = self._conn.execute("SELECT COUNT(*) FROM log_entries")
            return int(cur.fetchone()[0])

    # --- countersigned roots ---
    def put_root(self, root: CountersignedRoot) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO countersigned_roots "
                "(tenant_id, root_hash, seq_from, seq_to, attested_at, "
                " countersignature) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    root.tenant_id,
                    root.root_hash,
                    int(root.seq_range[0]),
                    int(root.seq_range[1]),
                    root.attested_at.isoformat(),
                    _sig_to_json(root.countersignature),
                ),
            )

    def get_root(self, tenant_id: str, root_hash: str) -> CountersignedRoot | None:
        with self._lock:
            cur = self._conn.execute(
                "SELECT tenant_id, root_hash, seq_from, seq_to, attested_at, "
                "countersignature FROM countersigned_roots "
                "WHERE tenant_id = ? AND root_hash = ?",
                (tenant_id, root_hash),
            )
            row = cur.fetchone()
        if row is None:
            return None
        return CountersignedRoot(
            tenant_id=row[0],
            root_hash=row[1],
            seq_range=(row[2], row[3]),
            attested_at=datetime.fromisoformat(row[4]),
            countersignature=_sig_from_json(row[5]),
        )

    # --- capsule binding (Phase 3 tail-add) ---
    def put_capsule_id(self, log_index: int, capsule_id: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO log_capsule_bindings "
                "(log_index, capsule_id) VALUES (?, ?)",
                (int(log_index), capsule_id),
            )

    def get_capsule_id(self, log_index: int) -> str | None:
        with self._lock:
            cur = self._conn.execute(
                "SELECT capsule_id FROM log_capsule_bindings WHERE log_index = ?",
                (int(log_index),),
            )
            row = cur.fetchone()
        return None if row is None else str(row[0])

    def entries_for_capsule(self, capsule_id: str) -> list[TransparencyLogEntry]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT le.log_index, le.logged_at, le.kind, le.payload_hash, "
                "le.log_signature, le.prev_log_hash "
                "FROM log_entries le "
                "JOIN log_capsule_bindings b ON le.log_index = b.log_index "
                "WHERE b.capsule_id = ? "
                "ORDER BY le.log_index ASC",
                (capsule_id,),
            )
            return [self._row_to_entry(r) for r in cur.fetchall()]

    # --- idempotent statement dedup ---
    def put_statement(
        self, entry_hash: str, receipt_bytes: bytes, leaf_index: int, tree_size: int
    ) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT OR IGNORE INTO submitted_statements "
                "(entry_hash, receipt, leaf_index, tree_size) VALUES (?, ?, ?, ?)",
                (entry_hash, receipt_bytes, leaf_index, tree_size),
            )

    def get_statement(self, entry_hash: str) -> tuple[bytes, int, int] | None:
        with self._lock:
            cur = self._conn.execute(
                "SELECT receipt, leaf_index, tree_size FROM submitted_statements "
                "WHERE entry_hash = ?",
                (entry_hash,),
            )
            row = cur.fetchone()
        if row is None:
            return None
        return (bytes(row[0]), int(row[1]), int(row[2]))

    def close(self) -> None:
        with self._lock:
            self._conn.close()


class PostgresLogStore:
    """Durable append-only store backed by Cloud SQL Postgres (psycopg v3).

    Pass a standard ``postgresql://`` connection URL (including Cloud Run
    unix-socket form: ``postgresql://USER:PASS@/DB?host=/cloudsql/INSTANCE``).

    All four tables are created idempotently on first ``__init__``; no migration
    tool is needed for a fresh schema. Schema version bumps should add columns or
    tables with ``ALTER TABLE … ADD COLUMN IF NOT EXISTS``; never delete.

    Requires: ``pip install 'capsule-anchor[postgres]'`` (psycopg v3).

    Reconnect policy: Cloud SQL closes idle connections after ~10 min. Each
    public method catches ``OperationalError`` and reconnects once before
    retrying, so a single idle-timeout cycle is transparent to callers.
    ``_lock`` is held across the reconnect, so no concurrent operation can
    observe the stale connection.
    """

    def __init__(self, database_url: str) -> None:
        try:
            import psycopg as _psycopg
        except ImportError as exc:
            raise ImportError(
                "psycopg v3 is required for PostgresLogStore. "
                "Install it with: pip install 'capsule-anchor[postgres]'"
            ) from exc
        self._pg = _psycopg
        self._database_url = database_url
        self._lock = threading.Lock()
        # autocommit=True: explicit conn.transaction() blocks own each write;
        # reads happen outside a transaction (no read-snapshot overhead).
        self._conn = _psycopg.connect(database_url, autocommit=True)
        self._init_schema()

    # ------------------------------------------------------------------
    # Reconnect helpers — MUST be called while _lock is held.
    # ------------------------------------------------------------------

    def _reconnect(self) -> None:
        """Replace the stale connection with a fresh one."""
        try:
            self._conn.close()
        except Exception:
            pass
        self._conn = self._pg.connect(self._database_url, autocommit=True)

    def _read(self, sql: str, params: tuple = ()) -> object:
        """Execute a read query; reconnect once on closed-connection error. Called under lock."""
        try:
            return self._conn.execute(sql, params)
        except self._pg.OperationalError:
            self._reconnect()
            return self._conn.execute(sql, params)

    def _transact(self, fn: object) -> None:
        """Run fn() in a transaction; reconnect once on closed-connection error. Called under lock."""
        def _run() -> None:
            with self._conn.transaction():
                fn()  # type: ignore[operator]

        try:
            _run()
        except self._pg.OperationalError:
            self._reconnect()
            _run()

    def _init_schema(self) -> None:
        with self._lock, self._conn.transaction():
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS log_entries (
                    log_index     BIGINT PRIMARY KEY,
                    logged_at     TIMESTAMPTZ NOT NULL,
                    kind          TEXT NOT NULL,
                    payload_hash  TEXT NOT NULL,
                    log_signature TEXT NOT NULL,
                    prev_log_hash TEXT
                )
            """)
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS countersigned_roots (
                    tenant_id        TEXT NOT NULL,
                    root_hash        TEXT NOT NULL,
                    seq_from         BIGINT NOT NULL,
                    seq_to           BIGINT NOT NULL,
                    attested_at      TIMESTAMPTZ NOT NULL,
                    countersignature TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, root_hash)
                )
            """)
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS log_capsule_bindings (
                    log_index  BIGINT PRIMARY KEY,
                    capsule_id TEXT NOT NULL
                )
            """)
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_lcb_capsule "
                "ON log_capsule_bindings(capsule_id)"
            )
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS submitted_statements (
                    entry_hash  TEXT PRIMARY KEY,
                    receipt     BYTEA NOT NULL,
                    leaf_index  BIGINT NOT NULL,
                    tree_size   BIGINT NOT NULL
                )
            """)

    @staticmethod
    def _row_to_entry(row: tuple) -> TransparencyLogEntry:
        log_index, logged_at, kind, payload_hash, log_signature, prev_log_hash = row
        # psycopg3 returns timezone-aware datetime for TIMESTAMPTZ; pass through.
        return TransparencyLogEntry(
            log_index=int(log_index),
            logged_at=logged_at,
            kind=str(kind),
            payload_hash=str(payload_hash),
            log_signature=_sig_from_json(log_signature),
            prev_log_hash=str(prev_log_hash) if prev_log_hash is not None else None,
        )

    # --- log ---
    def append_entry(self, entry: TransparencyLogEntry) -> None:
        params = (
            entry.log_index,
            entry.logged_at,
            entry.kind,
            entry.payload_hash,
            _sig_to_json(entry.log_signature),
            entry.prev_log_hash,
        )
        with self._lock:
            self._transact(
                lambda: self._conn.execute(
                    "INSERT INTO log_entries "
                    "(log_index, logged_at, kind, payload_hash, log_signature, prev_log_hash) "
                    "VALUES (%s, %s, %s, %s, %s, %s)",
                    params,
                )
            )

    def all_entries(self) -> list[TransparencyLogEntry]:
        with self._lock:
            cur = self._read(
                "SELECT log_index, logged_at, kind, payload_hash, log_signature, "
                "prev_log_hash FROM log_entries ORDER BY log_index ASC"
            )
            return [self._row_to_entry(r) for r in cur.fetchall()]

    def entries_after(self, after_index: int) -> list[TransparencyLogEntry]:
        with self._lock:
            cur = self._read(
                "SELECT log_index, logged_at, kind, payload_hash, log_signature, "
                "prev_log_hash FROM log_entries WHERE log_index >= %s "
                "ORDER BY log_index ASC",
                (after_index,),
            )
            return [self._row_to_entry(r) for r in cur.fetchall()]

    def size(self) -> int:
        with self._lock:
            cur = self._read("SELECT COUNT(*) FROM log_entries")
            return int(cur.fetchone()[0])

    # --- countersigned roots ---
    def put_root(self, root: CountersignedRoot) -> None:
        params = (
            root.tenant_id,
            root.root_hash,
            int(root.seq_range[0]),
            int(root.seq_range[1]),
            root.attested_at,
            _sig_to_json(root.countersignature),
        )
        with self._lock:
            self._transact(
                lambda: self._conn.execute(
                    "INSERT INTO countersigned_roots "
                    "(tenant_id, root_hash, seq_from, seq_to, attested_at, countersignature) "
                    "VALUES (%s, %s, %s, %s, %s, %s) "
                    "ON CONFLICT (tenant_id, root_hash) DO UPDATE SET "
                    "attested_at = EXCLUDED.attested_at, "
                    "countersignature = EXCLUDED.countersignature",
                    params,
                )
            )

    def get_root(self, tenant_id: str, root_hash: str) -> CountersignedRoot | None:
        with self._lock:
            cur = self._read(
                "SELECT tenant_id, root_hash, seq_from, seq_to, attested_at, "
                "countersignature FROM countersigned_roots "
                "WHERE tenant_id = %s AND root_hash = %s",
                (tenant_id, root_hash),
            )
            row = cur.fetchone()
        if row is None:
            return None
        return CountersignedRoot(
            tenant_id=row[0],
            root_hash=row[1],
            seq_range=(int(row[2]), int(row[3])),
            attested_at=row[4],
            countersignature=_sig_from_json(row[5]),
        )

    # --- capsule binding ---
    def put_capsule_id(self, log_index: int, capsule_id: str) -> None:
        params = (int(log_index), capsule_id)
        with self._lock:
            self._transact(
                lambda: self._conn.execute(
                    "INSERT INTO log_capsule_bindings (log_index, capsule_id) "
                    "VALUES (%s, %s) ON CONFLICT (log_index) DO UPDATE SET capsule_id = EXCLUDED.capsule_id",
                    params,
                )
            )

    def get_capsule_id(self, log_index: int) -> str | None:
        with self._lock:
            cur = self._read(
                "SELECT capsule_id FROM log_capsule_bindings WHERE log_index = %s",
                (int(log_index),),
            )
            row = cur.fetchone()
        return None if row is None else str(row[0])

    def entries_for_capsule(self, capsule_id: str) -> list[TransparencyLogEntry]:
        with self._lock:
            cur = self._read(
                "SELECT le.log_index, le.logged_at, le.kind, le.payload_hash, "
                "le.log_signature, le.prev_log_hash "
                "FROM log_entries le "
                "JOIN log_capsule_bindings b ON le.log_index = b.log_index "
                "WHERE b.capsule_id = %s ORDER BY le.log_index ASC",
                (capsule_id,),
            )
            return [self._row_to_entry(r) for r in cur.fetchall()]

    # --- idempotent statement dedup ---
    def put_statement(
        self, entry_hash: str, receipt_bytes: bytes, leaf_index: int, tree_size: int
    ) -> None:
        params = (entry_hash, receipt_bytes, leaf_index, tree_size)
        with self._lock:
            self._transact(
                lambda: self._conn.execute(
                    "INSERT INTO submitted_statements "
                    "(entry_hash, receipt, leaf_index, tree_size) "
                    "VALUES (%s, %s, %s, %s) ON CONFLICT (entry_hash) DO NOTHING",
                    params,
                )
            )

    def get_statement(self, entry_hash: str) -> tuple[bytes, int, int] | None:
        with self._lock:
            cur = self._read(
                "SELECT receipt, leaf_index, tree_size FROM submitted_statements "
                "WHERE entry_hash = %s",
                (entry_hash,),
            )
            row = cur.fetchone()
        if row is None:
            return None
        return (bytes(row[0]), int(row[1]), int(row[2]))

    def close(self) -> None:
        with self._lock:
            self._conn.close()
