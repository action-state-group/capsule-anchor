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
  put_checkpoint_witness / get_checkpoint_witness
  put_checkpoint_record / get_last_checkpoint_record / get_checkpoint_equivocations
  put_sth / get_latest_sth
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
        # Checkpoint witness state: log_id -> last-witnessed checkpoint fields.
        self._checkpoint_witnesses: dict[str, dict] = {}
        # POST /checkpoints read surface: (log_id, mmr_size) -> full record,
        # one row per position ever witnessed (first-seen root wins the slot;
        # see put_checkpoint_record). log_id -> flagged equivocation events.
        self._checkpoint_records: dict[tuple[str, int], dict] = {}
        self._checkpoint_equivocations: dict[str, list[dict]] = {}
        # Latest persisted Signed Tree Head (JSON string) or None.
        self._latest_sth: str | None = None

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

    # --- checkpoint witness state ---
    def put_checkpoint_witness(
        self, log_id: str, *, mmr_size: int, mmr_root: str, key_id: str, timestamp: str
    ) -> None:
        self._checkpoint_witnesses[log_id] = {
            "mmr_size": mmr_size,
            "mmr_root": mmr_root,
            "key_id": key_id,
            "timestamp": timestamp,
        }

    def get_checkpoint_witness(self, log_id: str) -> dict | None:
        w = self._checkpoint_witnesses.get(log_id)
        return dict(w) if w is not None else None

    # --- checkpoint read-back + equivocation detection (POST /checkpoints) ---
    def put_checkpoint_record(self, log_id: str, mmr_size: int, record: dict) -> bool:
        key = (log_id, mmr_size)
        existing = self._checkpoint_records.get(key)
        if existing is None:
            self._checkpoint_records[key] = dict(record)
            return False
        if existing["root"] == record["root"]:
            return False  # idempotent resubmission of the same checkpoint
        # EQUIVOCATION: a different root already occupies this exact
        # (log_id, mmr_size) slot. Never overwrite the first-seen record --
        # it is the fork evidence -- and flag the conflict loudly.
        def _evidence(r: dict) -> dict:
            return {"root": r["root"], "entry_hash": r["entry_hash"], "timestamp": r["timestamp"]}

        self._checkpoint_equivocations.setdefault(log_id, []).append(
            {"mmr_size": mmr_size, "first": _evidence(existing), "conflicting": _evidence(record)}
        )
        return True

    def get_last_checkpoint_record(self, log_id: str) -> dict | None:
        rows = [
            {"mmr_size": size, **rec}
            for (lid, size), rec in self._checkpoint_records.items()
            if lid == log_id
        ]
        if not rows:
            return None
        return max(rows, key=lambda r: r["mmr_size"])

    def get_checkpoint_equivocations(self, log_id: str) -> list[dict]:
        return [dict(e) for e in self._checkpoint_equivocations.get(log_id, [])]

    # --- persisted Signed Tree Head ---
    def put_sth(self, sth_json: str) -> None:
        self._latest_sth = sth_json

    def get_latest_sth(self) -> str | None:
        return self._latest_sth


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
            # Singleton latest Signed Tree Head (id=1 enforced by CHECK).
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS signed_tree_heads (
                    id       INTEGER PRIMARY KEY CHECK (id = 1),
                    sth_json TEXT NOT NULL
                )
                """
            )
            # Checkpoint witness state: one row per log_id, the last-witnessed
            # checkpoint. Only ever INSERT OR REPLACE -- prior witness history
            # isn't retained, only the current chain-tip needed for the next
            # monotonic/chain-linkage check.
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS checkpoint_witnesses (
                    log_id     TEXT PRIMARY KEY,
                    mmr_size   INTEGER NOT NULL,
                    mmr_root   TEXT NOT NULL,
                    key_id     TEXT NOT NULL,
                    timestamp  TEXT NOT NULL
                )
                """
            )
            # POST /checkpoints read surface: one row per (log_id, mmr_size)
            # position ever witnessed. Only ever INSERTed, never UPDATEd --
            # the first root seen at a position is preserved as fork
            # evidence (see put_checkpoint_record, which checks-before-insert
            # under the caller's lock and never overwrites a conflicting row).
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS checkpoint_records (
                    log_id           TEXT NOT NULL,
                    mmr_size         INTEGER NOT NULL,
                    root             TEXT NOT NULL,
                    prev_size        INTEGER NOT NULL,
                    prev_root        TEXT NOT NULL,
                    key_id           TEXT NOT NULL,
                    timestamp        TEXT NOT NULL,
                    grade            TEXT,
                    entry_hash       TEXT NOT NULL,
                    entry_hash_scheme TEXT NOT NULL,
                    leaf_index       INTEGER NOT NULL,
                    tree_size        INTEGER NOT NULL,
                    receipt          BLOB NOT NULL,
                    PRIMARY KEY (log_id, mmr_size)
                )
                """
            )
            # Loud-surface evidence: appended whenever a NEW submission's
            # root conflicts with the root already recorded for the same
            # (log_id, mmr_size) -- i.e. an equivocation/fork attempt.
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS checkpoint_equivocations (
                    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
                    log_id                TEXT NOT NULL,
                    mmr_size              INTEGER NOT NULL,
                    first_root            TEXT NOT NULL,
                    first_entry_hash      TEXT NOT NULL,
                    first_timestamp       TEXT NOT NULL,
                    conflicting_root      TEXT NOT NULL,
                    conflicting_entry_hash TEXT NOT NULL,
                    conflicting_timestamp TEXT NOT NULL
                )
                """
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_checkpoint_equivocations_log_id "
                "ON checkpoint_equivocations(log_id)"
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

    # --- checkpoint witness state ---
    def put_checkpoint_witness(
        self, log_id: str, *, mmr_size: int, mmr_root: str, key_id: str, timestamp: str
    ) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO checkpoint_witnesses "
                "(log_id, mmr_size, mmr_root, key_id, timestamp) VALUES (?, ?, ?, ?, ?)",
                (log_id, int(mmr_size), mmr_root, key_id, timestamp),
            )

    def get_checkpoint_witness(self, log_id: str) -> dict | None:
        with self._lock:
            cur = self._conn.execute(
                "SELECT mmr_size, mmr_root, key_id, timestamp FROM checkpoint_witnesses "
                "WHERE log_id = ?",
                (log_id,),
            )
            row = cur.fetchone()
        if row is None:
            return None
        return {
            "mmr_size": int(row[0]),
            "mmr_root": str(row[1]),
            "key_id": str(row[2]),
            "timestamp": str(row[3]),
        }

    # --- checkpoint read-back + equivocation detection (POST /checkpoints) ---
    def put_checkpoint_record(self, log_id: str, mmr_size: int, record: dict) -> bool:
        with self._lock, self._conn:
            cur = self._conn.execute(
                "SELECT root, entry_hash, timestamp FROM checkpoint_records "
                "WHERE log_id = ? AND mmr_size = ?",
                (log_id, mmr_size),
            )
            existing = cur.fetchone()
            if existing is None:
                self._conn.execute(
                    "INSERT INTO checkpoint_records (log_id, mmr_size, root, prev_size, "
                    "prev_root, key_id, timestamp, grade, entry_hash, entry_hash_scheme, "
                    "leaf_index, tree_size, receipt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        log_id, mmr_size, record["root"], int(record["prev_size"]),
                        record["prev_root"], record["key_id"], record["timestamp"],
                        record.get("grade"), record["entry_hash"], record["entry_hash_scheme"],
                        int(record["leaf_index"]), int(record["tree_size"]), record["receipt"],
                    ),
                )
                return False
            if existing[0] == record["root"]:
                return False  # idempotent resubmission of the same checkpoint
            self._conn.execute(
                "INSERT INTO checkpoint_equivocations (log_id, mmr_size, first_root, "
                "first_entry_hash, first_timestamp, conflicting_root, conflicting_entry_hash, "
                "conflicting_timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    log_id, mmr_size, existing[0], existing[1], existing[2],
                    record["root"], record["entry_hash"], record["timestamp"],
                ),
            )
            return True

    def get_last_checkpoint_record(self, log_id: str) -> dict | None:
        with self._lock:
            cur = self._conn.execute(
                "SELECT mmr_size, root, prev_size, prev_root, key_id, timestamp, grade, "
                "entry_hash, entry_hash_scheme, leaf_index, tree_size, receipt "
                "FROM checkpoint_records WHERE log_id = ? ORDER BY mmr_size DESC LIMIT 1",
                (log_id,),
            )
            row = cur.fetchone()
        if row is None:
            return None
        return {
            "mmr_size": int(row[0]), "root": str(row[1]), "prev_size": int(row[2]),
            "prev_root": str(row[3]), "key_id": str(row[4]), "timestamp": str(row[5]),
            "grade": row[6], "entry_hash": str(row[7]), "entry_hash_scheme": str(row[8]),
            "leaf_index": int(row[9]), "tree_size": int(row[10]), "receipt": bytes(row[11]),
        }

    def get_checkpoint_equivocations(self, log_id: str) -> list[dict]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT mmr_size, first_root, first_entry_hash, first_timestamp, "
                "conflicting_root, conflicting_entry_hash, conflicting_timestamp "
                "FROM checkpoint_equivocations WHERE log_id = ? ORDER BY id ASC",
                (log_id,),
            )
            rows = cur.fetchall()
        return [
            {
                "mmr_size": int(r[0]),
                "first": {"root": str(r[1]), "entry_hash": str(r[2]), "timestamp": str(r[3])},
                "conflicting": {"root": str(r[4]), "entry_hash": str(r[5]), "timestamp": str(r[6])},
            }
            for r in rows
        ]

    # --- persisted Signed Tree Head ---
    def put_sth(self, sth_json: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO signed_tree_heads (id, sth_json) VALUES (1, ?)",
                (sth_json,),
            )

    def get_latest_sth(self) -> str | None:
        with self._lock:
            cur = self._conn.execute(
                "SELECT sth_json FROM signed_tree_heads WHERE id = 1"
            )
            row = cur.fetchone()
        return None if row is None else str(row[0])

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
        except Exception:  # noqa: BLE001, S110
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
            # Singleton latest Signed Tree Head.
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS signed_tree_heads (
                    id       INTEGER PRIMARY KEY CHECK (id = 1),
                    sth_json TEXT NOT NULL
                )
            """)
            # Checkpoint witness state: one row per log_id, the last-witnessed
            # checkpoint (chain-tip only, no history retained).
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS checkpoint_witnesses (
                    log_id     TEXT PRIMARY KEY,
                    mmr_size   BIGINT NOT NULL,
                    mmr_root   TEXT NOT NULL,
                    key_id     TEXT NOT NULL,
                    timestamp  TEXT NOT NULL
                )
            """)
            # POST /checkpoints read surface: one row per (log_id, mmr_size)
            # position ever witnessed. Only ever INSERTed, never UPDATEd --
            # the first root seen at a position is preserved as fork
            # evidence (see put_checkpoint_record).
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS checkpoint_records (
                    log_id            TEXT NOT NULL,
                    mmr_size          BIGINT NOT NULL,
                    root              TEXT NOT NULL,
                    prev_size         BIGINT NOT NULL,
                    prev_root         TEXT NOT NULL,
                    key_id            TEXT NOT NULL,
                    timestamp         TEXT NOT NULL,
                    grade             TEXT,
                    entry_hash        TEXT NOT NULL,
                    entry_hash_scheme TEXT NOT NULL,
                    leaf_index        BIGINT NOT NULL,
                    tree_size         BIGINT NOT NULL,
                    receipt           BYTEA NOT NULL,
                    PRIMARY KEY (log_id, mmr_size)
                )
            """)
            # Loud-surface evidence: appended whenever a NEW submission's
            # root conflicts with the root already recorded for the same
            # (log_id, mmr_size) -- i.e. an equivocation/fork attempt.
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS checkpoint_equivocations (
                    id                     BIGSERIAL PRIMARY KEY,
                    log_id                 TEXT NOT NULL,
                    mmr_size               BIGINT NOT NULL,
                    first_root             TEXT NOT NULL,
                    first_entry_hash       TEXT NOT NULL,
                    first_timestamp        TEXT NOT NULL,
                    conflicting_root       TEXT NOT NULL,
                    conflicting_entry_hash TEXT NOT NULL,
                    conflicting_timestamp  TEXT NOT NULL
                )
            """)
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_checkpoint_equivocations_log_id "
                "ON checkpoint_equivocations(log_id)"
            )

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

    # --- checkpoint witness state ---
    def put_checkpoint_witness(
        self, log_id: str, *, mmr_size: int, mmr_root: str, key_id: str, timestamp: str
    ) -> None:
        params = (log_id, int(mmr_size), mmr_root, key_id, timestamp)
        with self._lock:
            self._transact(
                lambda: self._conn.execute(
                    "INSERT INTO checkpoint_witnesses "
                    "(log_id, mmr_size, mmr_root, key_id, timestamp) "
                    "VALUES (%s, %s, %s, %s, %s) "
                    "ON CONFLICT (log_id) DO UPDATE SET "
                    "mmr_size = EXCLUDED.mmr_size, mmr_root = EXCLUDED.mmr_root, "
                    "key_id = EXCLUDED.key_id, timestamp = EXCLUDED.timestamp",
                    params,
                )
            )

    def get_checkpoint_witness(self, log_id: str) -> dict | None:
        with self._lock:
            cur = self._read(
                "SELECT mmr_size, mmr_root, key_id, timestamp FROM checkpoint_witnesses "
                "WHERE log_id = %s",
                (log_id,),
            )
            row = cur.fetchone()
        if row is None:
            return None
        return {
            "mmr_size": int(row[0]),
            "mmr_root": str(row[1]),
            "key_id": str(row[2]),
            "timestamp": str(row[3]),
        }

    # --- checkpoint read-back + equivocation detection (POST /checkpoints) ---
    def put_checkpoint_record(self, log_id: str, mmr_size: int, record: dict) -> bool:
        outcome = {"equivocation": False}

        def _run() -> None:
            cur = self._conn.execute(
                "INSERT INTO checkpoint_records (log_id, mmr_size, root, prev_size, "
                "prev_root, key_id, timestamp, grade, entry_hash, entry_hash_scheme, "
                "leaf_index, tree_size, receipt) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
                "ON CONFLICT (log_id, mmr_size) DO NOTHING",
                (
                    log_id, mmr_size, record["root"], int(record["prev_size"]),
                    record["prev_root"], record["key_id"], record["timestamp"],
                    record.get("grade"), record["entry_hash"], record["entry_hash_scheme"],
                    int(record["leaf_index"]), int(record["tree_size"]), record["receipt"],
                ),
            )
            if cur.rowcount:
                return  # freshly inserted -- first sighting of this position
            existing = self._conn.execute(
                "SELECT root, entry_hash, timestamp FROM checkpoint_records "
                "WHERE log_id = %s AND mmr_size = %s",
                (log_id, mmr_size),
            ).fetchone()
            if existing[0] == record["root"]:
                return  # idempotent resubmission of the same checkpoint
            # EQUIVOCATION: a different root already occupies this exact
            # (log_id, mmr_size) slot. Never overwrite the first-seen row --
            # it is the fork evidence -- and flag the conflict loudly.
            outcome["equivocation"] = True
            self._conn.execute(
                "INSERT INTO checkpoint_equivocations (log_id, mmr_size, first_root, "
                "first_entry_hash, first_timestamp, conflicting_root, conflicting_entry_hash, "
                "conflicting_timestamp) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                (
                    log_id, mmr_size, existing[0], existing[1], existing[2],
                    record["root"], record["entry_hash"], record["timestamp"],
                ),
            )

        with self._lock:
            self._transact(_run)
        return outcome["equivocation"]

    def get_last_checkpoint_record(self, log_id: str) -> dict | None:
        with self._lock:
            cur = self._read(
                "SELECT mmr_size, root, prev_size, prev_root, key_id, timestamp, grade, "
                "entry_hash, entry_hash_scheme, leaf_index, tree_size, receipt "
                "FROM checkpoint_records WHERE log_id = %s ORDER BY mmr_size DESC LIMIT 1",
                (log_id,),
            )
            row = cur.fetchone()
        if row is None:
            return None
        return {
            "mmr_size": int(row[0]), "root": str(row[1]), "prev_size": int(row[2]),
            "prev_root": str(row[3]), "key_id": str(row[4]), "timestamp": str(row[5]),
            "grade": row[6], "entry_hash": str(row[7]), "entry_hash_scheme": str(row[8]),
            "leaf_index": int(row[9]), "tree_size": int(row[10]), "receipt": bytes(row[11]),
        }

    def get_checkpoint_equivocations(self, log_id: str) -> list[dict]:
        with self._lock:
            cur = self._read(
                "SELECT mmr_size, first_root, first_entry_hash, first_timestamp, "
                "conflicting_root, conflicting_entry_hash, conflicting_timestamp "
                "FROM checkpoint_equivocations WHERE log_id = %s ORDER BY id ASC",
                (log_id,),
            )
            rows = cur.fetchall()
        return [
            {
                "mmr_size": int(r[0]),
                "first": {"root": str(r[1]), "entry_hash": str(r[2]), "timestamp": str(r[3])},
                "conflicting": {"root": str(r[4]), "entry_hash": str(r[5]), "timestamp": str(r[6])},
            }
            for r in rows
        ]

    # --- persisted Signed Tree Head ---
    def put_sth(self, sth_json: str) -> None:
        params = (sth_json,)
        with self._lock:
            self._transact(
                lambda: self._conn.execute(
                    "INSERT INTO signed_tree_heads (id, sth_json) VALUES (1, %s) "
                    "ON CONFLICT (id) DO UPDATE SET sth_json = EXCLUDED.sth_json",
                    params,
                )
            )

    def get_latest_sth(self) -> str | None:
        with self._lock:
            cur = self._read(
                "SELECT sth_json FROM signed_tree_heads WHERE id = 1"
            )
            row = cur.fetchone()
        return None if row is None else str(row[0])

    def close(self) -> None:
        with self._lock:
            self._conn.close()
