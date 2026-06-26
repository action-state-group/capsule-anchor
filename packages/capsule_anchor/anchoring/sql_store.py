"""SQLAlchemy-Core-backed transparency-log store (Postgres / Cloud SQL).

Account-portable durable backend for the anchoring subsystem's append-only CT
log. Mirrors the interface of ``InMemoryLogStore`` / ``SqliteLogStore`` exactly
so ``AnchorerService`` swaps backend by construction only.

Speaks any SQLAlchemy URL: ``postgresql+psycopg://...`` in production (Cloud
SQL) and ``sqlite://`` in tests/CI, so the Postgres code path is exercised
without a live server. Append-only is enforced structurally — ``log_index`` is
the PRIMARY KEY and rows are only ever INSERTed.

Requires the ``[postgres]`` extra (SQLAlchemy >= 2.0); imported lazily.
"""

from __future__ import annotations

import threading
from datetime import datetime

from capsule_anchor.contracts.types import (
    CountersignedRoot,
    Signature,
    TransparencyLogEntry,
)


def _require_sqlalchemy():
    try:
        import sqlalchemy as sa  # noqa: F401
    except ModuleNotFoundError as exc:  # pragma: no cover - exercised only w/o extra
        raise ModuleNotFoundError(
            "SqlLogStore requires SQLAlchemy. Install the '[postgres]' extra: "
            "pip install -e '.[postgres]'"
        ) from exc
    return sa


def _sig_to_json(sig: Signature) -> str:
    return sig.model_dump_json()


def _sig_from_json(raw: str) -> Signature:
    return Signature.model_validate_json(raw)


class SqlLogStore:
    """Durable append-only CT log over SQLAlchemy Core (Postgres or sqlite)."""

    def __init__(self, db_url: str) -> None:
        self._sa = _require_sqlalchemy()
        self._lock = threading.Lock()
        self.engine = self._sa.create_engine(db_url, future=True, pool_pre_ping=True)
        meta = self._sa.MetaData()
        sa = self._sa
        self._log = sa.Table(
            "anchor_log_entries",
            meta,
            sa.Column("log_index", sa.Integer, primary_key=True),
            sa.Column("logged_at", sa.String, nullable=False),
            sa.Column("kind", sa.String, nullable=False),
            sa.Column("payload_hash", sa.String, nullable=False),
            sa.Column("log_signature", sa.Text, nullable=False),
            sa.Column("prev_log_hash", sa.String, nullable=True),
        )
        self._roots = sa.Table(
            "anchor_countersigned_roots",
            meta,
            sa.Column("tenant_id", sa.String, primary_key=True),
            sa.Column("root_hash", sa.String, primary_key=True),
            sa.Column("seq_from", sa.Integer, nullable=False),
            sa.Column("seq_to", sa.Integer, nullable=False),
            sa.Column("attested_at", sa.String, nullable=False),
            sa.Column("countersignature", sa.Text, nullable=False),
        )
        self._bindings = sa.Table(
            "anchor_log_capsule_bindings",
            meta,
            sa.Column("log_index", sa.Integer, primary_key=True),
            sa.Column("capsule_id", sa.String, nullable=False, index=True),
        )
        meta.create_all(self.engine)

    # --- row <-> model ---
    @staticmethod
    def _row_to_entry(r) -> TransparencyLogEntry:
        return TransparencyLogEntry(
            log_index=r[0],
            logged_at=datetime.fromisoformat(r[1]),
            kind=r[2],
            payload_hash=r[3],
            log_signature=_sig_from_json(r[4]),
            prev_log_hash=r[5],
        )

    # --- log ---
    def append_entry(self, entry: TransparencyLogEntry) -> None:
        t = self._log
        with self._lock, self.engine.begin() as conn:
            conn.execute(
                t.insert().values(
                    log_index=entry.log_index,
                    logged_at=entry.logged_at.isoformat(),
                    kind=entry.kind,
                    payload_hash=entry.payload_hash,
                    log_signature=_sig_to_json(entry.log_signature),
                    prev_log_hash=entry.prev_log_hash,
                )
            )

    def all_entries(self) -> list[TransparencyLogEntry]:
        t = self._log
        with self.engine.connect() as conn:
            rows = conn.execute(
                self._sa.select(
                    t.c.log_index, t.c.logged_at, t.c.kind, t.c.payload_hash,
                    t.c.log_signature, t.c.prev_log_hash,
                ).order_by(t.c.log_index)
            ).fetchall()
        return [self._row_to_entry(r) for r in rows]

    def entries_after(self, after_index: int) -> list[TransparencyLogEntry]:
        t = self._log
        with self.engine.connect() as conn:
            rows = conn.execute(
                self._sa.select(
                    t.c.log_index, t.c.logged_at, t.c.kind, t.c.payload_hash,
                    t.c.log_signature, t.c.prev_log_hash,
                )
                .where(t.c.log_index >= after_index)
                .order_by(t.c.log_index)
            ).fetchall()
        return [self._row_to_entry(r) for r in rows]

    def size(self) -> int:
        t = self._log
        with self.engine.connect() as conn:
            return int(
                conn.execute(
                    self._sa.select(self._sa.func.count()).select_from(t)
                ).scalar_one()
            )

    # --- countersigned roots ---
    def put_root(self, root: CountersignedRoot) -> None:
        t = self._roots
        with self._lock, self.engine.begin() as conn:
            exists = conn.execute(
                self._sa.select(t.c.tenant_id).where(
                    t.c.tenant_id == root.tenant_id, t.c.root_hash == root.root_hash
                )
            ).first()
            vals = dict(
                seq_from=int(root.seq_range[0]),
                seq_to=int(root.seq_range[1]),
                attested_at=root.attested_at.isoformat(),
                countersignature=_sig_to_json(root.countersignature),
            )
            if exists is None:
                conn.execute(
                    t.insert().values(
                        tenant_id=root.tenant_id, root_hash=root.root_hash, **vals
                    )
                )
            else:
                conn.execute(
                    t.update().where(
                        t.c.tenant_id == root.tenant_id,
                        t.c.root_hash == root.root_hash,
                    ).values(**vals)
                )

    def get_root(self, tenant_id: str, root_hash: str) -> CountersignedRoot | None:
        t = self._roots
        with self.engine.connect() as conn:
            r = conn.execute(
                self._sa.select(
                    t.c.tenant_id, t.c.root_hash, t.c.seq_from, t.c.seq_to,
                    t.c.attested_at, t.c.countersignature,
                ).where(t.c.tenant_id == tenant_id, t.c.root_hash == root_hash)
            ).first()
        if r is None:
            return None
        return CountersignedRoot(
            tenant_id=r[0],
            root_hash=r[1],
            seq_range=(r[2], r[3]),
            attested_at=datetime.fromisoformat(r[4]),
            countersignature=_sig_from_json(r[5]),
        )

    # --- capsule binding (Phase 3 tail-add) ---
    def put_capsule_id(self, log_index: int, capsule_id: str) -> None:
        t = self._bindings
        with self._lock, self.engine.begin() as conn:
            exists = conn.execute(
                self._sa.select(t.c.log_index).where(t.c.log_index == int(log_index))
            ).first()
            if exists is None:
                conn.execute(
                    t.insert().values(log_index=int(log_index), capsule_id=capsule_id)
                )
            else:
                conn.execute(
                    t.update().where(t.c.log_index == int(log_index)).values(
                        capsule_id=capsule_id
                    )
                )

    def get_capsule_id(self, log_index: int) -> str | None:
        t = self._bindings
        with self.engine.connect() as conn:
            r = conn.execute(
                self._sa.select(t.c.capsule_id).where(t.c.log_index == int(log_index))
            ).first()
        return None if r is None else str(r[0])

    def entries_for_capsule(self, capsule_id: str) -> list[TransparencyLogEntry]:
        le, b = self._log, self._bindings
        with self.engine.connect() as conn:
            rows = conn.execute(
                self._sa.select(
                    le.c.log_index, le.c.logged_at, le.c.kind, le.c.payload_hash,
                    le.c.log_signature, le.c.prev_log_hash,
                )
                .select_from(le.join(b, le.c.log_index == b.c.log_index))
                .where(b.c.capsule_id == capsule_id)
                .order_by(le.c.log_index)
            ).fetchall()
        return [self._row_to_entry(r) for r in rows]
