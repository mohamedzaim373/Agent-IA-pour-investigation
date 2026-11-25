"""Schéma de la base de données (SQLAlchemy Core).

SQLite par défaut (prototype), PostgreSQL par simple changement de DB_URL
(par ex. postgresql+psycopg://investigator:***@postgres:5432/investigator).

Tables :
  investigations  cas d'investigation et versions (GT-05)
  audit_log       journal d'audit en ajout seul, chaîné SHA-256 (GT-01, GT-02)
  evidence        mémoire de preuves (observations sourcées)
  reports         rapports produits et résultat de leur validation
  approvals       demandes de validation humaine (EF-19, GT-04)
  ti_cache        cache des enrichissements de Threat Intelligence
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone

from sqlalchemy import (
    Column,
    Float,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    UniqueConstraint,
    create_engine,
    event,
    text,
)
from sqlalchemy.engine import Engine

metadata = MetaData()

investigations = Table(
    "investigations",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("created_at", String(40), nullable=False),
    Column("finished_at", String(40)),
    Column("status", String(32), nullable=False),
    Column("analyst_id", String(64), nullable=False),
    Column("autonomy_level", String(4), nullable=False),
    Column("alert_json", Text, nullable=False),
    Column("metadata_json", Text, nullable=False, default="{}"),
    Column("verdict", String(32)),
    Column("stop_reason", Text),
)

audit_log = Table(
    "audit_log",
    metadata,
    Column("seq", Integer, primary_key=True, autoincrement=False),
    Column("ts", String(40), nullable=False),
    Column("investigation_id", String(64)),
    Column("actor", String(96), nullable=False),
    Column("event_type", String(40), nullable=False),
    Column("tool", String(64)),
    Column("params_json", Text),
    Column("result_hash", String(64)),
    Column("decision", String(32)),
    Column("reason", Text),
    Column("duration_ms", Float),
    Column("details_json", Text),
    Column("prev_hash", String(64), nullable=False),
    Column("entry_hash", String(64), nullable=False),
)

evidence = Table(
    "evidence",
    metadata,
    Column("pk", Integer, primary_key=True, autoincrement=True),
    Column("investigation_id", String(64), nullable=False, index=True),
    Column("evidence_id", String(16), nullable=False),
    Column("audit_seq", Integer, nullable=False),
    Column("source", String(64), nullable=False),
    Column("tool", String(64), nullable=False),
    Column("query_json", Text, nullable=False),
    Column("observed_at", String(40)),
    Column("host", String(128)),
    Column("event_type", String(64)),
    Column("summary", Text, nullable=False),
    Column("excerpt_json", Text, nullable=False),
    Column("item_hash", String(64), nullable=False),
    Column("raw_ref", String(128)),
    Column("flags_json", Text, nullable=False, default="[]"),
    Column("created_at", String(40), nullable=False),
    UniqueConstraint("investigation_id", "evidence_id", name="uq_evidence_id"),
)

reports = Table(
    "reports",
    metadata,
    Column("investigation_id", String(64), primary_key=True),
    Column("created_at", String(40), nullable=False),
    Column("report_json", Text, nullable=False),
    Column("markdown", Text, nullable=False),
    Column("validation_json", Text, nullable=False),
)

approvals = Table(
    "approvals",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("investigation_id", String(64), nullable=False, index=True),
    Column("tool", String(64), nullable=False),
    Column("args_json", Text, nullable=False),
    Column("justification", Text),
    Column("risk", String(32)),
    Column("status", String(16), nullable=False),  # pending | approved | rejected | expired
    Column("requested_at", String(40), nullable=False),
    Column("decided_at", String(40)),
    Column("analyst_id", String(64)),
    Column("reason", Text),
)

ti_cache = Table(
    "ti_cache",
    metadata,
    Column("key", String(256), primary_key=True),
    Column("provider", String(32), nullable=False),
    Column("value", String(512), nullable=False),
    Column("response_json", Text, nullable=False),
    Column("fetched_at", Float, nullable=False),
)


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


_APPEND_ONLY_SQLITE = [
    """CREATE TRIGGER IF NOT EXISTS audit_log_no_update BEFORE UPDATE ON audit_log
       BEGIN SELECT RAISE(ABORT, 'audit_log est en ajout seul'); END;""",
    """CREATE TRIGGER IF NOT EXISTS audit_log_no_delete BEFORE DELETE ON audit_log
       BEGIN SELECT RAISE(ABORT, 'audit_log est en ajout seul'); END;""",
]

_APPEND_ONLY_POSTGRES = [
    """CREATE OR REPLACE FUNCTION audit_log_append_only() RETURNS trigger AS $$
       BEGIN RAISE EXCEPTION 'audit_log est en ajout seul'; END; $$ LANGUAGE plpgsql;""",
    "DROP TRIGGER IF EXISTS audit_log_no_change ON audit_log;",
    """CREATE TRIGGER audit_log_no_change BEFORE UPDATE OR DELETE ON audit_log
       FOR EACH ROW EXECUTE FUNCTION audit_log_append_only();""",
]

_engines: dict[str, Engine] = {}
_engines_lock = threading.Lock()


def get_engine(url: str) -> Engine:
    """Retourne (et initialise une fois) le moteur associé à `url`."""
    with _engines_lock:
        engine = _engines.get(url)
        if engine is not None:
            return engine
        connect_args = {}
        if url.startswith("sqlite"):
            connect_args = {"check_same_thread": False, "timeout": 30}
        engine = create_engine(url, future=True, connect_args=connect_args)
        if url.startswith("sqlite"):

            @event.listens_for(engine, "connect")
            def _sqlite_pragmas(dbapi_conn, _record):  # pragma: no cover - trivial
                cur = dbapi_conn.cursor()
                cur.execute("PRAGMA journal_mode=WAL")
                cur.execute("PRAGMA foreign_keys=ON")
                cur.close()

        metadata.create_all(engine)
        statements = _APPEND_ONLY_SQLITE if engine.dialect.name == "sqlite" else (
            _APPEND_ONLY_POSTGRES if engine.dialect.name == "postgresql" else []
        )
        with engine.begin() as conn:
            for stmt in statements:
                conn.execute(text(stmt))
        _engines[url] = engine
        return engine


def dispose_engine(url: str) -> None:
    """Ferme le moteur (utile dans les tests)."""
    with _engines_lock:
        engine = _engines.pop(url, None)
    if engine is not None:
        engine.dispose()
