"""Journal d'audit en ajout seul, chaîné par empreintes SHA-256 (GT-01, GT-02).

Chaque entrée contient l'empreinte de l'entrée précédente : modifier, supprimer
ou réordonner une entrée a posteriori casse la chaîne, ce que `verify()` détecte.
La base refuse en plus UPDATE et DELETE sur la table (déclencheurs).

Seule la passerelle (et l'orchestrateur pour les événements de cycle de vie)
écrit dans ce journal ; le LLM n'y a aucun accès.

Vérification en ligne de commande :
    python -m gateway.audit verify
    python -m gateway.audit show <investigation_id>
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import func, select

from evidence.db import audit_log, get_engine, utcnow
from gateway.hashing import GENESIS_HASH, canonical_json, hash_obj

_locks: dict[str, threading.Lock] = {}
_locks_guard = threading.Lock()

HASHED_FIELDS = (
    "seq",
    "ts",
    "investigation_id",
    "actor",
    "event_type",
    "tool",
    "params_json",
    "result_hash",
    "decision",
    "reason",
    "duration_ms",
    "details_json",
    "prev_hash",
)


def _lock_for(url: str) -> threading.Lock:
    with _locks_guard:
        return _locks.setdefault(url, threading.Lock())


def compute_entry_hash(row: dict[str, Any]) -> str:
    return hash_obj({k: row.get(k) for k in HASHED_FIELDS})


@dataclass
class AuditEntry:
    seq: int
    ts: str
    investigation_id: str | None
    actor: str
    event_type: str
    tool: str | None
    params: Any
    result_hash: str | None
    decision: str | None
    reason: str | None
    duration_ms: float | None
    details: Any
    prev_hash: str
    entry_hash: str

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> "AuditEntry":
        return cls(
            seq=row["seq"],
            ts=row["ts"],
            investigation_id=row["investigation_id"],
            actor=row["actor"],
            event_type=row["event_type"],
            tool=row["tool"],
            params=json.loads(row["params_json"]) if row["params_json"] else None,
            result_hash=row["result_hash"],
            decision=row["decision"],
            reason=row["reason"],
            duration_ms=row["duration_ms"],
            details=json.loads(row["details_json"]) if row["details_json"] else None,
            prev_hash=row["prev_hash"],
            entry_hash=row["entry_hash"],
        )

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


@dataclass
class VerifyResult:
    ok: bool
    checked: int
    head_hash: str
    errors: list[str] = field(default_factory=list)

    @property
    def first_error(self) -> str | None:
        return self.errors[0] if self.errors else None


class AuditLog:
    """Accès au journal d'audit chaîné."""

    def __init__(self, db_url: str):
        self.db_url = db_url
        self.engine = get_engine(db_url)
        self._lock = _lock_for(db_url)

    # ------------------------------------------------------------------ écriture
    def append(
        self,
        *,
        investigation_id: str | None,
        actor: str,
        event_type: str,
        tool: str | None = None,
        params: Any = None,
        result_hash: str | None = None,
        decision: str | None = None,
        reason: str | None = None,
        duration_ms: float | None = None,
        details: Any = None,
    ) -> AuditEntry:
        with self._lock, self.engine.begin() as conn:
            last = conn.execute(
                select(audit_log.c.seq, audit_log.c.entry_hash).order_by(audit_log.c.seq.desc()).limit(1)
            ).first()
            seq = (last.seq + 1) if last else 1
            prev_hash = last.entry_hash if last else GENESIS_HASH
            row = {
                "seq": seq,
                "ts": utcnow(),
                "investigation_id": investigation_id,
                "actor": actor,
                "event_type": event_type,
                "tool": tool,
                "params_json": canonical_json(params) if params is not None else None,
                "result_hash": result_hash,
                "decision": decision,
                "reason": reason,
                "duration_ms": round(float(duration_ms), 3) if duration_ms is not None else None,
                "details_json": canonical_json(details) if details is not None else None,
                "prev_hash": prev_hash,
            }
            row["entry_hash"] = compute_entry_hash(row)
            conn.execute(audit_log.insert().values(**row))
        return AuditEntry.from_row(row)

    # ------------------------------------------------------------------ lecture
    def get(self, seq: int) -> AuditEntry | None:
        with self.engine.connect() as conn:
            row = conn.execute(select(audit_log).where(audit_log.c.seq == seq)).mappings().first()
        return AuditEntry.from_row(dict(row)) if row else None

    def entries(self, investigation_id: str | None = None) -> list[AuditEntry]:
        stmt = select(audit_log).order_by(audit_log.c.seq)
        if investigation_id is not None:
            stmt = stmt.where(audit_log.c.investigation_id == investigation_id)
        with self.engine.connect() as conn:
            rows = conn.execute(stmt).mappings().all()
        return [AuditEntry.from_row(dict(r)) for r in rows]

    def head_hash(self) -> str:
        with self.engine.connect() as conn:
            row = conn.execute(select(audit_log.c.entry_hash).order_by(audit_log.c.seq.desc()).limit(1)).first()
        return row.entry_hash if row else GENESIS_HASH

    def count(self) -> int:
        with self.engine.connect() as conn:
            return conn.execute(select(func.count()).select_from(audit_log)).scalar_one()

    # -------------------------------------------------------------- vérification
    def verify(self) -> VerifyResult:
        """Recalcule toute la chaîne : continuité des numéros, liens et empreintes."""
        errors: list[str] = []
        prev_hash = GENESIS_HASH
        expected_seq = 1
        checked = 0
        with self.engine.connect() as conn:
            rows = conn.execute(select(audit_log).order_by(audit_log.c.seq)).mappings()
            for raw in rows:
                row = dict(raw)
                checked += 1
                if row["seq"] != expected_seq:
                    errors.append(f"seq {row['seq']} : numéro attendu {expected_seq} (entrée supprimée ou insérée)")
                    expected_seq = row["seq"]
                if row["prev_hash"] != prev_hash:
                    errors.append(f"seq {row['seq']} : lien rompu avec l'entrée précédente")
                recomputed = compute_entry_hash(row)
                if recomputed != row["entry_hash"]:
                    errors.append(f"seq {row['seq']} : contenu modifié (empreinte invalide)")
                prev_hash = row["entry_hash"]
                expected_seq += 1
        return VerifyResult(ok=not errors, checked=checked, head_hash=prev_hash, errors=errors)


def _main(argv: list[str] | None = None) -> int:
    from config.settings import load_settings

    parser = argparse.ArgumentParser(description="Journal d'audit chaîné")
    parser.add_argument("--db", help="URL de base (défaut : DB_URL ou SQLite local)")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("verify", help="vérifier l'intégrité de la chaîne")
    show = sub.add_parser("show", help="afficher les entrées d'une investigation")
    show.add_argument("investigation_id")
    args = parser.parse_args(argv)

    settings = load_settings()
    settings.ensure_dirs()
    log = AuditLog(args.db or settings.database_url)
    if args.cmd == "verify":
        res = log.verify()
        status = "INTÈGRE" if res.ok else "ALTÉRÉ"
        print(f"Journal {status} : {res.checked} entrées vérifiées, tête = {res.head_hash}")
        for err in res.errors:
            print(f"  - {err}")
        return 0 if res.ok else 1
    for entry in log.entries(args.investigation_id):
        print(
            f"#{entry.seq:05d} {entry.ts} {entry.actor:<22} {entry.event_type:<16} "
            f"{entry.tool or '':<16} {entry.decision or '':<16} {entry.reason or ''}"
        )
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(_main())
