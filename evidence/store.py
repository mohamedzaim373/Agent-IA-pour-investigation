"""Mémoire de preuves : cas d'investigation, observations sourcées, rapports.

Une preuve (EV-xxx) est un élément renvoyé par une source via la passerelle.
Elle conserve son horodatage, sa source, la requête qui l'a produite, un extrait
normalisé et son empreinte. Elle est rattachée à l'entrée du journal d'audit
qui a journalisé l'appel (GT-03) : avant tout enregistrement, l'empreinte du
résultat est comparée à celle inscrite dans l'audit, si bien que l'agent ne peut
pas fabriquer une preuve qui ne provient pas d'un appel réel.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import func, select

from evidence.db import evidence as evidence_t
from evidence.db import get_engine, investigations, reports, utcnow
from gateway.audit import AuditLog
from gateway.hashing import canonical_json, hash_obj


class EvidenceIntegrityError(RuntimeError):
    """Le résultat présenté ne correspond pas à celui journalisé par la passerelle."""


@dataclass
class Evidence:
    evidence_id: str
    investigation_id: str
    audit_seq: int
    source: str
    tool: str
    query: dict[str, Any]
    observed_at: str | None
    host: str | None
    event_type: str | None
    summary: str
    excerpt: dict[str, Any]
    item_hash: str
    raw_ref: str | None = None
    flags: list[str] = field(default_factory=list)

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> "Evidence":
        return cls(
            evidence_id=row["evidence_id"],
            investigation_id=row["investigation_id"],
            audit_seq=row["audit_seq"],
            source=row["source"],
            tool=row["tool"],
            query=json.loads(row["query_json"]),
            observed_at=row["observed_at"],
            host=row["host"],
            event_type=row["event_type"],
            summary=row["summary"],
            excerpt=json.loads(row["excerpt_json"]),
            item_hash=row["item_hash"],
            raw_ref=row["raw_ref"],
            flags=json.loads(row["flags_json"] or "[]"),
        )

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


class EvidenceStore:
    def __init__(self, db_url: str):
        self.db_url = db_url
        self.engine = get_engine(db_url)
        self.audit = AuditLog(db_url)
        self._lock = threading.Lock()

    # ------------------------------------------------------------ investigations
    def create_investigation(
        self,
        investigation_id: str,
        *,
        analyst_id: str,
        autonomy_level: str,
        alert: dict[str, Any],
        metadata: dict[str, Any],
    ) -> None:
        with self.engine.begin() as conn:
            conn.execute(
                investigations.insert().values(
                    id=investigation_id,
                    created_at=utcnow(),
                    status="running",
                    analyst_id=analyst_id,
                    autonomy_level=autonomy_level,
                    alert_json=canonical_json(alert),
                    metadata_json=canonical_json(metadata),
                )
            )

    def finish_investigation(
        self, investigation_id: str, *, status: str, verdict: str | None, stop_reason: str | None
    ) -> None:
        with self.engine.begin() as conn:
            conn.execute(
                investigations.update()
                .where(investigations.c.id == investigation_id)
                .values(status=status, verdict=verdict, stop_reason=stop_reason, finished_at=utcnow())
            )

    def get_investigation(self, investigation_id: str) -> dict[str, Any] | None:
        with self.engine.connect() as conn:
            row = conn.execute(select(investigations).where(investigations.c.id == investigation_id)).mappings().first()
        return self._inv_row(row) if row else None

    def list_investigations(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.engine.connect() as conn:
            rows = (
                conn.execute(select(investigations).order_by(investigations.c.created_at.desc()).limit(limit))
                .mappings()
                .all()
            )
        return [self._inv_row(r) for r in rows]

    @staticmethod
    def _inv_row(row: Any) -> dict[str, Any]:
        data = dict(row)
        data["alert"] = json.loads(data.pop("alert_json"))
        data["metadata"] = json.loads(data.pop("metadata_json") or "{}")
        return data

    # ----------------------------------------------------------------- preuves
    def add_from_result(
        self,
        investigation_id: str,
        *,
        audit_seq: int,
        tool: str,
        query: dict[str, Any],
        payload: dict[str, Any],
    ) -> list[Evidence]:
        """Enregistre chaque élément d'un résultat d'outil comme une preuve."""
        entry = self.audit.get(audit_seq)
        if entry is None or entry.investigation_id != investigation_id or entry.tool != tool:
            raise EvidenceIntegrityError(f"entrée d'audit {audit_seq} introuvable pour cet appel")
        if entry.result_hash != hash_obj(payload):
            raise EvidenceIntegrityError(f"le résultat ne correspond pas à l'empreinte journalisée (audit {audit_seq})")

        items = payload.get("items") or []
        created: list[Evidence] = []
        with self._lock, self.engine.begin() as conn:
            count = conn.execute(
                select(func.count()).select_from(evidence_t).where(evidence_t.c.investigation_id == investigation_id)
            ).scalar_one()
            for item in items:
                count += 1
                ev = Evidence(
                    evidence_id=f"EV-{count:03d}",
                    investigation_id=investigation_id,
                    audit_seq=audit_seq,
                    source=str(item.get("source") or tool),
                    tool=tool,
                    query=query,
                    observed_at=item.get("timestamp"),
                    host=item.get("host"),
                    event_type=item.get("event_type"),
                    summary=str(item.get("summary") or "")[:2000],
                    excerpt={k: v for k, v in item.items() if k != "_flags"},
                    item_hash=hash_obj(item),
                    raw_ref=item.get("raw_ref"),
                    flags=list(item.get("_flags") or []),
                )
                conn.execute(
                    evidence_t.insert().values(
                        investigation_id=investigation_id,
                        evidence_id=ev.evidence_id,
                        audit_seq=audit_seq,
                        source=ev.source,
                        tool=tool,
                        query_json=canonical_json(query),
                        observed_at=ev.observed_at,
                        host=ev.host,
                        event_type=ev.event_type,
                        summary=ev.summary,
                        excerpt_json=canonical_json(ev.excerpt),
                        item_hash=ev.item_hash,
                        raw_ref=ev.raw_ref,
                        flags_json=canonical_json(ev.flags),
                        created_at=utcnow(),
                    )
                )
                created.append(ev)
        return created

    def get(self, investigation_id: str, evidence_id: str) -> Evidence | None:
        with self.engine.connect() as conn:
            row = (
                conn.execute(
                    select(evidence_t).where(
                        (evidence_t.c.investigation_id == investigation_id) & (evidence_t.c.evidence_id == evidence_id)
                    )
                )
                .mappings()
                .first()
            )
        return Evidence.from_row(dict(row)) if row else None

    def list(self, investigation_id: str) -> list[Evidence]:
        with self.engine.connect() as conn:
            rows = (
                conn.execute(
                    select(evidence_t).where(evidence_t.c.investigation_id == investigation_id).order_by(evidence_t.c.pk)
                )
                .mappings()
                .all()
            )
        return [Evidence.from_row(dict(r)) for r in rows]

    # ----------------------------------------------------------------- rapports
    def save_report(
        self, investigation_id: str, *, report: dict[str, Any], markdown: str, validation: dict[str, Any]
    ) -> None:
        values = dict(
            created_at=utcnow(),
            report_json=canonical_json(report),
            markdown=markdown,
            validation_json=canonical_json(validation),
        )
        with self.engine.begin() as conn:
            exists = conn.execute(
                select(reports.c.investigation_id).where(reports.c.investigation_id == investigation_id)
            ).first()
            if exists:
                conn.execute(reports.update().where(reports.c.investigation_id == investigation_id).values(**values))
            else:
                conn.execute(reports.insert().values(investigation_id=investigation_id, **values))

    def get_report(self, investigation_id: str) -> dict[str, Any] | None:
        with self.engine.connect() as conn:
            row = conn.execute(select(reports).where(reports.c.investigation_id == investigation_id)).mappings().first()
        if not row:
            return None
        return {
            "investigation_id": investigation_id,
            "created_at": row["created_at"],
            "report": json.loads(row["report_json"]),
            "markdown": row["markdown"],
            "validation": json.loads(row["validation_json"]),
        }
