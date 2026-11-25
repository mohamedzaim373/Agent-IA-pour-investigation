"""Validation humaine des actions sensibles (EF-19, GT-04).

La passerelle sollicite un `Approver` dès que la politique répond
NEEDS_APPROVAL. La décision (approbation ou refus), l'identité de l'analyste et
le motif sont journalisés dans l'audit.

Implémentations :
  AutoApprover      décision fixe (tests, évaluation automatisée)
  CallbackApprover  délègue à une fonction (notebook, intégrations)
  ConsoleApprover   question posée dans le terminal
  DatabaseApprover  demande persistée en base, tranchée via l'API / l'interface
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

from sqlalchemy import select

from evidence.db import approvals, get_engine, utcnow
from gateway.hashing import canonical_json


@dataclass
class ApprovalRequest:
    investigation_id: str
    tool: str
    args: dict[str, Any]
    justification: str
    risk: str | None
    policy_reason: str
    level: str
    requested_by: str = "agent"


@dataclass
class ApprovalDecision:
    approved: bool
    analyst_id: str
    reason: str = ""
    approval_id: int | None = None
    extra: dict[str, Any] = field(default_factory=dict)


class Approver(Protocol):
    def request(self, req: ApprovalRequest) -> ApprovalDecision: ...


class AutoApprover:
    def __init__(self, approve: bool, analyst_id: str = "auto", reason: str | None = None):
        self.approve = approve
        self.analyst_id = analyst_id
        self.reason = reason or ("approbation automatique (évaluation)" if approve else "refus automatique")
        self.requests: list[ApprovalRequest] = []

    def request(self, req: ApprovalRequest) -> ApprovalDecision:
        self.requests.append(req)
        return ApprovalDecision(self.approve, self.analyst_id, self.reason)


class CallbackApprover:
    def __init__(self, fn: Callable[[ApprovalRequest], ApprovalDecision]):
        self.fn = fn

    def request(self, req: ApprovalRequest) -> ApprovalDecision:
        return self.fn(req)


class ConsoleApprover:
    def __init__(self, analyst_id: str):
        self.analyst_id = analyst_id

    def request(self, req: ApprovalRequest) -> ApprovalDecision:  # pragma: no cover - interactif
        print("\n=== Validation requise ===")
        print(f"Outil         : {req.tool} ({req.risk})")
        print(f"Paramètres    : {json.dumps(req.args, ensure_ascii=False, default=str)}")
        print(f"Justification : {req.justification}")
        print(f"Politique     : {req.policy_reason}")
        answer = input("Approuver ? [o/N] ").strip().lower()
        reason = input("Motif : ").strip()
        return ApprovalDecision(answer in {"o", "oui", "y", "yes"}, self.analyst_id, reason)


class DatabaseApprover:
    """Persiste la demande et attend la décision prise via l'API.

    Sans réponse dans le délai imparti, la demande expire et vaut refus.
    """

    _conditions: dict[int, threading.Event] = {}
    _guard = threading.Lock()

    def __init__(self, db_url: str, timeout_s: float = 900):
        self.engine = get_engine(db_url)
        self.timeout_s = timeout_s

    def request(self, req: ApprovalRequest) -> ApprovalDecision:
        with self.engine.begin() as conn:
            res = conn.execute(
                approvals.insert().values(
                    investigation_id=req.investigation_id,
                    tool=req.tool,
                    args_json=canonical_json(req.args),
                    justification=req.justification,
                    risk=req.risk,
                    status="pending",
                    requested_at=utcnow(),
                )
            )
            approval_id = int(res.inserted_primary_key[0])
        event = threading.Event()
        with self._guard:
            self._conditions[approval_id] = event
        event.wait(self.timeout_s)
        with self._guard:
            self._conditions.pop(approval_id, None)
        row = self.get(approval_id)
        if row and row["status"] in {"approved", "rejected"}:
            return ApprovalDecision(row["status"] == "approved", row["analyst_id"], row["reason"] or "", approval_id)
        with self.engine.begin() as conn:
            conn.execute(
                approvals.update()
                .where((approvals.c.id == approval_id) & (approvals.c.status == "pending"))
                .values(status="expired", decided_at=utcnow(), analyst_id="system", reason="délai dépassé")
            )
        return ApprovalDecision(False, "system", "délai de validation dépassé", approval_id)

    # --------------------------------------------------------------- côté API
    def get(self, approval_id: int) -> dict[str, Any] | None:
        with self.engine.connect() as conn:
            row = conn.execute(select(approvals).where(approvals.c.id == approval_id)).mappings().first()
        return _approval_row(row) if row else None

    def pending(self, investigation_id: str | None = None) -> list[dict[str, Any]]:
        stmt = select(approvals).where(approvals.c.status == "pending").order_by(approvals.c.id)
        if investigation_id:
            stmt = stmt.where(approvals.c.investigation_id == investigation_id)
        with self.engine.connect() as conn:
            return [_approval_row(r) for r in conn.execute(stmt).mappings().all()]

    def decide(self, approval_id: int, *, approved: bool, analyst_id: str, reason: str) -> bool:
        with self.engine.begin() as conn:
            res = conn.execute(
                approvals.update()
                .where((approvals.c.id == approval_id) & (approvals.c.status == "pending"))
                .values(
                    status="approved" if approved else "rejected",
                    decided_at=utcnow(),
                    analyst_id=analyst_id,
                    reason=reason,
                )
            )
        if res.rowcount == 0:
            return False
        with self._guard:
            event = self._conditions.get(approval_id)
        if event:
            event.set()
        return True


def _approval_row(row: Any) -> dict[str, Any]:
    data = dict(row)
    data["args"] = json.loads(data.pop("args_json"))
    return data
