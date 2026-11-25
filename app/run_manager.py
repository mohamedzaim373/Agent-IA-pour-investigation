"""Exécution des investigations en arrière-plan pour l'API (EF-18, EF-19, EF-20)."""

from __future__ import annotations

import queue
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

from agent.runner import InvestigationOutcome, Investigator, new_investigation_id
from evidence.db import utcnow
from gateway.approval import DatabaseApprover


@dataclass
class RunState:
    investigation_id: str
    analyst_id: str
    status: str = "queued"  # queued | running | completed | error
    events: list[dict[str, Any]] = field(default_factory=list)
    directives: "queue.Queue[dict[str, Any]]" = field(default_factory=queue.Queue)
    outcome: InvestigationOutcome | None = None
    error: str | None = None
    created_at: str = field(default_factory=utcnow)


class RunManager:
    def __init__(self, investigator: Investigator, max_workers: int = 2):
        self.investigator = investigator
        timeout = float(investigator.policy.approval.get("timeout_s", 900))
        self.approver = DatabaseApprover(investigator.settings.database_url, timeout_s=timeout)
        self.pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="investigation")
        self.runs: dict[str, RunState] = {}
        self._lock = threading.Lock()

    def start(self, alert: dict[str, Any], *, analyst_id: str, autonomy_level: str | None,
              scenario: dict[str, Any] | None) -> RunState:
        inv_id = new_investigation_id()
        run = RunState(inv_id, analyst_id)
        with self._lock:
            self.runs[inv_id] = run

        def on_event(event: dict[str, Any]) -> None:
            with self._lock:
                run.events.append(dict(event, seq=len(run.events) + 1))

        def job() -> None:
            run.status = "running"
            try:
                outcome = self.investigator.investigate(
                    alert, analyst_id=analyst_id, autonomy_level=autonomy_level, approver=self.approver,
                    scenario=scenario, on_event=on_event, directives=run.directives, investigation_id=inv_id)
                run.outcome = outcome
                run.status = outcome.status
                run.error = outcome.error
            except Exception as exc:  # erreur de démarrage (alerte invalide, etc.)
                run.status, run.error = "error", f"{type(exc).__name__}: {exc}"
                on_event({"type": "run_error", "investigation_id": inv_id, "error": run.error})

        self.pool.submit(job)
        return run

    def get(self, investigation_id: str) -> RunState | None:
        return self.runs.get(investigation_id)

    def events(self, investigation_id: str, after: int = 0) -> list[dict[str, Any]]:
        run = self.runs.get(investigation_id)
        if run is None:
            return []
        with self._lock:
            return [e for e in run.events if e["seq"] > after]

    def add_directive(self, investigation_id: str, directive: dict[str, Any]) -> bool:
        run = self.runs.get(investigation_id)
        if run is None or run.status not in {"queued", "running"}:
            return False
        run.directives.put(directive)
        return True
