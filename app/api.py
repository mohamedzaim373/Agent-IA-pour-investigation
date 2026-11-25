"""Service applicatif FastAPI (chapitre 13 : « Service et interface »).

    uvicorn app.api:app --host 0.0.0.0 --port 8000

Authentification : en-tête `Authorization: Bearer <jeton>` (python -m scripts.create_token <analyste>).
L'intégration Wazuh appelle POST /alerts/wazuh avec l'en-tête `X-Webhook-Token`.
"""

from __future__ import annotations

import hmac
from typing import Any, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query, status
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from agent.entities import AlertFormatError, normalize_alert
from agent.runner import Investigator
from app.auth import TokenStore
from app.run_manager import RunManager
from config.settings import Settings, load_settings
from gateway.policy import AnalystIdentity


class StartRequest(BaseModel):
    alert: dict[str, Any] | None = Field(default=None, description="Alerte Wazuh (JSON) ou saisie manuelle")
    scenario_id: str | None = Field(default=None, description="Scénario simulé (backend simulation)")
    autonomy_level: Literal["N0", "N1", "N2", "N3"] | None = None


class ApprovalRequestBody(BaseModel):
    approve: bool
    reason: str = Field(default="", max_length=500)


class DirectiveBody(BaseModel):
    type: Literal["invalidate_hypothesis", "impose_lead", "note"]
    text: str = Field(min_length=1, max_length=500)
    hypothesis_id: str | None = None
    tool: str | None = None
    args: dict[str, Any] = Field(default_factory=dict)


def create_app(settings: Settings | None = None, investigator: Investigator | None = None) -> FastAPI:
    settings = settings or load_settings()
    investigator = investigator or Investigator(settings)
    tokens = TokenStore(settings.data_dir / "tokens.json")
    manager = RunManager(investigator)
    app = FastAPI(title="Agent IA d'investigation d'incidents", version="1.0",
                  description="Planification, interrogation multi-sources et chronologie argumentée sous contrôle.")
    app.state.manager = manager
    app.state.investigator = investigator

    def current_analyst(authorization: str | None = Header(default=None)) -> AnalystIdentity:
        token = authorization.split(" ", 1)[1] if authorization and authorization.lower().startswith("bearer ") else None
        analyst_id = tokens.verify(token)
        if analyst_id is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "jeton absent ou invalide",
                                headers={"WWW-Authenticate": "Bearer"})
        try:
            return investigator.identities.get(analyst_id)
        except KeyError as exc:
            raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from exc

    def require_investigation(investigation_id: str) -> dict[str, Any]:
        inv = investigator.store.get_investigation(investigation_id)
        if inv is None and manager.get(investigation_id) is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "investigation inconnue")
        return inv or {"id": investigation_id, "status": manager.get(investigation_id).status}

    def start(analyst: AnalystIdentity, alert: dict[str, Any] | None, scenario_id: str | None,
              level: str | None) -> dict[str, Any]:
        if not analyst.tools:
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"le rôle {analyst.role} ne peut pas lancer d'investigation")
        scenario = None
        if settings.backend == "simulation":
            if not scenario_id:
                raise HTTPException(status.HTTP_400_BAD_REQUEST, "backend de simulation : préciser scenario_id")
            from connectors.simulation import load_scenario

            try:
                scenario = load_scenario(scenario_id)
            except FileNotFoundError as exc:
                raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
            alert = alert or scenario["alert"]
        if not alert:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "alerte manquante")
        try:
            normalize_alert(alert)
        except AlertFormatError as exc:
            raise HTTPException(422, str(exc)) from exc
        effective, notes = investigator.policy.effective_level(level, analyst)
        run = manager.start(alert, analyst_id=analyst.analyst_id, autonomy_level=level, scenario=scenario)
        return {"investigation_id": run.investigation_id, "autonomy_level": effective, "notes": notes}

    # ----------------------------------------------------------------- routes
    @app.get("/health")
    def health() -> dict[str, Any]:
        return {"status": "ok", "backend": settings.backend, "llm": settings.llm_provider,
                "policy_version": investigator.policy.version, "attack_kb": investigator.rag.kb_version}

    @app.get("/me")
    def me(analyst: AnalystIdentity = Depends(current_analyst)) -> dict[str, Any]:
        return {"analyst_id": analyst.analyst_id, "name": analyst.name, "role": analyst.role,
                "max_autonomy": analyst.max_autonomy, "tools": sorted(analyst.tools),
                "can_approve": analyst.can_approve, "can_read_audit": analyst.can_read_audit,
                "policy_max_level": investigator.policy.max_level, "default_level": investigator.policy.default_level}

    @app.get("/scenarios")
    def scenarios(_: AnalystIdentity = Depends(current_analyst)) -> list[dict[str, Any]]:
        from connectors.simulation import list_scenarios, load_scenario

        out = []
        for sid in list_scenarios():
            s = load_scenario(sid)
            out.append({"id": sid, "name": s.get("name"), "description": s.get("description")})
        return out

    @app.post("/investigations", status_code=status.HTTP_202_ACCEPTED)
    def create_investigation(body: StartRequest, analyst: AnalystIdentity = Depends(current_analyst)) -> dict[str, Any]:
        return start(analyst, body.alert, body.scenario_id, body.autonomy_level)

    @app.get("/investigations")
    def list_investigations(_: AnalystIdentity = Depends(current_analyst)) -> list[dict[str, Any]]:
        rows = investigator.store.list_investigations()
        for r in rows:
            run = manager.get(r["id"])
            r.pop("alert", None)
            if run and run.status in {"queued", "running"}:
                r["status"] = run.status
        return rows

    @app.get("/investigations/{investigation_id}")
    def get_investigation(investigation_id: str, _: AnalystIdentity = Depends(current_analyst)) -> dict[str, Any]:
        inv = require_investigation(investigation_id)
        run = manager.get(investigation_id)
        if run:
            inv["live_status"] = run.status
            inv["error"] = run.error
            plans = [e for e in run.events if e.get("type") == "plan"]
            inv["plan"] = plans[-1] if plans else None
        inv["pending_approvals"] = manager.approver.pending(investigation_id)
        return inv

    @app.get("/investigations/{investigation_id}/events")
    def get_events(investigation_id: str, after: int = Query(0, ge=0),
                   _: AnalystIdentity = Depends(current_analyst)) -> list[dict[str, Any]]:
        require_investigation(investigation_id)
        return manager.events(investigation_id, after)

    @app.get("/investigations/{investigation_id}/report")
    def get_report(investigation_id: str, _: AnalystIdentity = Depends(current_analyst)) -> dict[str, Any]:
        report = investigator.store.get_report(investigation_id)
        if report is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "rapport non disponible")
        return report

    @app.get("/investigations/{investigation_id}/report.md", response_class=PlainTextResponse)
    def get_report_md(investigation_id: str, _: AnalystIdentity = Depends(current_analyst)) -> str:
        report = investigator.store.get_report(investigation_id)
        if report is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "rapport non disponible")
        return report["markdown"]

    @app.get("/investigations/{investigation_id}/evidence")
    def get_evidence(investigation_id: str, _: AnalystIdentity = Depends(current_analyst)) -> list[dict[str, Any]]:
        require_investigation(investigation_id)
        return [e.to_dict() for e in investigator.store.list(investigation_id)]

    @app.post("/investigations/{investigation_id}/directives")
    def add_directive(investigation_id: str, body: DirectiveBody,
                      analyst: AnalystIdentity = Depends(current_analyst)) -> dict[str, Any]:
        require_investigation(investigation_id)
        if not analyst.can_approve:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "rôle non habilité à orienter l'agent")
        directive = dict(body.model_dump(), analyst_id=analyst.analyst_id)
        if not manager.add_directive(investigation_id, directive):
            raise HTTPException(status.HTTP_409_CONFLICT, "investigation terminée ou inconnue")
        return {"accepted": True, "note": "prise en compte à la prochaine révision du plan"}

    @app.get("/approvals")
    def list_approvals(investigation_id: str | None = None,
                       _: AnalystIdentity = Depends(current_analyst)) -> list[dict[str, Any]]:
        return manager.approver.pending(investigation_id)

    @app.post("/approvals/{approval_id}")
    def decide(approval_id: int, body: ApprovalRequestBody,
               analyst: AnalystIdentity = Depends(current_analyst)) -> dict[str, Any]:
        if not analyst.can_approve:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "rôle non habilité à valider")
        if not body.approve and investigator.policy.approval.get("require_reason_on_reject", True) and not body.reason:
            raise HTTPException(422, "motif obligatoire pour un refus")
        ok = manager.approver.decide(approval_id, approved=body.approve, analyst_id=analyst.analyst_id,
                                     reason=body.reason or ("approuvé" if body.approve else "refusé"))
        if not ok:
            raise HTTPException(status.HTTP_409_CONFLICT, "demande déjà traitée ou inconnue")
        return {"approval_id": approval_id, "approved": body.approve}

    @app.get("/audit/verify")
    def audit_verify(analyst: AnalystIdentity = Depends(current_analyst)) -> dict[str, Any]:
        if not analyst.can_read_audit:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "lecture de l'audit réservée")
        res = investigator.audit.verify()
        return {"ok": res.ok, "checked": res.checked, "head_hash": res.head_hash, "errors": res.errors}

    @app.get("/audit/{investigation_id}")
    def audit_entries(investigation_id: str, analyst: AnalystIdentity = Depends(current_analyst)) -> list[dict[str, Any]]:
        inv = require_investigation(investigation_id)
        if not (analyst.can_read_audit or inv.get("analyst_id") == analyst.analyst_id):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "lecture de l'audit réservée")
        return [e.to_dict() for e in investigator.audit.entries(investigation_id)]

    @app.post("/alerts/wazuh", status_code=status.HTTP_202_ACCEPTED)
    def wazuh_webhook(alert: dict[str, Any], x_webhook_token: str | None = Header(default=None)) -> dict[str, Any]:
        if not settings.webhook_token or not x_webhook_token or not hmac.compare_digest(
                settings.webhook_token, x_webhook_token):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "jeton d'intégration invalide")
        if settings.backend == "simulation":
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "réception d'alertes réelles : utiliser BACKEND=live")
        analyst = investigator.identities.get(settings.webhook_analyst)
        return start(analyst, alert, None, None)

    return app


def __getattr__(name: str):  # pragma: no cover - point d'entrée « uvicorn app.api:app »
    # Construction paresseuse : importer le module (tests) ne démarre pas le service.
    if name == "app":
        globals()["app"] = create_app()
        return globals()["app"]
    raise AttributeError(name)
