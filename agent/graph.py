"""Graphe LangGraph de l'agent (chapitre 12).

    qualifier → planifier → agir → observer ─┬─→ agir            (plan en cours)
                   ↑                         ├─→ planifier       (révision justifiée, EF-05)
                   └─────────────────────────┘
                                             └─→ conclure → valider ─┬─→ conclure (réparation)
                                                                     └─→ fin

Critères d'arrêt (EF-06) : conclusion étayée (le modèle conclut ou le plan est
épuisé), budget épuisé (étapes, jetons, durée, appels) ou blocage (échecs
consécutifs). La raison de l'arrêt figure dans le rapport.

L'agent ne détient aucun accès : chaque appel d'outil passe par la
`ToolGateway`, chaque appel au LLM est journalisé dans l'audit.
"""

from __future__ import annotations

import queue
import time
from dataclasses import dataclass, field
from typing import Any, Callable, TypedDict

from langgraph.graph import END, StateGraph
from pydantic import ValidationError

from agent import prompts
from agent.entities import extract_observables
from agent.llm.base import BaseLLM, LLMError
from agent.llm.offline import OfflineLLM
from agent.report_models import REPORT_JSON_SHAPE, Hypothesis, InvestigationReport, Plan, PlanStep
from agent.validator import enforce_grounding, validate_report
from evidence.db import utcnow
from evidence.store import EvidenceStore
from gateway.audit import AuditLog
from gateway.gateway import ToolGateway, ToolResult
from gateway.hashing import hash_obj, sha256_hex
from gateway.injection import wrap_untrusted
from gateway.policy import Policy
from gateway.privacy import Pseudonymizer
from gateway.tool_schemas import tools_for_prompt

LOG_TOOLS = {"search_logs", "get_process_tree"}
TI_TOOLS = {"misp_lookup", "ti_lookup"}
CHECKABLE = {"ip", "domain", "url", "sha256", "sha1", "md5"}


@dataclass
class AgentContext:
    """Dépendances d'exécution (hors état du graphe)."""

    investigation_id: str
    alert: dict[str, Any]
    gateway: ToolGateway
    llm: BaseLLM
    store: EvidenceStore
    audit: AuditLog
    rag: Any
    policy: Policy
    pseudonymizer: Pseudonymizer | None = None
    on_event: Callable[[dict[str, Any]], None] = lambda e: None
    directives: "queue.Queue[dict[str, Any]]" = field(default_factory=queue.Queue)
    backend: str = "simulation"
    max_replans: int = 8
    max_new_steps: int = 8
    max_repairs: int = 1
    fallback_llm: BaseLLM = field(default_factory=OfflineLLM)


class AgentState(TypedDict, total=False):
    observables: list[dict[str, Any]]
    checked_observables: list[str]
    new_observables: list[dict[str, Any]]
    malicious_iocs: list[str]
    pivoted: list[str]
    hypotheses: list[dict[str, Any]]
    severity: str
    assessment: str
    plan: dict[str, Any]
    replan_log: list[dict[str, Any]]
    replans: int
    observations: list[dict[str, Any]]
    needs_replan: bool
    current_step: str | None
    last_result: Any
    stop_reason: str
    failures: list[dict[str, Any]]
    injections: list[dict[str, Any]]
    report: dict[str, Any]
    validation: dict[str, Any]
    repair_attempts: int
    validation_feedback: list[str]
    needs_repair: bool
    llm_fallback: str


# ---------------------------------------------------------------------- outils
def _compact_alert(alert: dict[str, Any]) -> dict[str, Any]:
    keep = {k: alert.get(k) for k in ("timestamp", "host", "event_type", "rule", "summary")}
    keep["fields"] = {k: v for k, v in (alert.get("fields") or {}).items()
                      if k in {"image", "command_line", "parent_image", "user", "process_guid", "pid",
                               "destination_ip", "destination_port", "target_object", "target_filename"}}
    return keep


def _ev_dict(ev) -> dict[str, Any]:
    return {"evidence_id": ev.evidence_id, "tool": ev.tool, "source": ev.source, "observed_at": ev.observed_at,
            "host": ev.host, "event_type": ev.event_type, "summary": ev.summary, "excerpt": ev.excerpt,
            "flags": ev.flags, "query": ev.query, "raw_ref": ev.raw_ref, "audit_seq": ev.audit_seq}


def _obs_key(o: dict[str, Any]) -> str:
    return f"{o['type']}:{str(o['value']).lower()}"


def build_graph(ctx: AgentContext):
    policy = ctx.policy
    usage = ctx.gateway.usage
    internal_domains = policy.internal_domains

    def emit(event: dict[str, Any]) -> None:
        try:
            ctx.on_event(dict(event, investigation_id=ctx.investigation_id, at=utcnow()))
        except Exception:  # le suivi temps réel ne doit jamais interrompre l'enquête
            pass

    def register(observables: list[dict[str, Any]]) -> None:
        if ctx.pseudonymizer is None:
            return
        for o in observables:
            if o["type"] in {"user", "host"} or (o["type"] == "ip" and o.get("internal")):
                ctx.pseudonymizer.register(o["type"], o["value"])

    def call_llm(task: str, user: str, context: dict[str, Any], llm: BaseLLM | None = None) -> dict[str, Any]:
        model = llm or ctx.llm
        started = time.perf_counter()
        try:
            out = model.generate(task, prompts.SYSTEM, user, context)
        except Exception as exc:
            ctx.audit.append(investigation_id=ctx.investigation_id, actor="agent", event_type="llm_error",
                             tool=f"llm:{task}", reason=str(exc)[:500],
                             details={"provider": model.provider, "model": model.model})
            raise LLMError(str(exc)) from exc
        usage.tokens = ctx.llm.total_tokens
        ctx.audit.append(
            investigation_id=ctx.investigation_id, actor="agent", event_type="llm_call", tool=f"llm:{task}",
            params={"prompt_sha256": sha256_hex(user), "prompt_chars": len(user)}, result_hash=hash_obj(out),
            duration_ms=(time.perf_counter() - started) * 1000,
            details={"provider": model.provider, "model": model.model, "tokens_total": model.total_tokens},
        )
        return out

    # ------------------------------------------------------------- qualifier
    def qualify(state: AgentState) -> AgentState:
        alert = ctx.alert
        observables = extract_observables(alert, internal_domains)
        register(observables)
        user = prompts.render(prompts.QUALIFY, alert=wrap_untrusted(_compact_alert(alert), source="alerte"),
                              observables=observables)
        try:
            out = call_llm("qualify", user, {"alert": alert, "observables": observables})
        except LLMError:
            out = call_llm("qualify", user, {"alert": alert, "observables": observables}, ctx.fallback_llm)
        hypotheses = []
        for i, h in enumerate(out.get("hypotheses") or []):
            try:
                hypotheses.append(Hypothesis(**{"id": h.get("id") or f"H{i + 1}", **h}).model_dump())
            except (ValidationError, TypeError):
                continue
        if not hypotheses:
            hypotheses = [Hypothesis(id="H1", statement="Activité malveillante réelle").model_dump(),
                          Hypothesis(id="H2", statement="Activité légitime ou faux positif").model_dump()]
        severity = str(out.get("severity", "medium")).lower()
        emit({"type": "qualified", "severity": severity, "assessment": out.get("assessment", ""),
              "hypotheses": hypotheses, "observables": observables})
        ctx.audit.append(investigation_id=ctx.investigation_id, actor="agent", event_type="qualification",
                         decision=severity, reason=str(out.get("assessment", ""))[:500],
                         details={"hypotheses": hypotheses, "observables": len(observables)})
        return {"observables": observables, "hypotheses": hypotheses, "severity": severity,
                "assessment": out.get("assessment", ""), "checked_observables": [], "new_observables": [],
                "malicious_iocs": [], "pivoted": [], "plan": Plan(version=0).model_dump(), "replan_log": [],
                "replans": 0, "observations": [], "failures": [], "injections": [], "repair_attempts": 0,
                "stop_reason": "", "needs_replan": False}

    # ------------------------------------------------------------- planifier
    def plan(state: AgentState) -> AgentState:
        current = Plan(**state["plan"])
        mode = "initial" if not current.steps else "revise"
        hypotheses = list(state.get("hypotheses", []))
        directives: list[dict[str, Any]] = []
        while True:
            try:
                directives.append(ctx.directives.get_nowait())
            except queue.Empty:
                break
        for d in directives:
            ctx.audit.append(investigation_id=ctx.investigation_id, actor=f"analyst:{d.get('analyst_id', '?')}",
                             event_type="analyst_directive", decision=d.get("type"), reason=d.get("text", "")[:500],
                             details=d)
            if d.get("type") == "invalidate_hypothesis":
                for h in hypotheses:
                    if h["id"] == d.get("hypothesis_id"):
                        h["status"], h["rationale"] = "refuted", f"invalidée par l'analyste : {d.get('text', '')}"

        available = ctx.gateway.available_tools()
        evidence = [_ev_dict(e) for e in ctx.store.list(ctx.investigation_id)]
        recent = state.get("observations", [])[-6:]
        context = {
            "mode": mode, "alert": ctx.alert, "alert_time": ctx.alert.get("timestamp"), "host": ctx.alert.get("host"),
            "observables": state.get("observables", []), "new_observables": state.get("new_observables", []),
            "checked_observables": state.get("checked_observables", []), "hypotheses": hypotheses,
            "steps": [s.model_dump() for s in current.steps], "evidence": evidence, "available_tools": available,
            "directives": directives, "max_new_steps": ctx.max_new_steps,
            "malicious_iocs": [i for i in state.get("malicious_iocs", []) if i not in state.get("pivoted", [])],
            "level": ctx.gateway.level,
        }
        done_steps = [{"id": s.id, "tool": s.tool, "args": s.args, "status": s.status, "result": s.result}
                      for s in current.steps if s.status != "pending"]
        user = prompts.render(
            prompts.PLAN, mode=prompts.PLAN_INITIAL if mode == "initial" else prompts.PLAN_REVISE,
            alert=wrap_untrusted(_compact_alert(ctx.alert), source="alerte"), alert_time=ctx.alert.get("timestamp"),
            host=ctx.alert.get("host"), hypotheses=hypotheses, observables=state.get("observables", [])[:30],
            new_observables=state.get("new_observables", []), done_steps=done_steps,
            observations=wrap_untrusted(recent, source="observations"), directives=directives or "aucune",
            tools=tools_for_prompt(available), max_new_steps=ctx.max_new_steps,
        )
        try:
            out = call_llm("plan", user, context)
        except LLMError as exc:
            if mode == "initial":
                out = call_llm("plan", user, context, ctx.fallback_llm)
                state = dict(state, llm_fallback=f"planification de secours : {exc}")
            else:
                out = {"rationale": f"révision impossible (LLM indisponible : {exc})", "changes": [], "steps":
                       [s.model_dump() for s in current.steps if s.status == "pending"]}

        kept = [s for s in current.steps if s.status != "pending"]
        used_ids = {s.id for s in kept}
        changes = list(out.get("changes") or [])
        new_pending: list[PlanStep] = []
        for raw in out.get("steps") or []:
            try:
                step = PlanStep(**{k: v for k, v in raw.items() if k in PlanStep.model_fields})
            except (ValidationError, TypeError) as exc:
                changes.append({"change": "étape ignorée", "justification": f"format invalide : {exc}"[:200]})
                continue
            if step.tool not in available:
                changes.append({"change": f"étape {step.id} ignorée", "justification": f"outil « {step.tool} » indisponible"})
                continue
            if step.id in used_ids:
                if any(s.id == step.id and s.status != "pending" for s in kept):
                    continue
                step.id = f"S{len(used_ids) + len(new_pending) + 1}"
            step.status = "pending"
            used_ids.add(step.id)
            new_pending.append(step)
        new_plan = Plan(version=current.version + 1, rationale=str(out.get("rationale", "")), steps=kept + new_pending)
        if out.get("hypotheses"):
            merged = []
            for i, h in enumerate(out["hypotheses"]):
                try:
                    merged.append(Hypothesis(**{"id": h.get("id") or f"H{i + 1}", **h}).model_dump())
                except (ValidationError, TypeError):
                    continue
            refuted = {h["id"] for h in hypotheses if h.get("status") == "refuted" and "analyste" in h.get("rationale", "")}
            for h in merged:
                if h["id"] in refuted:
                    h["status"] = "refuted"
            hypotheses = merged or hypotheses
        log_entry = {"version": new_plan.version, "mode": mode, "at": utcnow(), "rationale": new_plan.rationale,
                     "changes": changes}
        ctx.audit.append(
            investigation_id=ctx.investigation_id, actor="agent", event_type="plan", decision=mode,
            reason=new_plan.rationale[:500],
            details={"version": new_plan.version, "changes": changes[:20],
                     "steps": [{"id": s.id, "tool": s.tool, "objective": s.objective, "status": s.status}
                               for s in new_plan.steps]},
        )
        emit({"type": "plan", "mode": mode, "version": new_plan.version, "rationale": new_plan.rationale,
              "changes": changes, "steps": [s.model_dump() for s in new_plan.steps]})
        checked = list(dict.fromkeys(state.get("checked_observables", []) +
                                     [_obs_key(o) for o in state.get("new_observables", [])]))
        pivoted = list(state.get("pivoted", [])) + [i for i in state.get("malicious_iocs", [])
                                                     if i not in state.get("pivoted", [])]
        return {"plan": new_plan.model_dump(), "replan_log": state.get("replan_log", []) + [log_entry],
                "hypotheses": hypotheses, "needs_replan": False, "new_observables": [],
                "checked_observables": checked, "pivoted": pivoted,
                "replans": state.get("replans", 0) + (1 if mode == "revise" else 0),
                **({"llm_fallback": state["llm_fallback"]} if state.get("llm_fallback") else {})}

    # ------------------------------------------------------------------ agir
    def act(state: AgentState) -> AgentState:
        current = Plan(**state["plan"])
        usage.steps += 1
        stop = None
        if usage.steps > policy.budget("max_steps", 30):
            stop = f"budget d'étapes épuisé ({policy.budget('max_steps', 30)})"
        elif ctx.llm.total_tokens >= policy.budget("max_tokens", 100_000):
            stop = f"budget de jetons épuisé ({policy.budget('max_tokens', 100_000)})"
        elif usage.elapsed_s >= policy.budget("max_duration_s", 600):
            stop = f"durée maximale atteinte ({policy.budget('max_duration_s', 600)} s)"
        elif usage.total_calls >= policy.budget("max_tool_calls", 40):
            stop = f"budget d'appels d'outils épuisé ({policy.budget('max_tool_calls', 40)})"
        if stop:
            emit({"type": "stop", "reason": stop})
            return {"stop_reason": stop, "last_result": None, "current_step": None}

        pending = [s for s in current.steps if s.status == "pending"]
        if not pending:
            return {"stop_reason": "conclusion : plan exécuté, plus aucune vérification prévue", "last_result": None,
                    "current_step": None}
        budget = {"steps_left": int(policy.budget("max_steps", 30) - usage.steps),
                  "tool_calls_left": int(policy.budget("max_tool_calls", 40) - usage.total_calls),
                  "tokens_used": ctx.llm.total_tokens}
        user = prompts.render(
            prompts.ACT, plan=[{"id": s.id, "objective": s.objective, "tool": s.tool, "args": s.args, "status": s.status}
                               for s in current.steps],
            budget=budget, observations=wrap_untrusted(state.get("observations", [])[-4:], source="observations"),
        )
        try:
            out = call_llm("act", user, {"steps": [s.model_dump() for s in current.steps], "budget": budget})
        except LLMError as exc:
            return {"stop_reason": f"erreur du modèle de langage : {exc}", "last_result": None, "current_step": None}

        if out.get("action") != "call_tool":
            reason = str(out.get("reason") or "preuves jugées suffisantes")
            return {"stop_reason": f"conclusion : {reason}", "last_result": None, "current_step": None}
        step_id = out.get("step_id")
        step = next((s for s in current.steps if s.id == step_id and s.status == "pending"), None)
        tool = out.get("tool") or (step.tool if step else "")
        args = out.get("args") if isinstance(out.get("args"), dict) else (step.args if step else {})
        if step is None:
            step = PlanStep(id=f"A{len(current.steps) + 1}", objective=str(out.get("justification", "appel hors plan")),
                            tool=str(tool), args=args or {})
            current.steps.append(step)
        step.status, step.tool, step.args = "running", str(tool), args or {}
        emit({"type": "step_start", "step_id": step.id, "tool": step.tool, "args": step.args,
              "objective": step.objective})
        result = ctx.gateway.call(step.tool, step.args, str(out.get("justification") or step.objective))
        return {"plan": current.model_dump(), "last_result": result, "current_step": step.id}

    # -------------------------------------------------------------- observer
    def observe(state: AgentState) -> AgentState:
        current = Plan(**state["plan"])
        result: ToolResult = state["last_result"]
        step = next(s for s in current.steps if s.id == state["current_step"])
        step.audit_seq = result.audit_seq
        failures = list(state.get("failures", []))
        injections = list(state.get("injections", []))
        new_obs: list[dict[str, Any]] = list(state.get("new_observables", []))
        malicious = list(state.get("malicious_iocs", []))
        known = {_obs_key(o) for o in state.get("observables", [])} | set(state.get("checked_observables", []))
        known |= {_obs_key(o) for o in new_obs}
        observables = list(state.get("observables", []))
        replan = False

        if result.ok:
            evs = ctx.store.add_from_result(ctx.investigation_id, audit_seq=result.audit_seq, tool=result.tool,
                                            query=result.args, payload=result.payload)
            step.status = "done"
            step.evidence_ids = [e.evidence_id for e in evs]
            step.result = f"{len(evs)} élément(s) : {result.payload.get('meta', {}).get('note', '')}".strip(" :")
            for ev in evs:
                if ev.tool in LOG_TOOLS:
                    found = extract_observables(ev.excerpt, internal_domains)
                    register(found)
                    for o in found:
                        if o["type"] in CHECKABLE and not o["internal"] and _obs_key(o) not in known:
                            known.add(_obs_key(o))
                            new_obs.append(o)
                            observables.append(o)
                elif ev.tool in TI_TOOLS and ev.excerpt.get("verdict") == "malicious":
                    value = ev.excerpt.get("queried") or ev.excerpt.get("value")
                    if value and value not in malicious:
                        malicious.append(value)
                        replan = True
            if result.injection_findings:
                injections.append({"step_id": step.id, "tool": result.tool, "audit_seq": result.audit_seq,
                                   "findings": result.injection_findings[:5]})
            replan = replan or bool(new_obs) or (result.tool in LOG_TOOLS and bool(evs))
            summaries = [e.summary for e in evs[:8]]
        else:
            step.status = "failed"
            step.result = f"{result.status} : {result.error or result.reason}"
            failures.append({"step_id": step.id, "tool": result.tool, "status": result.status,
                             "reason": result.error or result.reason, "audit_seq": result.audit_seq})
            summaries = []
            replan = True

        observation = {"step_id": step.id, "tool": result.tool, "status": result.status,
                       "summary": result.summary(), "evidence_ids": step.evidence_ids, "items": summaries}
        emit({"type": "observation", **observation})
        # Plan épuisé : laisser au planificateur l'occasion d'ajouter des vérifications.
        if not any(s.status == "pending" for s in current.steps):
            replan = True
        update: AgentState = {
            "plan": current.model_dump(), "observations": state.get("observations", []) + [observation],
            "failures": failures, "injections": injections, "new_observables": new_obs, "malicious_iocs": malicious,
            "observables": observables, "last_result": None,
            "needs_replan": replan and state.get("replans", 0) < ctx.max_replans,
        }
        limit = int(policy.budget("max_consecutive_failures", 4))
        if usage.consecutive_failures >= limit:
            update["stop_reason"] = f"blocage : {usage.consecutive_failures} appels consécutifs refusés ou en échec"
            emit({"type": "stop", "reason": update["stop_reason"]})
        return update

    # -------------------------------------------------------------- conclure
    def conclude(state: AgentState) -> AgentState:
        current = Plan(**state["plan"])
        evidence = ctx.store.list(ctx.investigation_id)
        ev_dicts = [_ev_dict(e) for e in evidence]
        by_seq: dict[int, list[Any]] = {}
        for e in evidence:
            by_seq.setdefault(e.audit_seq, []).append(e)
        attack = []
        for s in current.steps:
            if s.tool == "attack_search" and s.status == "done" and s.audit_seq in by_seq:
                attack.append({"step_id": s.id, "query": s.args.get("query", ""), "related_evidence": s.related_evidence,
                               "results": [{"evidence_id": e.evidence_id, "technique_id": e.excerpt.get("technique_id"),
                                            "name": e.excerpt.get("name"), "tactics": e.excerpt.get("tactics", []),
                                            "score": e.excerpt.get("score"), "fragment_id": e.excerpt.get("fragment_id")}
                                           for e in by_seq[s.audit_seq]]})
        repair = bool(state.get("needs_repair"))
        context = {"investigation_id": ctx.investigation_id, "alert": ctx.alert, "evidence": ev_dicts, "attack": attack,
                   "hypotheses": state.get("hypotheses", []), "failures": state.get("failures", []),
                   "injections": state.get("injections", []), "stop_reason": state.get("stop_reason", ""),
                   "severity": state.get("severity", "medium"), "backend": ctx.backend,
                   "report": state.get("report", {})}
        if repair:
            task = "repair"
            user = prompts.render(prompts.REPAIR, errors=state.get("validation_feedback", []),
                                  valid_evidence=[e.evidence_id for e in evidence],
                                  valid_fragments=sorted({r["fragment_id"] for a in attack for r in a["results"]}),
                                  report=state.get("report", {}))
        else:
            task = "report"
            lines = [f"{e.evidence_id} | {e.observed_at or '-'} | {e.host or '-'} | {e.tool} | {e.event_type or '-'} | "
                     f"{e.summary[:350]}" + (" | FLAG:injection_suspected" if "injection_suspected" in e.flags else "")
                     for e in evidence[:150]]
            user = prompts.render(
                prompts.REPORT, alert=wrap_untrusted(_compact_alert(ctx.alert), source="alerte"),
                hypotheses=state.get("hypotheses", []), stop_reason=state.get("stop_reason", ""),
                evidence=wrap_untrusted("\n".join(lines), source="preuves", max_chars=60_000),
                attack=attack, failures=state.get("failures", []) or "aucun",
                injections=state.get("injections", []) or "aucune", shape=REPORT_JSON_SHAPE,
            )
        fallback_note = state.get("llm_fallback", "")
        try:
            out = call_llm(task, user, context)
            report = InvestigationReport(**out)
        except (LLMError, ValidationError, TypeError) as exc:
            fallback_note = f"rapport de secours produit par le modèle à règles ({type(exc).__name__} : {str(exc)[:200]})"
            report = InvestigationReport(**call_llm("report", user, context, ctx.fallback_llm))
        report.investigation_id = ctx.investigation_id
        report.alert_summary = ctx.alert.get("summary", "")
        report.stop_reason = state.get("stop_reason") or "conclusion"
        if fallback_note and fallback_note not in report.limitations:
            report.limitations.append(fallback_note)
        emit({"type": "report_draft", "verdict": report.verdict, "repair": repair})
        return {"report": report.model_dump(mode="json"), "needs_repair": False,
                "repair_attempts": state.get("repair_attempts", 0) + (1 if repair else 0)}

    # --------------------------------------------------------------- valider
    def validate(state: AgentState) -> AgentState:
        report = InvestigationReport(**state["report"])
        evidence = {e.evidence_id: e for e in ctx.store.list(ctx.investigation_id)}
        candidates = {(e.excerpt.get("technique_id"), e.excerpt.get("fragment_id"))
                      for e in evidence.values() if e.tool == "attack_search"}
        first = validate_report(report, evidence, ctx.rag, candidates)
        if not first.ok and state.get("repair_attempts", 0) < ctx.max_repairs and not isinstance(ctx.llm, OfflineLLM):
            emit({"type": "validation", "ok": False, "errors": [str(e) for e in first.errors][:10], "action": "repair"})
            return {"needs_repair": True, "validation_feedback": [str(e) for e in first.errors][:30]}
        corrections: list[str] = []
        if not first.ok:
            report, corrections = enforce_grounding(report, evidence, ctx.rag, candidates)
        final = validate_report(report, evidence, ctx.rag, candidates)
        validation = {"initial": first.to_dict(), "final": final.to_dict(), "corrections": corrections,
                      "repair_attempts": state.get("repair_attempts", 0)}
        ctx.audit.append(investigation_id=ctx.investigation_id, actor="agent", event_type="report_validation",
                         decision="ok" if final.ok else "errors", reason=f"ancrage {final.grounding_ratio:.0%}",
                         result_hash=hash_obj(report.model_dump(mode="json")), details=validation)
        emit({"type": "validation", "ok": final.ok, "grounding_ratio": final.grounding_ratio,
              "corrections": corrections})
        return {"report": report.model_dump(mode="json"), "validation": validation, "needs_repair": False}

    # ---------------------------------------------------------------- routage
    def after_act(state: AgentState) -> str:
        return "conclude" if state.get("stop_reason") else "observe"

    def after_observe(state: AgentState) -> str:
        if state.get("stop_reason"):
            return "conclude"
        return "plan" if state.get("needs_replan") else "act"

    def after_validate(state: AgentState) -> str:
        return "conclude" if state.get("needs_repair") else END

    g = StateGraph(AgentState)
    g.add_node("qualify", qualify)
    g.add_node("plan", plan)
    g.add_node("act", act)
    g.add_node("observe", observe)
    g.add_node("conclude", conclude)
    g.add_node("validate", validate)
    g.set_entry_point("qualify")
    g.add_edge("qualify", "plan")
    g.add_edge("plan", "act")
    g.add_conditional_edges("act", after_act, {"observe": "observe", "conclude": "conclude"})
    g.add_conditional_edges("observe", after_observe, {"plan": "plan", "act": "act", "conclude": "conclude"})
    g.add_edge("conclude", "validate")
    g.add_conditional_edges("validate", after_validate, {"conclude": "conclude", END: END})
    return g.compile()
