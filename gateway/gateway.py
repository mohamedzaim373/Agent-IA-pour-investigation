"""Passerelle d'outils : point d'entrée unique vers les sources (chapitre 6.1).

Pour chaque appel demandé par l'agent :

  1. validation stricte des paramètres (GP-04) ;
  2. décision de la politique : autoriser, soumettre à l'analyste, refuser ;
  3. sollicitation de l'analyste si nécessaire (EF-19) ;
  4. exécution par le connecteur, avec délai maximal et gestion d'erreurs (ENF-04) ;
     les secrets sont détenus par les connecteurs, jamais par le LLM (GP-06) ;
  5. détection d'injection dans le résultat (GP-07) ;
  6. journalisation chaînée de l'appel, de la décision et de l'empreinte du
     résultat (GT-01).

L'agent n'appelle jamais un connecteur directement : il ne reçoit que des
`ToolResult`.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass, field
from typing import Any, Callable

from pydantic import BaseModel, ValidationError

from connectors.base import ConnectorError

from gateway.approval import ApprovalRequest, Approver
from gateway.audit import AuditLog
from gateway.hashing import hash_obj
from gateway.injection import scan_payload
from gateway.policy import AnalystIdentity, BudgetUsage, Decision, IdentityDirectory, Policy
from gateway.tool_schemas import TOOL_SCHEMAS

Executor = Callable[[BaseModel], dict[str, Any]]
EventSink = Callable[[dict[str, Any]], None]

_POOL = ThreadPoolExecutor(max_workers=8, thread_name_prefix="tool")


@dataclass
class ToolResult:
    tool: str
    status: str  # ok | denied | rejected | error
    args: dict[str, Any]
    decision: str
    reason: str
    payload: dict[str, Any] | None = None
    audit_seq: int | None = None
    error: str | None = None
    injection_findings: list[dict[str, Any]] = field(default_factory=list)
    duration_ms: float = 0.0
    approval: dict[str, Any] | None = None

    @property
    def ok(self) -> bool:
        return self.status == "ok"

    @property
    def items(self) -> list[dict[str, Any]]:
        return list((self.payload or {}).get("items") or [])

    def summary(self) -> str:
        if self.ok:
            return f"{self.tool} : {len(self.items)} résultat(s)"
        return f"{self.tool} : {self.status} — {self.error or self.reason}"


class ToolGateway:
    def __init__(
        self,
        *,
        policy: Policy,
        executors: dict[str, Executor],
        audit: AuditLog,
        analyst: AnalystIdentity,
        level: str,
        investigation_id: str,
        approver: Approver | None = None,
        identities: IdentityDirectory | None = None,
        usage: BudgetUsage | None = None,
        on_event: EventSink | None = None,
    ):
        self.policy = policy
        self.executors = executors
        self.audit = audit
        self.analyst = analyst
        self.level = level
        self.investigation_id = investigation_id
        self.approver = approver
        self.identities = identities
        self.usage = usage or BudgetUsage()
        self.on_event = on_event or (lambda _e: None)

    # -------------------------------------------------------------- découverte
    def available_tools(self) -> list[str]:
        """Outils que l'agent peut demander (déclarés, actifs, dans les droits)."""
        names = []
        for name, cfg in self.policy.tools.items():
            if name not in TOOL_SCHEMAS or not cfg.get("enabled", False):
                continue
            if cfg.get("risk") == "action":
                continue
            if name in self.analyst.tools and name in self.executors:
                names.append(name)
        return names

    # ------------------------------------------------------------------ appel
    def call(self, tool: str, raw_args: dict[str, Any] | None, justification: str = "") -> ToolResult:
        raw_args = dict(raw_args or {})
        started = time.perf_counter()
        base_details = {"on_behalf_of": self.analyst.analyst_id, "level": self.level, "justification": justification[:500]}

        spec = TOOL_SCHEMAS.get(tool)
        if spec is None:
            return self._refuse(tool, raw_args, f"outil « {tool} » inconnu", "GP-01", base_details, started)
        try:
            args = spec.args_model.model_validate(raw_args)
        except ValidationError as exc:
            msg = "; ".join(f"{'.'.join(map(str, e['loc'])) or 'args'}: {e['msg']}" for e in exc.errors()[:5])
            return self._refuse(tool, raw_args, f"paramètres invalides — {msg}", "GP-04", base_details, started)
        args_json = args.model_dump(mode="json")

        decision = self.policy.decide(tool, args, level=self.level, analyst=self.analyst, usage=self.usage)
        if decision.decision == Decision.DENY:
            return self._refuse(tool, args_json, decision.reason, decision.rule, base_details, started, risk=decision.risk)

        approval_info = None
        final_decision = "allow"
        if decision.decision == Decision.NEEDS_APPROVAL:
            approved, approval_info = self._ask_approval(tool, args_json, justification, decision.risk, decision.reason)
            if not approved:
                self.usage.approvals_rejected += 1
                self.usage.consecutive_failures += 1
                duration = (time.perf_counter() - started) * 1000
                self.on_event({"type": "tool_rejected", "tool": tool, "args": args_json, "reason": approval_info["reason"]})
                return ToolResult(tool, "rejected", args_json, "rejected", approval_info["reason"],
                                  duration_ms=duration, approval=approval_info)
            final_decision = "approved"

        # ----------------------------------------------------------- exécution
        executor = self.executors.get(tool)
        cfg = self.policy.tools.get(tool, {})
        timeout = float(cfg.get("timeout_s", 20))
        self.on_event({"type": "tool_call", "tool": tool, "args": args_json, "justification": justification})
        payload, error = None, None
        if executor is None:
            error = f"aucun connecteur configuré pour « {tool} »"
        else:
            for attempt in (1, 2):
                try:
                    payload = _POOL.submit(executor, args).result(timeout=timeout)
                    error = None
                    break
                except FutureTimeout:
                    error = f"délai de {timeout:.0f} s dépassé"
                except ConnectorError as exc:
                    error = str(exc)
                    if not exc.transient:
                        break
                except Exception as exc:  # ENF-04 : jamais d'interruption brutale
                    error = f"{type(exc).__name__}: {exc}"
                    break
                if attempt == 1:
                    time.sleep(0.2)
        if error is None and (not isinstance(payload, dict) or not isinstance(payload.get("items"), list)):
            error = "réponse du connecteur mal formée"

        duration = (time.perf_counter() - started) * 1000
        details = dict(base_details)
        if approval_info:
            details["approval"] = approval_info

        if error is not None:
            self.usage.errors += 1
            self.usage.consecutive_failures += 1
            self.usage.calls_by_tool[tool] += 1
            self.usage.total_calls += 1
            entry = self.audit.append(
                investigation_id=self.investigation_id, actor="agent", event_type="tool_error", tool=tool,
                params=args_json, decision=final_decision, reason=error, duration_ms=duration, details=details,
            )
            self.on_event({"type": "tool_error", "tool": tool, "error": error})
            return ToolResult(tool, "error", args_json, final_decision, decision.reason, audit_seq=entry.seq,
                              error=error, duration_ms=duration, approval=approval_info)

        payload, findings = scan_payload(payload)
        payload.setdefault("meta", {})
        if not payload["items"]:
            payload["meta"].setdefault("note", "aucun résultat")
        result_hash = hash_obj(payload)
        self.usage.calls_by_tool[tool] += 1
        self.usage.total_calls += 1
        self.usage.consecutive_failures = 0
        details["items"] = len(payload["items"])
        entry = self.audit.append(
            investigation_id=self.investigation_id, actor="agent", event_type="tool_call", tool=tool,
            params=args_json, result_hash=result_hash, decision=final_decision, reason=decision.reason,
            duration_ms=duration, details=details,
        )
        finding_dicts = [f.to_dict() for f in findings]
        if findings:
            self.audit.append(
                investigation_id=self.investigation_id, actor="system", event_type="injection_detected", tool=tool,
                decision="flagged", reason=f"{len(findings)} motif(s) d'injection dans le résultat de l'audit {entry.seq}",
                details={"audit_seq": entry.seq, "findings": finding_dicts[:10]},
            )
            self.on_event({"type": "injection_detected", "tool": tool, "count": len(findings)})
        self.on_event({"type": "tool_result", "tool": tool, "items": len(payload["items"]), "audit_seq": entry.seq})
        return ToolResult(tool, "ok", args_json, final_decision, decision.reason, payload=payload, audit_seq=entry.seq,
                          injection_findings=finding_dicts, duration_ms=duration, approval=approval_info)

    # --------------------------------------------------------------- internes
    def _refuse(self, tool, args, reason, rule, details, started, risk=None) -> ToolResult:
        self.usage.denied += 1
        self.usage.consecutive_failures += 1
        duration = (time.perf_counter() - started) * 1000
        d = dict(details, rule=rule, risk=risk)
        entry = self.audit.append(
            investigation_id=self.investigation_id, actor="agent", event_type="tool_denied", tool=tool,
            params=args, decision="deny", reason=reason, duration_ms=duration, details=d,
        )
        self.on_event({"type": "tool_denied", "tool": tool, "reason": reason})
        return ToolResult(tool, "denied", args if isinstance(args, dict) else {}, "deny", reason,
                          audit_seq=entry.seq, duration_ms=duration)

    def _ask_approval(self, tool, args_json, justification, risk, policy_reason) -> tuple[bool, dict[str, Any]]:
        self.usage.approvals_requested += 1
        req_entry = self.audit.append(
            investigation_id=self.investigation_id, actor="agent", event_type="approval_request", tool=tool,
            params=args_json, decision="needs_approval", reason=policy_reason,
            details={"justification": justification[:500], "risk": risk, "level": self.level},
        )
        self.on_event({"type": "approval_pending", "tool": tool, "args": args_json, "justification": justification,
                       "risk": risk, "audit_seq": req_entry.seq})
        if self.approver is None:
            approved, analyst_id, reason, approval_id = False, "system", "aucun approbateur disponible", None
        else:
            dec = self.approver.request(ApprovalRequest(
                investigation_id=self.investigation_id, tool=tool, args=args_json, justification=justification,
                risk=risk, policy_reason=policy_reason, level=self.level,
            ))
            approved, analyst_id, reason, approval_id = dec.approved, dec.analyst_id, dec.reason, dec.approval_id
            if approved and self.identities is not None and analyst_id not in {"auto"}:
                try:
                    approver_identity = self.identities.get(analyst_id)
                    if not approver_identity.can_approve:
                        approved, reason = False, f"{analyst_id} n'est pas habilité à approuver"
                except KeyError:
                    approved, reason = False, f"approbateur inconnu : {analyst_id}"
        info = {"approved": approved, "analyst_id": analyst_id, "reason": reason, "approval_id": approval_id,
                "request_audit_seq": req_entry.seq}
        self.audit.append(
            investigation_id=self.investigation_id, actor=f"analyst:{analyst_id}", event_type="approval_decision",
            tool=tool, params=args_json, decision="approved" if approved else "rejected", reason=reason,
            details={"approval_id": approval_id, "request_audit_seq": req_entry.seq},
        )
        return approved, info
