"""Tests de la passerelle : action, fenêtre, paramètres, budget (A–D) et compléments."""

from __future__ import annotations

import copy
import time

import pytest

from connectors.base import ConnectorError
from gateway.approval import AutoApprover
from gateway.gateway import ToolGateway
from gateway.policy import Policy

START = "2026-10-12T08:00:00Z"
END = "2026-10-12T10:00:00Z"


def ok_executor(args):
    return {"items": [{"source": "test", "summary": "élément", "value": getattr(args, "value", None)}], "meta": {}}


EXECUTORS = {name: ok_executor for name in
             ("search_logs", "get_process_tree", "misp_lookup", "ti_lookup", "attack_search", "isolate_host")}


def make_gateway(policy, audit, identities, *, level="N2", analyst="jdupont", approver=None, executors=None):
    return ToolGateway(policy=policy, executors=executors or EXECUTORS, audit=audit,
                       analyst=identities.get(analyst), level=level, investigation_id="INV-TEST",
                       approver=approver, identities=identities)


# ------------------------------------------------------------------ A : action
@pytest.mark.parametrize("level", ["N0", "N1", "N2", "N3"])
def test_a_action_is_always_denied(policy, audit, identities, level):
    gw = make_gateway(policy, audit, identities, level=level, approver=AutoApprover(True, "jdupont"))
    res = gw.call("isolate_host", {"host": "WIN10-01", "reason": "confinement"}, "test")
    assert res.status == "denied"
    assert gw.usage.total_calls == 0
    entry = audit.entries("INV-TEST")[-1]
    assert entry.event_type == "tool_denied" and entry.decision == "deny"


def test_a_irreversible_action_denied_even_if_enabled(audit, identities, policy):
    data = copy.deepcopy(policy.data)
    data["tools"]["isolate_host"].update(enabled=True, reversible=False)
    res = make_gateway(Policy(data), audit, identities, level="N2").call(
        "isolate_host", {"host": "WIN10-01", "reason": "x" * 5})
    assert res.status == "denied" and "irréversible" in res.reason


# ----------------------------------------------------------------- B : fenêtre
def test_b_window_too_large_denied(policy, audit, identities):
    gw = make_gateway(policy, audit, identities)
    res = gw.call("search_logs", {"start": "2026-10-11T00:00:00Z", "end": "2026-10-12T02:00:00Z"})
    assert res.status == "denied" and "fenêtre" in res.reason
    ok = gw.call("search_logs", {"start": START, "end": END})
    assert ok.status == "ok"


def test_b_index_not_allowed(policy, audit, identities):
    res = make_gateway(policy, audit, identities).call("search_logs", {"start": START, "end": END,
                                                                       "index": "security-auditlog-*"})
    assert res.status == "denied" and "index" in res.reason


# -------------------------------------------------------------- C : paramètres
@pytest.mark.parametrize("args", [
    {"start": START, "end": END, "unexpected": 1},             # champ inconnu
    {"start": "pas une date", "end": END},                      # type invalide
    {"start": END, "end": START},                               # fenêtre inversée
    {"start": START, "end": END, "limit": 5000},                # taille maximale du schéma
    {"start": START, "end": END, "host": "WIN10-01; rm -rf /"},  # caractères interdits
])
def test_c_invalid_parameters_denied(policy, audit, identities, args):
    res = make_gateway(policy, audit, identities).call("search_logs", args)
    assert res.status == "denied" and "paramètres invalides" in res.reason


def test_c_max_results_from_policy(policy, audit, identities):
    res = make_gateway(policy, audit, identities).call("search_logs", {"start": START, "end": END, "limit": 500})
    assert res.status == "denied" and "limite" in res.reason


def test_c_unknown_tool_denied(policy, audit, identities):
    res = make_gateway(policy, audit, identities).call("delete_logs", {})
    assert res.status == "denied" and "inconnu" in res.reason


# ------------------------------------------------------------------ D : budget
def test_d_budget_per_tool(policy, audit, identities):
    data = copy.deepcopy(policy.data)
    data["tools"]["misp_lookup"]["max_calls"] = 2
    gw = make_gateway(Policy(data), audit, identities)
    results = [gw.call("misp_lookup", {"value": f"203.0.113.{i}", "type": "ip"}) for i in range(3)]
    assert [r.status for r in results] == ["ok", "ok", "denied"]
    assert "budget" in results[2].reason


def test_d_global_budget(policy, audit, identities):
    data = copy.deepcopy(policy.data)
    data["budgets"]["max_tool_calls"] = 1
    gw = make_gateway(Policy(data), audit, identities)
    assert gw.call("misp_lookup", {"value": "203.0.113.1", "type": "ip"}).ok
    assert gw.call("attack_search", {"query": "powershell"}).status == "denied"


# ------------------------------------------------- niveaux et validation humaine
def test_n0_requires_approval_for_every_call(policy, audit, identities):
    approver = AutoApprover(False, "jdupont", "refus de test")
    gw = make_gateway(policy, audit, identities, level="N0", approver=approver)
    res = gw.call("search_logs", {"start": START, "end": END}, "contexte")
    assert res.status == "rejected"
    assert approver.requests and approver.requests[0].justification == "contexte"
    decision = [e for e in audit.entries("INV-TEST") if e.event_type == "approval_decision"][-1]
    assert decision.actor == "analyst:jdupont" and decision.decision == "rejected" and decision.reason == "refus de test"


def test_n0_approved_call_is_executed_and_traced(policy, audit, identities):
    gw = make_gateway(policy, audit, identities, level="N0", approver=AutoApprover(True, "mmanager", "ok"))
    res = gw.call("misp_lookup", {"value": "203.0.113.9", "type": "ip"})
    assert res.ok and res.decision == "approved"
    call = [e for e in audit.entries("INV-TEST") if e.event_type == "tool_call"][-1]
    assert call.details["approval"]["analyst_id"] == "mmanager"


def test_n1_external_ti_needs_approval_n2_does_not(policy, audit, identities):
    args = {"value": "203.0.113.9", "type": "ip"}
    n1 = make_gateway(policy, audit, identities, level="N1", approver=None).call("ti_lookup", args)
    assert n1.status == "rejected"  # aucun approbateur : refus par défaut
    n2 = make_gateway(policy, audit, identities, level="N2").call("ti_lookup", args)
    assert n2.ok


def test_approver_must_be_entitled(policy, audit, identities):
    gw = make_gateway(policy, audit, identities, level="N0", approver=AutoApprover(True, "aaudit"))
    assert gw.call("misp_lookup", {"value": "203.0.113.9", "type": "ip"}).status == "rejected"


def test_internal_observable_never_sent_to_ti(policy, audit, identities):
    gw = make_gateway(policy, audit, identities, level="N2")
    for value, otype in [("192.168.56.20", "ip"), ("dc01.lab.local", "domain"), ("http://10.0.0.5/x", "url")]:
        res = gw.call("ti_lookup", {"value": value, "type": otype})
        assert res.status == "denied" and "GP-08" in res.reason


def test_delegated_identity_limits_tools(policy, audit, identities):
    gw = make_gateway(policy, audit, identities, level="N2", analyst="jjunior")
    res = gw.call("ti_lookup", {"value": "203.0.113.9", "type": "ip"})
    assert res.status == "denied" and "droits" in res.reason
    assert "ti_lookup" not in gw.available_tools()


# ---------------------------------------------------------------- robustesse
def test_connector_error_does_not_crash(policy, audit, identities):
    def failing(_args):
        raise ConnectorError("service indisponible", transient=True)

    gw = make_gateway(policy, audit, identities, executors=dict(EXECUTORS, misp_lookup=failing))
    res = gw.call("misp_lookup", {"value": "203.0.113.9", "type": "ip"})
    assert res.status == "error" and "indisponible" in res.error
    assert audit.entries("INV-TEST")[-1].event_type == "tool_error"


def test_timeout_is_enforced(policy, audit, identities):
    data = copy.deepcopy(policy.data)
    data["tools"]["misp_lookup"]["timeout_s"] = 0.2

    def slow(_args):
        time.sleep(1.0)
        return {"items": [], "meta": {}}

    gw = make_gateway(Policy(data), audit, identities, executors=dict(EXECUTORS, misp_lookup=slow))
    started = time.perf_counter()
    res = gw.call("misp_lookup", {"value": "203.0.113.9", "type": "ip"})
    assert res.status == "error" and "délai" in res.error
    assert time.perf_counter() - started < 2.0


def test_malformed_connector_response(policy, audit, identities):
    gw = make_gateway(policy, audit, identities, executors=dict(EXECUTORS, misp_lookup=lambda a: ["pas", "un", "dict"]))
    assert gw.call("misp_lookup", {"value": "203.0.113.9", "type": "ip"}).status == "error"


def test_result_hash_is_audited(policy, audit, identities):
    from gateway.hashing import hash_obj

    res = make_gateway(policy, audit, identities).call("misp_lookup", {"value": "203.0.113.9", "type": "ip"})
    assert audit.get(res.audit_seq).result_hash == hash_obj(res.payload)
