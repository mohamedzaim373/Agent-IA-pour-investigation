"""Investigations de bout en bout sur les scénarios (critères de recette, chapitre 18)."""

from __future__ import annotations

import queue
from pathlib import Path

import pytest

from agent.llm.offline import OfflineLLM
from agent.report_models import InvestigationReport
from gateway.approval import AutoApprover


@pytest.mark.parametrize("sid", ["S1", "S2", "S3", "S4", "S5"])
def test_scenario_verdict_and_traceability(investigator, scenarios, sid):
    scenario = scenarios[sid]
    out = investigator.investigate(scenario["alert"], analyst_id="jdupont", autonomy_level="N2",
                                   approver=AutoApprover(True, "jdupont"), scenario=scenario)
    assert out.status == "completed", out.error
    assert out.verdict == scenario["ground_truth"]["verdict"]
    InvestigationReport(**out.report)  # rapport conforme au modèle
    final = out.validation["final"]
    assert final["ok"] and final["grounding_ratio"] >= 0.95  # ENF-01
    assert out.audit["ok"]  # intégrité du journal
    evidence = {e.evidence_id: e for e in investigator.store.list(out.investigation_id)}
    seqs = {e.seq for e in investigator.audit.entries(out.investigation_id)}
    for entry in out.report["timeline"]:
        for ev_id in entry["evidence_ids"]:  # GT-03 : affirmation -> preuve -> entrée d'audit
            assert ev_id in evidence and evidence[ev_id].audit_seq in seqs
    assert Path(out.files["markdown"]).exists() and "## Chronologie" in out.markdown
    meta = investigator.store.get_investigation(out.investigation_id)["metadata"]
    assert meta["llm"]["provider"] == "offline" and len(meta["policy"]["sha256"]) == 64  # GT-05
    assert out.usage["elapsed_s"] < 600  # ENF-02


def test_plan_is_visible_and_revised_with_justification(investigator, scenarios):
    scenario = scenarios["S1"]
    out = investigator.investigate(scenario["alert"], analyst_id="jdupont", autonomy_level="N2",
                                   approver=AutoApprover(True, "jdupont"), scenario=scenario)
    assert len(out.replan_log) >= 2 and out.replan_log[0]["mode"] == "initial"
    revisions = [r for r in out.replan_log if r["mode"] == "revise" and r["changes"]]
    assert revisions and all(c.get("justification") for r in revisions for c in r["changes"])
    plan_entries = [e for e in investigator.audit.entries(out.investigation_id) if e.event_type == "plan"]
    assert len(plan_entries) == len(out.replan_log)
    assert out.report["stop_reason"].startswith("conclusion")


def test_n1_requests_approval_for_external_ti(investigator, scenarios):
    approver = AutoApprover(False, "jdupont", "pas d'exposition externe")
    scenario = scenarios["S1"]
    out = investigator.investigate(scenario["alert"], analyst_id="jdupont", autonomy_level="N1",
                                   approver=approver, scenario=scenario)
    assert approver.requests and all(r.tool == "ti_lookup" for r in approver.requests)
    assert out.status == "completed" and out.verdict == "true_positive"  # MISP suffit
    assert any("ti_lookup" in lim for lim in out.report["limitations"])


def test_n0_with_refusals_stops_on_blocking(investigator, scenarios):
    scenario = scenarios["S1"]
    out = investigator.investigate(scenario["alert"], analyst_id="jdupont", autonomy_level="N0",
                                   approver=AutoApprover(False, "jdupont", "refus"), scenario=scenario)
    assert out.status == "completed"
    assert out.report["stop_reason"].startswith("blocage")
    assert out.verdict != "true_positive"  # rien d'observé : pas de conclusion hâtive
    assert out.usage["total_calls"] == 0


def test_tool_failures_are_reported_not_fatal(investigator, scenarios):
    scenario = dict(scenarios["S1"], faults={"misp_lookup": "unavailable", "ti_lookup": "timeout"})
    out = investigator.investigate(scenario["alert"], analyst_id="jdupont", autonomy_level="N2",
                                   approver=AutoApprover(True, "jdupont"), scenario=scenario)
    assert out.status == "completed"
    assert out.failures and any("indisponible" in f["reason"] for f in out.failures)
    assert any("non abouti" in lim for lim in out.report["limitations"])


def test_budget_exhaustion_is_reported(investigator, scenarios):
    investigator.policy.budgets["max_steps"] = 3
    scenario = scenarios["S2"]
    out = investigator.investigate(scenario["alert"], analyst_id="jdupont", autonomy_level="N2",
                                   approver=AutoApprover(True, "jdupont"), scenario=scenario)
    assert out.status == "completed" and "budget" in out.report["stop_reason"]


def test_analyst_directive_invalidates_hypothesis(investigator, scenarios):
    directives: queue.Queue = queue.Queue()
    directives.put({"type": "invalidate_hypothesis", "hypothesis_id": "H2", "text": "pas d'outil SCCM sur ce poste",
                    "analyst_id": "jdupont"})
    scenario = scenarios["S1"]
    out = investigator.investigate(scenario["alert"], analyst_id="jdupont", autonomy_level="N2",
                                   approver=AutoApprover(True, "jdupont"), scenario=scenario, directives=directives)
    entries = investigator.audit.entries(out.investigation_id)
    assert any(e.event_type == "analyst_directive" and e.actor == "analyst:jdupont" for e in entries)


def test_llm_failure_falls_back_to_baseline(investigator, scenarios):
    class BrokenLLM(OfflineLLM):
        provider, model = "broken", "broken"

        def _task_report(self, ctx):
            raise RuntimeError("API indisponible")

    investigator.llm_factory = lambda _p: BrokenLLM()
    scenario = scenarios["S4"]
    out = investigator.investigate(scenario["alert"], analyst_id="jdupont", autonomy_level="N2",
                                   approver=AutoApprover(True, "jdupont"), scenario=scenario)
    assert out.status == "completed" and out.verdict == "false_positive"
    assert any("secours" in lim for lim in out.report["limitations"])
    assert any(e.event_type == "llm_error" for e in investigator.audit.entries(out.investigation_id))


def test_hallucinating_llm_is_corrected(investigator, scenarios):
    """Un modèle qui invente preuves et techniques : le rapport final reste étayé."""

    class Hallucinating(OfflineLLM):
        provider, model = "hallucinating", "test"

        def _task_report(self, ctx):
            report = super()._task_report(ctx)
            report["timeline"].append({"timestamp": "2026-10-12T09:30:00Z", "host": "WIN-SRV01",
                                       "description": "Mouvement latéral vers le contrôleur de domaine",
                                       "kind": "observed", "confidence": 0.9, "evidence_ids": ["EV-999"]})
            report["techniques"].append({"technique_id": "T1021.002", "name": "SMB", "evidence_ids": ["EV-999"],
                                         "fragment_ids": ["T1021.002#0"], "confidence": 0.9})
            return report

    investigator.llm_factory = lambda _p: Hallucinating()
    scenario = scenarios["S1"]
    out = investigator.investigate(scenario["alert"], analyst_id="jdupont", autonomy_level="N2",
                                   approver=AutoApprover(True, "jdupont"), scenario=scenario)
    assert not out.validation["initial"]["ok"]
    assert out.validation["final"]["ok"] and out.validation["corrections"]
    assert "T1021.002" not in {t["technique_id"] for t in out.report["techniques"]}
    lateral = [e for e in out.report["timeline"] if "latéral" in e["description"]]
    assert lateral and lateral[0]["kind"] == "hypothesis"


def test_invalid_alert_rejected(investigator):
    from agent.entities import AlertFormatError

    with pytest.raises(AlertFormatError):
        investigator.investigate({"foo": "bar"}, analyst_id="jdupont")


def test_manual_alert_entry(investigator, scenarios):
    manual = {"manual": True, "title": "Signalement utilisateur", "host": "WIN10-01", "user": "LAB\\jdoe",
              "timestamp": "2026-10-12T09:14:00Z", "description": "Fenêtre PowerShell apparue brièvement",
              "observables": [{"type": "ip", "value": "203.0.113.45"}]}
    out = investigator.investigate(manual, analyst_id="jdupont", autonomy_level="N2",
                                   approver=AutoApprover(True, "jdupont"), scenario=scenarios["S1"])
    assert out.status == "completed" and out.verdict == "true_positive"
