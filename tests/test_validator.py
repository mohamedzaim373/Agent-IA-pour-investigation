"""Validation du rapport : aucune affirmation sans preuve (ENF-01, EF-13, EF-14)."""

from __future__ import annotations

from dataclasses import dataclass, field

from agent.report_models import InvestigationReport
from agent.validator import enforce_grounding, validate_report


@dataclass
class FakeEvidence:
    evidence_id: str
    tool: str
    observed_at: str | None
    excerpt: dict = field(default_factory=dict)


EVIDENCE = {
    "EV-001": FakeEvidence("EV-001", "search_logs", "2026-10-12T09:14:03.200+00:00", {"summary": "powershell -enc"}),
    "EV-002": FakeEvidence("EV-002", "attack_search", None, {"technique_id": "T1059.001", "fragment_id": "T1059.001#0"}),
    "EV-003": FakeEvidence("EV-003", "misp_lookup", None, {"value": "203.0.113.45", "verdict": "malicious"}),
}
CANDIDATES = {("T1059.001", "T1059.001#0")}


def good_report(**overrides) -> InvestigationReport:
    data = {
        "verdict": "true_positive", "severity": "high", "confidence": 0.8, "summary": "ok",
        "timeline": [{"timestamp": "2026-10-12T09:14:03Z", "host": "WIN10-01", "description": "PowerShell encodé",
                      "kind": "observed", "confidence": 0.9, "evidence_ids": ["EV-001"], "techniques": ["T1059.001"]}],
        "techniques": [{"technique_id": "T1059.001", "name": "PowerShell", "evidence_ids": ["EV-001", "EV-002"],
                        "fragment_ids": ["T1059.001#0"], "confidence": 0.8}],
        "iocs": [{"type": "ip", "value": "203.0.113.45", "verdict": "malicious", "evidence_ids": ["EV-003"]}],
    }
    data.update(overrides)
    return InvestigationReport(**data)


def test_valid_report(rag):
    res = validate_report(good_report(), EVIDENCE, rag, CANDIDATES)
    assert res.ok, res.to_dict()
    assert res.grounding_ratio == 1.0 and res.claims_total == 3


def test_fabricated_evidence_detected(rag):
    report = good_report(timeline=[{"timestamp": "2026-10-12T09:14:03Z", "description": "inventé", "kind": "observed",
                                    "evidence_ids": ["EV-999"]}])
    res = validate_report(report, EVIDENCE, rag, CANDIDATES)
    assert not res.ok and any("EV-999" in str(e) for e in res.errors)


def test_claim_without_evidence_detected(rag):
    report = good_report(timeline=[{"timestamp": "2026-10-12T09:14:03Z", "description": "sans preuve",
                                    "kind": "inferred", "evidence_ids": []}])
    assert any("sans preuve" in str(e) for e in validate_report(report, EVIDENCE, rag, CANDIDATES).errors)


def test_timestamp_must_match_evidence(rag):
    report = good_report(timeline=[{"timestamp": "2026-10-12T15:00:00Z", "description": "décalé", "kind": "observed",
                                    "evidence_ids": ["EV-001"]}])
    res = validate_report(report, EVIDENCE, rag, CANDIDATES)
    assert any("horodatage" in str(e) for e in res.errors)
    fixed, changes = enforce_grounding(report, EVIDENCE, rag, CANDIDATES)
    assert fixed.timeline[0].timestamp.startswith("2026-10-12T09:14:03") and changes


def test_technique_not_from_attack_search(rag):
    report = good_report(techniques=[{"technique_id": "T1003.001", "evidence_ids": ["EV-001"],
                                      "fragment_ids": ["T1003.001#0"]}])
    res = validate_report(report, EVIDENCE, rag, CANDIDATES)
    assert any("attack_search" in str(e) for e in res.errors)


def test_unknown_technique_and_fragment(rag):
    report = good_report(techniques=[{"technique_id": "T9999", "evidence_ids": ["EV-001"], "fragment_ids": ["T9999#0"]}])
    errors = [str(e) for e in validate_report(report, EVIDENCE, rag, set()).errors]
    assert any("inconnu" in e for e in errors) and any("inexistant" in e for e in errors)


def test_enforce_grounding_downgrades_and_removes(rag):
    report = good_report(
        timeline=[{"timestamp": "2026-10-12T09:14:03Z", "description": "inventé", "kind": "observed",
                   "confidence": 0.9, "evidence_ids": ["EV-999"]}],
        techniques=[{"technique_id": "T1003.001", "evidence_ids": [], "fragment_ids": []}],
        iocs=[{"type": "ip", "value": "198.51.100.1", "verdict": "malicious", "evidence_ids": []}],
    )
    fixed, changes = enforce_grounding(report, EVIDENCE, rag, CANDIDATES)
    assert fixed.timeline[0].kind == "hypothesis" and fixed.timeline[0].confidence <= 0.3
    assert fixed.techniques == []
    assert fixed.iocs[0].verdict == "unknown"
    assert fixed.verdict == "needs_investigation"  # plus aucun fait observé étayé
    assert len(changes) >= 4 and fixed.limitations
    assert validate_report(fixed, EVIDENCE, rag, CANDIDATES).ok


def test_hypotheses_are_not_claims(rag):
    report = good_report(timeline=good_report().timeline + [
        {"timestamp": "2026-10-12T09:20:00Z", "description": "piste", "kind": "hypothesis", "confidence": 0.3}])
    res = validate_report(report, EVIDENCE, rag, CANDIDATES)
    assert res.ok and res.claims_total == 3


def test_report_model_aliases():
    r = InvestigationReport(verdict="Faux positif", severity="Élevée", confidence=3)
    assert r.verdict == "false_positive" and r.severity == "high" and r.confidence == 1.0
