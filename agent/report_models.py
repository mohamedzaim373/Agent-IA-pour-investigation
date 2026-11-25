"""Modèles de données de l'investigation et du rapport (EF-04, EF-13 à EF-15)."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Verdict(str, Enum):
    true_positive = "true_positive"
    false_positive = "false_positive"
    needs_investigation = "needs_investigation"  # « à approfondir »


VERDICT_FR = {
    "true_positive": "Vrai positif",
    "false_positive": "Faux positif",
    "needs_investigation": "À approfondir",
}


class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class ClaimKind(str, Enum):
    observed = "observed"      # fait observé dans une source
    inferred = "inferred"      # déduit de faits observés
    hypothesis = "hypothesis"  # piste non vérifiée


class _Model(BaseModel):
    model_config = ConfigDict(extra="ignore", use_enum_values=True)


def _clamp(v: Any) -> float:
    try:
        return max(0.0, min(1.0, float(v)))
    except (TypeError, ValueError):
        return 0.0


# ------------------------------------------------------------------- enquête
class Hypothesis(_Model):
    id: str
    statement: str
    status: str = "open"  # open | supported | refuted
    confidence: float = 0.5
    rationale: str = ""

    _c = field_validator("confidence", mode="before")(_clamp)


class PlanStep(_Model):
    id: str
    objective: str
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    hypothesis_ids: list[str] = Field(default_factory=list)
    related_evidence: list[str] = Field(default_factory=list)
    status: str = "pending"  # pending | running | done | failed | skipped
    result: str = ""
    evidence_ids: list[str] = Field(default_factory=list)
    audit_seq: int | None = None


class Plan(_Model):
    version: int = 1
    rationale: str = ""
    steps: list[PlanStep] = Field(default_factory=list)


# ------------------------------------------------------------------- rapport
class TimelineEntry(_Model):
    timestamp: str
    host: str | None = None
    description: str
    kind: ClaimKind = ClaimKind.observed
    confidence: float = 0.5
    evidence_ids: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)

    _c = field_validator("confidence", mode="before")(_clamp)


class TechniqueMapping(_Model):
    technique_id: str
    name: str = ""
    tactics: list[str] = Field(default_factory=list)
    justification: str = ""
    confidence: float = 0.5
    evidence_ids: list[str] = Field(default_factory=list)
    fragment_ids: list[str] = Field(default_factory=list)

    _c = field_validator("confidence", mode="before")(_clamp)

    @field_validator("technique_id")
    @classmethod
    def _upper(cls, v: str) -> str:
        return v.strip().upper()


class IOC(_Model):
    type: str
    value: str
    verdict: str = "unknown"  # malicious | suspicious | benign | unknown
    sources: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)


class ImpactedScope(_Model):
    hosts: list[str] = Field(default_factory=list)
    users: list[str] = Field(default_factory=list)


class InvestigationReport(_Model):
    investigation_id: str = ""
    alert_summary: str = ""
    verdict: Verdict = Verdict.needs_investigation
    severity: Severity = Severity.medium
    confidence: float = 0.5
    summary: str = ""
    timeline: list[TimelineEntry] = Field(default_factory=list)
    techniques: list[TechniqueMapping] = Field(default_factory=list)
    iocs: list[IOC] = Field(default_factory=list)
    impacted_scope: ImpactedScope = Field(default_factory=ImpactedScope)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    detection_rules: list[str] = Field(default_factory=list)  # règles Sigma proposées (EF-12), non déployées
    limitations: list[str] = Field(default_factory=list)
    stop_reason: str = ""

    _c = field_validator("confidence", mode="before")(_clamp)

    @field_validator("verdict", mode="before")
    @classmethod
    def _verdict(cls, v: Any) -> Any:
        aliases = {"vrai positif": "true_positive", "faux positif": "false_positive", "tp": "true_positive",
                   "fp": "false_positive", "à approfondir": "needs_investigation", "inconclusive": "needs_investigation"}
        return aliases.get(str(v).strip().lower(), v) if isinstance(v, str) else v

    @field_validator("severity", mode="before")
    @classmethod
    def _severity(cls, v: Any) -> Any:
        aliases = {"faible": "low", "moyenne": "medium", "moyen": "medium", "élevée": "high", "haute": "high",
                   "critique": "critical"}
        return aliases.get(str(v).strip().lower(), str(v).strip().lower()) if isinstance(v, str) else v

    def claims(self) -> list[tuple[str, list[str]]]:
        """Affirmations soumises à l'exigence de preuve (ENF-01)."""
        out = [(f"timeline[{i}]", e.evidence_ids) for i, e in enumerate(self.timeline) if e.kind != "hypothesis"]
        out += [(f"technique {t.technique_id}", t.evidence_ids) for t in self.techniques]
        out += [(f"ioc {c.value}", c.evidence_ids) for c in self.iocs if c.verdict != "unknown"]
        return out


REPORT_JSON_SHAPE = {
    "verdict": "true_positive | false_positive | needs_investigation",
    "severity": "low | medium | high | critical",
    "confidence": "0..1",
    "summary": "résumé en français, 3 à 6 phrases",
    "timeline": [{"timestamp": "ISO 8601", "host": "...", "description": "...",
                  "kind": "observed | inferred | hypothesis", "confidence": "0..1",
                  "evidence_ids": ["EV-001"], "techniques": ["T1059.001"]}],
    "techniques": [{"technique_id": "T1059.001", "name": "...", "tactics": ["execution"], "justification": "...",
                    "confidence": "0..1", "evidence_ids": ["EV-001"], "fragment_ids": ["T1059.001#0"]}],
    "iocs": [{"type": "ip", "value": "...", "verdict": "malicious | suspicious | benign | unknown",
              "sources": ["misp", "virustotal"], "evidence_ids": ["EV-010"]}],
    "impacted_scope": {"hosts": ["..."], "users": ["..."]},
    "hypotheses": [{"id": "H1", "statement": "...", "status": "open | supported | refuted", "confidence": "0..1"}],
    "recommendations": ["..."],
    "detection_rules": ["règle Sigma YAML proposée (non déployée)"],
    "limitations": ["..."],
}
