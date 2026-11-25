"""Validation du rapport : preuves, techniques, fragments (ENF-01, EF-13, EF-14, GT-03).

`validate_report` détecte les affirmations non étayées ou inventées ;
`enforce_grounding` corrige le rapport de façon déterministe lorsqu'une
réparation par le LLM n'a pas suffi : une affirmation sans preuve valide est
rétrogradée en hypothèse, une technique non justifiée est retirée, etc.
Chaque correction est signalée dans les limites du rapport.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agent.report_models import InvestigationReport
from connectors.base import parse_iso

TIMESTAMP_TOLERANCE_S = 300


@dataclass
class Issue:
    level: str  # error | warning
    path: str
    message: str

    def __str__(self) -> str:
        return f"[{self.level}] {self.path} : {self.message}"


@dataclass
class ValidationResult:
    issues: list[Issue] = field(default_factory=list)
    claims_total: int = 0
    claims_grounded: int = 0

    @property
    def errors(self) -> list[Issue]:
        return [i for i in self.issues if i.level == "error"]

    @property
    def warnings(self) -> list[Issue]:
        return [i for i in self.issues if i.level == "warning"]

    @property
    def ok(self) -> bool:
        return not self.errors

    @property
    def grounding_ratio(self) -> float:
        return 1.0 if self.claims_total == 0 else self.claims_grounded / self.claims_total

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "errors": [str(i) for i in self.errors],
            "warnings": [str(i) for i in self.warnings],
            "claims_total": self.claims_total,
            "claims_grounded": self.claims_grounded,
            "grounding_ratio": round(self.grounding_ratio, 4),
        }


def _ts_close(entry_ts: str, evidence: list[Any]) -> bool | None:
    """Vrai si l'horodatage correspond à une preuve citée (None : rien à comparer)."""
    target = parse_iso(entry_ts)
    stamps = [parse_iso(e.observed_at) for e in evidence if e.observed_at and e.tool in {"search_logs", "get_process_tree"}]
    stamps = [s for s in stamps if s is not None]
    if not stamps:
        return None
    if target is None:
        return False
    return any(abs((target - s).total_seconds()) <= TIMESTAMP_TOLERANCE_S for s in stamps)


def validate_report(
    report: InvestigationReport,
    evidence: dict[str, Any],
    rag: Any,
    attack_candidates: set[tuple[str, str]],
) -> ValidationResult:
    """`evidence` : {EV-xxx: Evidence} ; `attack_candidates` : {(technique, fragment)} issus de attack_search."""
    res = ValidationResult()
    add = res.issues.append

    def check_ids(path: str, ids: list[str]) -> list[str]:
        valid = []
        for ev_id in ids:
            if ev_id in evidence:
                valid.append(ev_id)
            else:
                add(Issue("error", path, f"preuve inexistante : {ev_id}"))
        return valid

    candidate_techs = {t for t, _ in attack_candidates}
    candidate_frags = {f for _, f in attack_candidates}
    report_techs = {t.technique_id for t in report.techniques}

    observed = 0
    for i, entry in enumerate(report.timeline):
        path = f"timeline[{i}]"
        valid = check_ids(path, entry.evidence_ids)
        if parse_iso(entry.timestamp) is None:
            add(Issue("error", path, f"horodatage invalide : {entry.timestamp!r}"))
        if entry.kind == "hypothesis":
            if entry.confidence > 0.5:
                add(Issue("warning", path, "une hypothèse ne peut pas avoir une confiance supérieure à 0,5"))
            continue
        res.claims_total += 1
        if not valid:
            add(Issue("error", path, f"affirmation « {entry.kind} » sans preuve valide"))
            continue
        res.claims_grounded += 1
        if entry.kind == "observed":
            observed += 1
            close = _ts_close(entry.timestamp, [evidence[v] for v in valid])
            if close is False:
                add(Issue("error", path, "horodatage sans rapport avec les preuves citées"))
        for tech in entry.techniques:
            if tech not in report_techs:
                add(Issue("warning", path, f"technique {tech} absente de la section ATT&CK"))

    for t in report.techniques:
        path = f"technique {t.technique_id}"
        res.claims_total += 1
        valid = check_ids(path, t.evidence_ids)
        known = rag.get_technique(t.technique_id) if rag is not None else True
        problems = []
        if not known:
            problems.append("identifiant inconnu dans ATT&CK")
        if attack_candidates and t.technique_id not in candidate_techs:
            problems.append("technique non issue de attack_search")
        if not t.fragment_ids:
            problems.append("aucun fragment ATT&CK cité")
        for frag in t.fragment_ids:
            if rag is not None and rag.fragment(frag) is None:
                problems.append(f"fragment inexistant : {frag}")
            elif frag.split("#")[0] != t.technique_id:
                problems.append(f"le fragment {frag} n'appartient pas à {t.technique_id}")
            elif attack_candidates and frag not in candidate_frags:
                problems.append(f"fragment {frag} non renvoyé par attack_search")
        if not valid:
            problems.append("aucune preuve valide")
        for p in problems:
            add(Issue("error", path, p))
        if not problems:
            res.claims_grounded += 1

    for c in report.iocs:
        path = f"ioc {c.value}"
        valid = check_ids(path, c.evidence_ids)
        if c.verdict == "unknown":
            continue
        res.claims_total += 1
        if not valid:
            add(Issue("error", path, f"verdict « {c.verdict} » sans preuve"))
            continue
        res.claims_grounded += 1
        if not any(str(c.value).lower() in str(evidence[v].excerpt).lower() for v in valid):
            add(Issue("warning", path, "les preuves citées ne mentionnent pas cet IOC"))

    if report.verdict == "true_positive" and observed == 0:
        add(Issue("error", "verdict", "vrai positif sans aucun fait observé étayé"))
    return res


def enforce_grounding(
    report: InvestigationReport,
    evidence: dict[str, Any],
    rag: Any,
    attack_candidates: set[tuple[str, str]],
) -> tuple[InvestigationReport, list[str]]:
    """Corrige le rapport pour qu'il ne contienne que des affirmations étayées."""
    r = report.model_copy(deep=True)
    changes: list[str] = []
    candidate_techs = {t for t, _ in attack_candidates}
    candidate_frags = {f for _, f in attack_candidates}

    kept_techs = []
    for t in r.techniques:
        t.evidence_ids = [e for e in t.evidence_ids if e in evidence]
        t.fragment_ids = [f for f in t.fragment_ids
                          if (rag is None or rag.fragment(f) is not None) and f.split("#")[0] == t.technique_id
                          and (not attack_candidates or f in candidate_frags)]
        known = rag is None or rag.get_technique(t.technique_id) is not None
        if known and t.evidence_ids and t.fragment_ids and (not attack_candidates or t.technique_id in candidate_techs):
            kept_techs.append(t)
        else:
            changes.append(f"technique {t.technique_id} retirée (non étayée par une preuve et un fragment ATT&CK)")
    r.techniques = kept_techs
    tech_ids = {t.technique_id for t in kept_techs}

    for i, e in enumerate(r.timeline):
        before = list(e.evidence_ids)
        e.evidence_ids = [x for x in e.evidence_ids if x in evidence]
        e.techniques = [t for t in e.techniques if t in tech_ids]
        if e.kind != "hypothesis" and not e.evidence_ids:
            changes.append(f"timeline[{i}] rétrogradée en hypothèse (preuve absente ou invalide : {before or 'aucune'})")
            e.kind = "hypothesis"
            e.confidence = min(e.confidence, 0.3)
        elif e.kind == "observed":
            cited = [evidence[x] for x in e.evidence_ids]
            if _ts_close(e.timestamp, cited) is False:
                stamps = sorted(c.observed_at for c in cited if c.observed_at)
                if stamps:
                    changes.append(f"timeline[{i}] : horodatage corrigé d'après la preuve {e.evidence_ids[0]}")
                    e.timestamp = stamps[0]
        if e.kind == "hypothesis" and e.confidence > 0.5:
            e.confidence = 0.5
    r.timeline.sort(key=lambda x: x.timestamp or "")

    for c in r.iocs:
        c.evidence_ids = [x for x in c.evidence_ids if x in evidence]
        if c.verdict != "unknown" and not c.evidence_ids:
            changes.append(f"IOC {c.value} : verdict « {c.verdict} » ramené à « unknown » (aucune preuve)")
            c.verdict = "unknown"

    if r.verdict == "true_positive" and not any(e.kind == "observed" for e in r.timeline):
        changes.append("verdict ramené à « à approfondir » : aucun fait observé étayé")
        r.verdict = "needs_investigation"
        r.confidence = min(r.confidence, 0.5)

    if changes:
        r.limitations.append(f"Validation automatique : {len(changes)} correction(s) appliquée(s) pour garantir "
                             "que chaque affirmation est reliée à une preuve.")
    return r, changes
