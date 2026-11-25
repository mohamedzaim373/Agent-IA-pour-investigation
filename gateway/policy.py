"""Moteur de politique de la passerelle (GP-01 à GP-05, chapitre 8.1).

La politique est chargée depuis config/policy.yaml et appliquée ici, dans du
code déterministe : le LLM peut demander un appel, il ne décide jamais de son
autorisation.
"""

from __future__ import annotations

import fnmatch
import time
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel

from gateway.hashing import sha256_hex
from gateway.observables import is_internal_observable

LEVELS = ("N0", "N1", "N2", "N3")


class Decision(str, Enum):
    ALLOW = "allow"
    NEEDS_APPROVAL = "needs_approval"
    DENY = "deny"


@dataclass(frozen=True)
class PolicyDecision:
    decision: Decision
    reason: str
    risk: str | None = None
    rule: str | None = None

    @property
    def allowed(self) -> bool:
        return self.decision == Decision.ALLOW


@dataclass(frozen=True)
class AnalystIdentity:
    """Identité déléguée : l'agent agit avec ces droits, jamais au-delà (GP-03)."""

    analyst_id: str
    name: str
    role: str
    max_autonomy: str
    tools: frozenset[str]
    can_approve: bool
    can_read_audit: bool

    @property
    def actor(self) -> str:
        return f"analyst:{self.analyst_id}"


@dataclass
class BudgetUsage:
    """Consommation d'une investigation, suivie par la passerelle (GP-05)."""

    started_at: float = field(default_factory=time.monotonic)
    calls_by_tool: Counter = field(default_factory=Counter)
    total_calls: int = 0
    tokens: int = 0
    steps: int = 0
    denied: int = 0
    approvals_requested: int = 0
    approvals_rejected: int = 0
    errors: int = 0
    consecutive_failures: int = 0

    @property
    def elapsed_s(self) -> float:
        return time.monotonic() - self.started_at

    def snapshot(self) -> dict[str, Any]:
        return {
            "elapsed_s": round(self.elapsed_s, 2),
            "calls_by_tool": dict(self.calls_by_tool),
            "total_calls": self.total_calls,
            "tokens": self.tokens,
            "steps": self.steps,
            "denied": self.denied,
            "approvals_requested": self.approvals_requested,
            "approvals_rejected": self.approvals_rejected,
            "errors": self.errors,
        }


def level_rank(level: str) -> int:
    return LEVELS.index(level)


class Policy:
    def __init__(self, data: dict[str, Any], *, source: str = "<dict>", raw: str | None = None):
        self.data = data
        self.source = source
        self.version = str(data.get("version", "0"))
        self.sha256 = sha256_hex(raw if raw is not None else yaml.safe_dump(data, sort_keys=True))
        autonomy = data.get("autonomy", {})
        self.max_level: str = autonomy.get("max_level", "N1")
        self.default_level: str = autonomy.get("default_level", "N1")
        self.levels: dict[str, dict[str, Any]] = autonomy.get("levels", {})
        self.tools: dict[str, dict[str, Any]] = data.get("tools", {})
        self.budgets: dict[str, Any] = data.get("budgets", {})
        self.approval: dict[str, Any] = data.get("approval", {})
        self.privacy: dict[str, Any] = data.get("privacy", {})
        for lvl in (self.max_level, self.default_level):
            if lvl not in LEVELS:
                raise ValueError(f"niveau d'autonomie inconnu dans la politique : {lvl}")

    # ---------------------------------------------------------------- chargement
    @classmethod
    def load(cls, path: str | Path) -> "Policy":
        raw = Path(path).read_text(encoding="utf-8")
        return cls(yaml.safe_load(raw), source=str(path), raw=raw)

    @property
    def internal_domains(self) -> list[str]:
        return list(self.privacy.get("internal_domains", ["lab.local"]))

    def budget(self, key: str, default: float) -> float:
        return self.budgets.get(key, default)

    def level_implemented(self, level: str) -> bool:
        return bool(self.levels.get(level, {}).get("implemented", True))

    # ------------------------------------------------------- niveau d'autonomie
    def effective_level(self, requested: str | None, analyst: AnalystIdentity) -> tuple[str, list[str]]:
        """Niveau retenu : jamais au-dessus du maximum SOC ni des droits de l'analyste."""
        notes: list[str] = []
        level = requested or self.default_level
        if level not in LEVELS:
            notes.append(f"niveau {level} inconnu : niveau par défaut {self.default_level} appliqué")
            level = self.default_level
        ceiling = min(level_rank(self.max_level), level_rank(analyst.max_autonomy))
        while ceiling > 0 and not self.level_implemented(LEVELS[ceiling]):
            ceiling -= 1
        if level_rank(level) > ceiling:
            notes.append(
                f"relèvement refusé : {level} demandé, plafond {LEVELS[ceiling]} "
                f"(politique SOC {self.max_level}, rôle {analyst.role} {analyst.max_autonomy})"
            )
            level = LEVELS[ceiling]
        return level, notes

    def auto_execute(self, level: str) -> set[str]:
        return set(self.levels.get(level, {}).get("auto_execute", []))

    # ------------------------------------------------------------------ décision
    def decide(
        self,
        tool: str,
        args: BaseModel,
        *,
        level: str,
        analyst: AnalystIdentity,
        usage: BudgetUsage,
    ) -> PolicyDecision:
        cfg = self.tools.get(tool)
        if cfg is None:
            return PolicyDecision(Decision.DENY, f"outil « {tool} » non déclaré dans la politique", rule="GP-01")
        risk = cfg.get("risk", "action")
        if not cfg.get("enabled", False):
            return PolicyDecision(Decision.DENY, f"outil « {tool} » désactivé par la politique", risk, "GP-02")

        if risk == "action":
            if not cfg.get("reversible", False):
                return PolicyDecision(Decision.DENY, "action irréversible : toujours interdite", risk, "8.1")
            if level != "N3" or not self.level_implemented("N3"):
                return PolicyDecision(Decision.DENY, "action de réponse interdite : niveau N3 non implémenté", risk, "8.1")

        if tool not in analyst.tools:
            return PolicyDecision(
                Decision.DENY, f"« {tool} » hors des droits de l'analyste {analyst.analyst_id} ({analyst.role})", risk, "GP-03"
            )

        violation = self._check_constraints(tool, cfg, args)
        if violation:
            return PolicyDecision(Decision.DENY, violation, risk, "GP-04")

        budget_violation = self._check_budget(tool, cfg, usage)
        if budget_violation:
            return PolicyDecision(Decision.DENY, budget_violation, risk, "GP-05")

        if risk in self.auto_execute(level):
            return PolicyDecision(Decision.ALLOW, f"{risk} autorisé automatiquement au niveau {level}", risk, "8.1")
        return PolicyDecision(
            Decision.NEEDS_APPROVAL, f"{risk} soumis à l'approbation de l'analyste au niveau {level}", risk, "EF-19"
        )

    def _check_constraints(self, tool: str, cfg: dict[str, Any], args: BaseModel) -> str | None:
        a = args.model_dump()
        if tool == "search_logs":
            allowed = cfg.get("allowed_indices", [])
            if allowed and not any(fnmatch.fnmatch(a["index"], pat) or a["index"] == pat for pat in allowed):
                return f"index « {a['index']} » non autorisé (autorisés : {', '.join(allowed)})"
            window = (a["end"] - a["start"]).total_seconds() / 60
            if window > cfg.get("max_window_minutes", 1440):
                return f"fenêtre de {window:.0f} min supérieure au maximum de {cfg.get('max_window_minutes')} min"
            if a["limit"] > cfg.get("max_results", 200):
                return f"limite de {a['limit']} résultats supérieure au maximum de {cfg.get('max_results')}"
        elif tool == "get_process_tree":
            if a["window_minutes"] > cfg.get("max_window_minutes", 1440):
                return f"fenêtre de {a['window_minutes']} min supérieure au maximum de {cfg.get('max_window_minutes')} min"
        elif tool == "ti_lookup":
            allowed = set(cfg.get("allowed_providers", []))
            extra = [p for p in a["providers"] if p not in allowed]
            if extra:
                return f"source(s) de TI hors liste blanche : {', '.join(extra)}"
            otype = a["type"].value if hasattr(a["type"], "value") else str(a["type"])
            if cfg.get("forbid_internal_observables", True) and is_internal_observable(
                a["value"], otype, self.internal_domains
            ):
                return "observable interne : exposition à un service externe interdite (GP-08)"
        elif tool == "attack_search":
            if a["k"] > cfg.get("max_k", 10):
                return f"k={a['k']} supérieur au maximum de {cfg.get('max_k')}"
        return None

    def _check_budget(self, tool: str, cfg: dict[str, Any], usage: BudgetUsage) -> str | None:
        if usage.calls_by_tool[tool] >= cfg.get("max_calls", 10):
            return f"budget épuisé pour « {tool} » ({cfg.get('max_calls')} appels)"
        if usage.total_calls >= self.budget("max_tool_calls", 40):
            return f"budget global d'appels épuisé ({self.budget('max_tool_calls', 40)})"
        if usage.tokens >= self.budget("max_tokens", 100_000):
            return f"budget de jetons épuisé ({self.budget('max_tokens', 100_000)})"
        if usage.elapsed_s >= self.budget("max_duration_s", 600):
            return f"durée maximale atteinte ({self.budget('max_duration_s', 600)} s)"
        return None


# --------------------------------------------------------------------- identités
class IdentityDirectory:
    """Annuaire des analystes et de leurs rôles (config/analysts.yaml)."""

    def __init__(self, data: dict[str, Any]):
        self.roles: dict[str, dict[str, Any]] = data.get("roles", {})
        self.analysts: dict[str, dict[str, Any]] = data.get("analysts", {})

    @classmethod
    def load(cls, path: str | Path) -> "IdentityDirectory":
        return cls(yaml.safe_load(Path(path).read_text(encoding="utf-8")))

    def get(self, analyst_id: str) -> AnalystIdentity:
        info = self.analysts.get(analyst_id)
        if info is None:
            raise KeyError(f"analyste inconnu : {analyst_id}")
        role = self.roles.get(info.get("role", ""))
        if role is None:
            raise KeyError(f"rôle inconnu pour {analyst_id} : {info.get('role')}")
        return AnalystIdentity(
            analyst_id=analyst_id,
            name=info.get("name", analyst_id),
            role=info["role"],
            max_autonomy=role.get("max_autonomy", "N0"),
            tools=frozenset(role.get("tools", [])),
            can_approve=bool(role.get("can_approve", False)),
            can_read_audit=bool(role.get("can_read_audit", False)),
        )
