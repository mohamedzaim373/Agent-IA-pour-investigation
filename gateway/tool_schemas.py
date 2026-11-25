"""Schémas stricts des paramètres d'outils (GP-04).

Chaque appel demandé par l'agent est validé contre ces modèles Pydantic avant
toute décision de politique : types, formats, champs inconnus interdits, tailles
maximales. Les contraintes propres à la politique (fenêtre maximale, index
autorisés, nombre de résultats) sont ensuite vérifiées par `gateway.policy`.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SAFE_NAME = r"^[A-Za-z0-9_.\-\\@$ ]{1,128}$"


class ObservableType(str, Enum):
    ip = "ip"
    domain = "domain"
    url = "url"
    sha256 = "sha256"
    sha1 = "sha1"
    md5 = "md5"
    user = "user"
    host = "host"
    process = "process"
    filename = "filename"
    registry = "registry"
    email = "email"


TI_TYPES = {ObservableType.ip, ObservableType.domain, ObservableType.url,
            ObservableType.sha256, ObservableType.sha1, ObservableType.md5}


def _to_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


class _StrictArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class SearchLogsArgs(_StrictArgs):
    """Recherche en lecture dans les journaux du SIEM."""

    start: datetime = Field(description="Début de la fenêtre (ISO 8601, UTC)")
    end: datetime = Field(description="Fin de la fenêtre (ISO 8601, UTC)")
    host: str | None = Field(default=None, pattern=SAFE_NAME, description="Nom de l'hôte (agent Wazuh)")
    user: str | None = Field(default=None, pattern=SAFE_NAME, description="Compte, ex. LAB\\jdoe")
    ioc: str | None = Field(default=None, max_length=512, description="Observable recherché dans tous les champs")
    terms: list[str] = Field(default_factory=list, max_length=5, description="Termes libres (ET logique)")
    event_types: list[str] = Field(default_factory=list, max_length=10, description="Types normalisés, ex. process_creation")
    index: str = Field(default="wazuh-archives-*", max_length=64)
    limit: int = Field(default=100, ge=1, le=1000)

    @field_validator("start", "end")
    @classmethod
    def _utc(cls, v: datetime) -> datetime:
        return _to_utc(v)

    @field_validator("terms")
    @classmethod
    def _terms(cls, v: list[str]) -> list[str]:
        for term in v:
            if not 1 <= len(term) <= 128:
                raise ValueError("chaque terme doit contenir entre 1 et 128 caractères")
        return v

    @model_validator(mode="after")
    def _window(self) -> "SearchLogsArgs":
        if self.end <= self.start:
            raise ValueError("la fin de la fenêtre doit être postérieure au début")
        return self


class ProcessTreeArgs(_StrictArgs):
    """Arbre de processus (parents et enfants) autour d'un processus."""

    host: str = Field(pattern=SAFE_NAME)
    process_guid: str | None = Field(default=None, max_length=64)
    pid: int | None = Field(default=None, ge=0, le=10_000_000)
    image: str | None = Field(default=None, max_length=260)
    around: datetime = Field(description="Instant de référence (ISO 8601, UTC)")
    window_minutes: int = Field(default=60, ge=1, le=10_080)

    @field_validator("around")
    @classmethod
    def _utc(cls, v: datetime) -> datetime:
        return _to_utc(v)

    @model_validator(mode="after")
    def _selector(self) -> "ProcessTreeArgs":
        if not (self.process_guid or self.pid is not None or self.image):
            raise ValueError("préciser process_guid, pid ou image")
        return self


class MispLookupArgs(_StrictArgs):
    """Présence d'un observable dans la base d'IOC MISP."""

    value: str = Field(min_length=1, max_length=512)
    type: ObservableType


class TiLookupArgs(_StrictArgs):
    """Réputation d'un observable auprès de services de TI externes."""

    value: str = Field(min_length=1, max_length=512)
    type: ObservableType
    providers: list[str] = Field(default_factory=lambda: ["virustotal", "abuseipdb"], min_length=1, max_length=4)

    @field_validator("type")
    @classmethod
    def _ti_type(cls, v: ObservableType) -> ObservableType:
        if v not in TI_TYPES:
            raise ValueError(f"type {v.value} non pris en charge par la TI externe")
        return v


class AttackSearchArgs(_StrictArgs):
    """Recherche sémantique de techniques MITRE ATT&CK."""

    query: str = Field(min_length=3, max_length=1000)
    k: int = Field(default=5, ge=1, le=50)
    tactic: str | None = Field(default=None, max_length=64)


class IsolateHostArgs(_StrictArgs):
    """Confinement réseau d'un hôte (niveau N3, non implémenté)."""

    host: str = Field(pattern=SAFE_NAME)
    reason: str = Field(min_length=3, max_length=500)


@dataclass(frozen=True)
class ToolSpec:
    name: str
    args_model: type[BaseModel]
    description: str

    def json_schema(self) -> dict[str, Any]:
        schema = self.args_model.model_json_schema()
        schema.pop("title", None)
        return schema


TOOL_SCHEMAS: dict[str, ToolSpec] = {
    spec.name: spec
    for spec in (
        ToolSpec("search_logs", SearchLogsArgs, "Rechercher des événements dans les journaux Wazuh/Sysmon."),
        ToolSpec("get_process_tree", ProcessTreeArgs, "Reconstruire l'arbre de processus autour d'un processus."),
        ToolSpec("misp_lookup", MispLookupArgs, "Vérifier la présence d'un observable dans MISP."),
        ToolSpec("ti_lookup", TiLookupArgs, "Obtenir la réputation d'un observable (VirusTotal, AbuseIPDB)."),
        ToolSpec("attack_search", AttackSearchArgs, "Rechercher les techniques ATT&CK correspondant à un comportement."),
        ToolSpec("isolate_host", IsolateHostArgs, "Isoler un hôte du réseau (N3, non implémenté)."),
    )
}


def tools_for_prompt(names: list[str]) -> list[dict[str, Any]]:
    """Description compacte des outils autorisés, à destination du LLM."""
    return [
        {"name": n, "description": TOOL_SCHEMAS[n].description, "parameters": TOOL_SCHEMAS[n].json_schema()}
        for n in names
        if n in TOOL_SCHEMAS
    ]
