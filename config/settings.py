"""Configuration centrale, lue depuis l'environnement (et un fichier .env optionnel).

Les secrets (clés d'API, mots de passe) ne sont lus qu'ici et ne sont transmis
qu'aux connecteurs, via la passerelle. Ils ne sont jamais exposés au LLM (GP-06).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

try:  # python-dotenv est optionnel
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover
    load_dotenv = None

ROOT_DIR = Path(__file__).resolve().parent.parent

if load_dotenv is not None:
    load_dotenv(ROOT_DIR / ".env", override=False)


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "oui", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    try:
        return int(raw) if raw not in (None, "") else default
    except ValueError:
        return default


def _path(name: str, default: Path) -> Path:
    raw = _env(name)
    path = Path(raw) if raw else default
    return path if path.is_absolute() else ROOT_DIR / path


@dataclass(frozen=True)
class Settings:
    # --- LLM (ENF-07 : changement de modèle par configuration) ---
    llm_provider: str = "offline"  # offline | groq | ollama
    groq_api_key: str = field(default="", repr=False)
    groq_model: str = "llama-3.3-70b-versatile"
    groq_base_url: str = "https://api.groq.com/openai/v1"
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "qwen2.5:7b-instruct"
    llm_temperature: float = 0.0
    llm_timeout_s: int = 120

    # --- Sources de données ---
    backend: str = "simulation"  # simulation | live
    wazuh_indexer_url: str = "https://192.168.56.30:9200"
    wazuh_user: str = "admin"
    wazuh_password: str = field(default="", repr=False)
    wazuh_verify_tls: bool = False
    misp_url: str = "https://localhost:8443"
    misp_key: str = field(default="", repr=False)
    misp_verify_tls: bool = False
    virustotal_api_key: str = field(default="", repr=False)
    abuseipdb_api_key: str = field(default="", repr=False)
    ti_cache_ttl_s: int = 86400

    # --- Stockage ---
    db_url: str = ""
    data_dir: Path = ROOT_DIR / "investigation_lab" / "data"
    runs_dir: Path = ROOT_DIR / "investigation_lab" / "runs"

    # --- Politique et identité ---
    policy_path: Path = ROOT_DIR / "config" / "policy.yaml"
    analysts_path: Path = ROOT_DIR / "config" / "analysts.yaml"
    pseudonym_secret: str = field(default="", repr=False)

    # --- RAG ATT&CK ---
    attack_kb_path: Path = ROOT_DIR / "rag" / "data" / "attack_kb.json.gz"
    embedder: str = "tfidf"  # tfidf | sbert
    sbert_model: str = "sentence-transformers/all-MiniLM-L6-v2"
    vector_store: str = "memory"  # memory | chroma

    # --- Intégration Wazuh -> API ---
    webhook_token: str = field(default="", repr=False)
    webhook_analyst: str = "soc-duty"

    @property
    def database_url(self) -> str:
        return self.db_url or f"sqlite:///{self.data_dir / 'investigator.db'}"

    @property
    def llm_is_external(self) -> bool:
        return self.llm_provider == "groq"

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.runs_dir.mkdir(parents=True, exist_ok=True)


def load_settings(**overrides) -> Settings:
    """Construit la configuration depuis l'environnement ; `overrides` sert aux tests."""
    values = dict(
        llm_provider=_env("LLM_PROVIDER", "offline").lower(),
        groq_api_key=_env("GROQ_API_KEY"),
        groq_model=_env("GROQ_MODEL", Settings.groq_model),
        groq_base_url=_env("GROQ_BASE_URL", Settings.groq_base_url),
        ollama_url=_env("OLLAMA_URL", Settings.ollama_url),
        ollama_model=_env("OLLAMA_MODEL", Settings.ollama_model),
        llm_temperature=float(_env("LLM_TEMPERATURE", "0") or 0),
        llm_timeout_s=_env_int("LLM_TIMEOUT_S", 120),
        backend=_env("BACKEND", "simulation").lower(),
        wazuh_indexer_url=_env("WAZUH_INDEXER_URL", Settings.wazuh_indexer_url),
        wazuh_user=_env("WAZUH_USER", "admin"),
        wazuh_password=_env("WAZUH_PASSWORD"),
        wazuh_verify_tls=_env_bool("WAZUH_VERIFY_TLS", False),
        misp_url=_env("MISP_URL", Settings.misp_url),
        misp_key=_env("MISP_KEY"),
        misp_verify_tls=_env_bool("MISP_VERIFY_TLS", False),
        virustotal_api_key=_env("VT_API_KEY"),
        abuseipdb_api_key=_env("ABUSEIPDB_API_KEY"),
        ti_cache_ttl_s=_env_int("TI_CACHE_TTL_S", 86400),
        db_url=_env("DB_URL"),
        data_dir=_path("DATA_DIR", Settings.data_dir),
        runs_dir=_path("RUNS_DIR", Settings.runs_dir),
        policy_path=_path("POLICY_PATH", Settings.policy_path),
        analysts_path=_path("ANALYSTS_PATH", Settings.analysts_path),
        pseudonym_secret=_env("PSEUDONYM_SECRET"),
        attack_kb_path=_path("ATTACK_KB_PATH", Settings.attack_kb_path),
        embedder=_env("EMBEDDER", "tfidf").lower(),
        sbert_model=_env("SBERT_MODEL", Settings.sbert_model),
        vector_store=_env("VECTOR_STORE", "memory").lower(),
        webhook_token=_env("WEBHOOK_TOKEN"),
        webhook_analyst=_env("WEBHOOK_ANALYST", "soc-duty"),
    )
    values.update(overrides)
    return Settings(**values)


CONFIG = load_settings()
