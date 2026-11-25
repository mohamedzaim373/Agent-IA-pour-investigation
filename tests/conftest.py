from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config.settings import load_settings  # noqa: E402
from gateway.audit import AuditLog  # noqa: E402
from gateway.policy import IdentityDirectory, Policy  # noqa: E402


@pytest.fixture(scope="session")
def rag():
    from rag.retriever import get_rag

    return get_rag()


@pytest.fixture()
def settings(tmp_path):
    return load_settings(backend="simulation", llm_provider="offline", data_dir=tmp_path / "data",
                         runs_dir=tmp_path / "runs", db_url="", webhook_token="secret-webhook")


@pytest.fixture()
def db_url(tmp_path):
    (tmp_path / "db").mkdir(exist_ok=True)
    return f"sqlite:///{tmp_path / 'db' / 'test.db'}"


@pytest.fixture()
def audit(db_url):
    return AuditLog(db_url)


@pytest.fixture()
def policy():
    return Policy.load(ROOT / "config" / "policy.yaml")


@pytest.fixture()
def identities():
    return IdentityDirectory.load(ROOT / "config" / "analysts.yaml")


@pytest.fixture()
def investigator(settings, rag):
    from agent.runner import Investigator

    return Investigator(settings, rag=rag)


@pytest.fixture(scope="session")
def scenarios():
    from connectors.simulation import list_scenarios, load_scenario

    return {sid: load_scenario(sid) for sid in list_scenarios()}
