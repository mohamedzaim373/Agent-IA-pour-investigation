"""Stockage sur PostgreSQL (activé si TEST_POSTGRES_URL est défini).

    TEST_POSTGRES_URL=postgresql+psycopg://investigator:***@localhost:5432/investigator pytest tests/test_postgres.py
"""

from __future__ import annotations

import os

import pytest
from sqlalchemy.exc import DBAPIError

PG_URL = os.environ.get("TEST_POSTGRES_URL")
pytestmark = pytest.mark.skipif(not PG_URL, reason="TEST_POSTGRES_URL non défini")


def test_investigation_on_postgres(tmp_path, rag, scenarios):
    from agent.runner import Investigator
    from config.settings import load_settings
    from gateway.approval import AutoApprover

    settings = load_settings(backend="simulation", llm_provider="offline", db_url=PG_URL,
                             data_dir=tmp_path / "data", runs_dir=tmp_path / "runs")
    inv = Investigator(settings, rag=rag)
    scenario = scenarios["S3"]
    out = inv.investigate(scenario["alert"], analyst_id="jdupont", autonomy_level="N2",
                          approver=AutoApprover(True, "jdupont"), scenario=scenario)
    assert out.status == "completed" and out.verdict == "true_positive" and out.audit["ok"]
    assert inv.audit.engine.dialect.name == "postgresql"
    for sql in ("UPDATE audit_log SET reason='x' WHERE seq=1", "DELETE FROM audit_log WHERE seq=1"):
        with pytest.raises(DBAPIError):
            with inv.audit.engine.begin() as conn:
                conn.exec_driver_sql(sql)
