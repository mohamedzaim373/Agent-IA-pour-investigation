"""Service FastAPI : authentification, droits, suivi, validations (ENF-05, EF-18, EF-19)."""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from app.api import create_app
from app.auth import TokenStore


@pytest.fixture()
def client(settings, investigator):
    app = create_app(settings, investigator)
    store = TokenStore(settings.data_dir / "tokens.json")
    tokens = {a: store.issue(a) for a in ("jdupont", "aaudit", "mmanager")}
    with TestClient(app) as c:
        c.tokens = tokens
        yield c


def h(client, analyst):
    return {"Authorization": f"Bearer {client.tokens[analyst]}"}


def wait_done(client, inv_id, analyst="jdupont", timeout=120, approve=False):
    deadline = time.time() + timeout
    while time.time() < deadline:
        info = client.get(f"/investigations/{inv_id}", headers=h(client, analyst)).json()
        if approve:
            for p in info.get("pending_approvals", []):
                client.post(f"/approvals/{p['id']}", json={"approve": True, "reason": "ok"}, headers=h(client, analyst))
        if info.get("live_status") in {"completed", "error"}:
            return info
        time.sleep(0.2)
    raise AssertionError("investigation non terminée")


def test_authentication_required(client):
    assert client.get("/me").status_code == 401
    assert client.get("/me", headers={"Authorization": "Bearer faux"}).status_code == 401
    me = client.get("/me", headers=h(client, "jdupont")).json()
    assert me["role"] == "analyst" and me["max_autonomy"] == "N2"
    assert client.get("/health").json()["status"] == "ok"


def test_full_investigation_via_api(client):
    res = client.post("/investigations", json={"scenario_id": "S4", "autonomy_level": "N2"}, headers=h(client, "jdupont"))
    assert res.status_code == 202
    inv_id = res.json()["investigation_id"]
    info = wait_done(client, inv_id)
    assert info["live_status"] == "completed" and info["verdict"] == "false_positive"
    events = client.get(f"/investigations/{inv_id}/events", headers=h(client, "jdupont")).json()
    types = {e["type"] for e in events}
    assert {"run_start", "plan", "tool_call", "tool_result", "run_end"} <= types
    report = client.get(f"/investigations/{inv_id}/report", headers=h(client, "jdupont")).json()
    assert report["report"]["verdict"] == "false_positive"
    md = client.get(f"/investigations/{inv_id}/report.md", headers=h(client, "jdupont"))
    assert md.status_code == 200 and "# Rapport d'investigation" in md.text
    assert client.get(f"/investigations/{inv_id}/evidence", headers=h(client, "jdupont")).json()


def test_approval_flow_at_n0(client):
    res = client.post("/investigations", json={"scenario_id": "S4", "autonomy_level": "N0"}, headers=h(client, "jdupont"))
    inv_id = res.json()["investigation_id"]
    info = wait_done(client, inv_id, approve=True)
    assert info["live_status"] == "completed"
    audit = client.get(f"/audit/{inv_id}", headers=h(client, "jdupont")).json()
    decisions = [e for e in audit if e["event_type"] == "approval_decision"]
    assert decisions and all(e["actor"] == "analyst:jdupont" and e["decision"] == "approved" for e in decisions)


def test_rejection_requires_reason(client):
    assert client.post("/approvals/1", json={"approve": False, "reason": ""},
                       headers=h(client, "jdupont")).status_code == 422


def test_role_permissions(client):
    assert client.post("/investigations", json={"scenario_id": "S4"}, headers=h(client, "aaudit")).status_code == 403
    assert client.post("/approvals/1", json={"approve": True}, headers=h(client, "aaudit")).status_code == 403
    assert client.get("/audit/verify", headers=h(client, "jdupont")).status_code == 403
    verify = client.get("/audit/verify", headers=h(client, "aaudit"))
    assert verify.status_code == 200 and verify.json()["ok"]


def test_level_cannot_be_raised(client):
    res = client.post("/investigations", json={"scenario_id": "S4", "autonomy_level": "N3"}, headers=h(client, "jdupont"))
    assert res.json()["autonomy_level"] == "N2" and res.json()["notes"]
    wait_done(client, res.json()["investigation_id"])


def test_bad_requests(client):
    assert client.post("/investigations", json={}, headers=h(client, "jdupont")).status_code == 400
    assert client.post("/investigations", json={"scenario_id": "S99"}, headers=h(client, "jdupont")).status_code == 404
    assert client.get("/investigations/INV-inconnue", headers=h(client, "jdupont")).status_code == 404


def test_webhook_token(client):
    assert client.post("/alerts/wazuh", json={"rule": {}}).status_code == 401
    res = client.post("/alerts/wazuh", json={"rule": {}}, headers={"X-Webhook-Token": "secret-webhook"})
    assert res.status_code == 400  # backend de simulation : alertes réelles refusées
