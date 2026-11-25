"""Connecteurs : normalisation Wazuh/Sysmon, MISP, TI, cache, simulation."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
import requests

from connectors.base import ConnectorError, to_iso_utc
from connectors.misp import MispConnector
from connectors.simulation import SimulationBackend
from connectors.threat_intel import ThreatIntelService, TICache, normalize_abuseipdb, normalize_virustotal
from connectors.wazuh import WazuhIndexerConnector, build_process_tree, normalize_event
from gateway.tool_schemas import MispLookupArgs, ProcessTreeArgs, SearchLogsArgs, TiLookupArgs


class FakeResponse:
    def __init__(self, status=200, payload=None, text=""):
        self.status_code, self._payload, self.text = status, payload, text
        self.headers = {}

    def json(self):
        if self._payload is None:
            raise ValueError("pas de JSON")
        return self._payload


@pytest.mark.parametrize("raw,expected", [
    ("2026-10-12T09:14:03.123+0000", "2026-10-12T09:14:03.123+00:00"),
    ("2026-10-12T09:14:03.1234567Z", "2026-10-12T09:14:03.123+00:00"),
    ("2026-10-12 09:14:03", "2026-10-12T09:14:03.000+00:00"),
    (1790000000, "2026-09-21T14:13:20.000+00:00"),
])
def test_timestamp_normalization(raw, expected):
    assert to_iso_utc(raw) == expected


def test_normalize_sysmon_process(scenarios):
    doc = next(d for d in scenarios["S1"]["logs"] if d["data"]["win"]["system"]["eventID"] == "1"
               and "powershell" in d["data"]["win"]["eventdata"]["image"].lower() and "rule" not in d)
    item = normalize_event(doc)
    assert item["event_type"] == "process_creation" and item["host"] == "WIN10-01"
    assert item["fields"]["user"] == "LAB\\jdoe" and len(item["fields"]["sha256"]) == 64
    assert item["raw_ref"] == doc["_id"] and "powershell.exe" in item["summary"]


def test_normalize_other_event_types(scenarios):
    types = {normalize_event(d)["event_type"] for s in scenarios.values() for d in s["logs"]}
    assert {"process_creation", "network_connection", "file_create", "registry_value_set", "process_access",
            "scheduled_task_created", "dns_query", "logon"} <= types


def test_simulation_search_filters(scenarios):
    sim = SimulationBackend(scenarios["S1"])
    base = dict(start=datetime(2026, 10, 12, 8, 0, tzinfo=timezone.utc), end=datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc))
    everything = sim.search_logs(SearchLogsArgs(**base))["items"]
    assert everything and all("rule" not in i for i in everything)  # archives : événements bruts
    alerts = sim.search_logs(SearchLogsArgs(**base, index="wazuh-alerts-*"))["items"]
    assert len(alerts) == 1 and alerts[0]["rule"]["id"] == "100200"
    by_ioc = sim.search_logs(SearchLogsArgs(**base, ioc="203.0.113.45"))["items"]
    assert by_ioc and all("203.0.113.45" in str(i) for i in by_ioc)
    typed = sim.search_logs(SearchLogsArgs(**base, event_types=["network_connection"]))["items"]
    assert typed and all(i["event_type"] == "network_connection" for i in typed)
    assert sim.search_logs(SearchLogsArgs(**base, host="WIN-SRV01"))["items"] == []


def test_process_tree(scenarios):
    sim = SimulationBackend(scenarios["S3"])
    tree = sim.get_process_tree(ProcessTreeArgs(host="WIN10-01", image="rundll32.exe",
                                                around=datetime(2026, 10, 14, 10, 5, 52, tzinfo=timezone.utc)))["items"]
    relations = {i["relation"] for i in tree}
    assert {"target", "ancestor"} <= relations
    assert any(i["relation"] == "ancestor" and i["fields"]["image"].endswith("cmd.exe") for i in tree)


def test_simulated_faults(scenarios):
    sim = SimulationBackend(dict(scenarios["S1"], faults={"misp_lookup": "unavailable", "ti_lookup": "empty"}))
    with pytest.raises(ConnectorError):
        sim.misp_lookup(MispLookupArgs(value="203.0.113.45", type="ip"))
    assert sim.ti_lookup(TiLookupArgs(value="203.0.113.45", type="ip"))["items"] == []


def test_misp_connector(monkeypatch):
    calls = {}

    def fake_request(self, method, url, **kwargs):
        calls.update(method=method, url=url, json=kwargs.get("json"), auth=self.headers.get("Authorization"))
        return FakeResponse(200, {"response": {"Attribute": [{
            "id": "1", "type": "ip-dst", "value": "203.0.113.45", "to_ids": True, "category": "Network activity",
            "timestamp": "1790000000", "Event": {"id": "12", "info": "C2", "threat_level_id": "1"}}]}})

    monkeypatch.setattr(requests.Session, "request", fake_request)
    out = MispConnector("https://misp", "CLE-SECRETE").lookup(MispLookupArgs(value="203.0.113.45", type="ip"))
    assert calls["url"].endswith("/attributes/restSearch") and calls["auth"] == "CLE-SECRETE"
    assert out["items"][0]["verdict"] == "malicious" and out["items"][0]["event_info"] == "C2"


def test_http_errors_are_classified(monkeypatch):
    monkeypatch.setattr(requests.Session, "request", lambda self, m, u, **k: FakeResponse(429, {}))
    with pytest.raises(ConnectorError) as exc:
        MispConnector("https://misp", "k").lookup(MispLookupArgs(value="x.example", type="domain"))
    assert exc.value.transient

    def boom(self, m, u, **k):
        raise requests.ConnectionError("refused")

    monkeypatch.setattr(requests.Session, "request", boom)
    with pytest.raises(ConnectorError) as exc:
        MispConnector("https://misp", "k").lookup(MispLookupArgs(value="x.example", type="domain"))
    assert "indisponible" in str(exc.value)


def test_ti_normalization():
    assert normalize_virustotal("x", "ip", {"data": {"attributes": {"last_analysis_stats": {
        "malicious": 10, "harmless": 50}}}})["verdict"] == "malicious"
    assert normalize_virustotal("x", "ip", {"data": {"attributes": {"last_analysis_stats": {
        "malicious": 0, "harmless": 70}}}})["verdict"] == "benign"
    assert normalize_virustotal("x", "ip", None)["verdict"] == "unknown"
    assert normalize_abuseipdb("x", {"data": {"abuseConfidenceScore": 90, "totalReports": 5}})["verdict"] == "malicious"
    assert normalize_abuseipdb("x", {"data": {"abuseConfidenceScore": 30, "totalReports": 5}})["verdict"] == "suspicious"


def test_ti_service_cache_and_missing_keys(db_url):
    calls = []

    class FakeVT:
        def fetch(self, value, otype):
            calls.append(value)
            return {"data": {"attributes": {"last_analysis_stats": {"malicious": 7, "harmless": 40}}}}

    svc = ThreatIntelService(virustotal=FakeVT(), abuseipdb=None, cache=TICache(db_url))
    args = TiLookupArgs(value="203.0.113.45", type="ip")
    first = svc.lookup(args)
    second = svc.lookup(args)
    assert calls == ["203.0.113.45"] and second["items"][0]["cached"]
    assert first["meta"]["errors"]["abuseipdb"] == "clé d'API non configurée"
    with pytest.raises(ConnectorError):
        ThreatIntelService(virustotal=None, abuseipdb=None).lookup(args)


def test_wazuh_query_is_read_only_search(monkeypatch):
    captured = {}

    def fake_request(self, method, url, **kwargs):
        captured.update(method=method, url=url, body=kwargs["json"])
        return FakeResponse(200, {"hits": {"hits": []}})

    monkeypatch.setattr(requests.Session, "request", fake_request)
    conn = WazuhIndexerConnector("https://wazuh:9200", "admin", "pwd")
    args = SearchLogsArgs(start="2026-10-12T08:00:00Z", end="2026-10-12T10:00:00Z", host="WIN10-01",
                          ioc="203.0.113.45", event_types=["network_connection"], limit=50)
    conn.search_logs(args)
    assert captured["method"] == "POST" and captured["url"].endswith("/wazuh-archives-*/_search")
    body = captured["body"]
    assert body["size"] == 50
    assert {"term": {"agent.name": "WIN10-01"}} in body["query"]["bool"]["filter"]
    assert {"terms": {"data.win.system.eventID": ["3"]}} in body["query"]["bool"]["filter"]


def test_tree_empty_when_target_absent():
    args = ProcessTreeArgs(host="H", image="x.exe", around="2026-10-12T09:00:00Z")
    assert build_process_tree([], args) == []
