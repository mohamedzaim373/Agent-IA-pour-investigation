"""Connecteur Wazuh : requêtes en lecture sur l'indexeur (OpenSearch) et
normalisation des événements Windows / Sysmon.

Les archives (`wazuh-archives-*`) nécessitent `logall_json` dans ossec.conf
(voir lab/wazuh/ossec.conf). Les fonctions de normalisation, de filtrage et de
reconstruction d'arbre de processus sont partagées avec le backend de simulation,
qui rejoue des documents au format Wazuh.
"""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

import requests

from connectors.base import http_json, parse_iso, to_iso_utc, truncate
from gateway.tool_schemas import ProcessTreeArgs, SearchLogsArgs

VERSION = "1.0"

SYSMON_EVENTS = {
    "1": "process_creation",
    "2": "file_time_changed",
    "3": "network_connection",
    "5": "process_terminated",
    "6": "driver_loaded",
    "7": "image_loaded",
    "8": "create_remote_thread",
    "10": "process_access",
    "11": "file_create",
    "12": "registry_object",
    "13": "registry_value_set",
    "14": "registry_rename",
    "15": "file_stream_created",
    "17": "pipe_created",
    "22": "dns_query",
    "23": "file_delete",
}
SECURITY_EVENTS = {
    "4624": "logon",
    "4625": "logon_failed",
    "4688": "process_creation",
    "4698": "scheduled_task_created",
    "4720": "user_created",
    "4732": "group_member_added",
    "1102": "log_cleared",
    "7045": "service_installed",
    "4104": "powershell_script_block",
}
EVENT_IDS_BY_TYPE: dict[str, list[str]] = {}
for _eid, _etype in {**SYSMON_EVENTS, **SECURITY_EVENTS}.items():
    EVENT_IDS_BY_TYPE.setdefault(_etype, []).append(_eid)

FIELD_MAP = {
    "image": "image",
    "commandLine": "command_line",
    "parentImage": "parent_image",
    "parentCommandLine": "parent_command_line",
    "user": "user",
    "processGuid": "process_guid",
    "parentProcessGuid": "parent_process_guid",
    "processId": "pid",
    "parentProcessId": "ppid",
    "hashes": "hashes",
    "originalFileName": "original_file_name",
    "currentDirectory": "current_directory",
    "integrityLevel": "integrity_level",
    "destinationIp": "destination_ip",
    "destinationPort": "destination_port",
    "destinationHostname": "destination_hostname",
    "sourceIp": "source_ip",
    "sourcePort": "source_port",
    "protocol": "protocol",
    "initiated": "initiated",
    "queryName": "query_name",
    "queryResults": "query_results",
    "targetFilename": "target_filename",
    "targetObject": "target_object",
    "details": "details",
    "eventType": "registry_event",
    "sourceImage": "source_image",
    "targetImage": "target_image",
    "grantedAccess": "granted_access",
    "callTrace": "call_trace",
    "imageLoaded": "image_loaded",
    "signed": "signed",
    "signature": "signature",
    "taskName": "task_name",
    "taskContent": "task_content",
    "subjectUserName": "subject_user",
    "targetUserName": "target_user",
    "logonType": "logon_type",
    "ipAddress": "source_ip",
    "serviceName": "service_name",
    "imagePath": "service_image",
    "scriptBlockText": "script_block",
}


def _basename(path: str | None) -> str:
    if not path:
        return ""
    return str(path).replace("/", "\\").rsplit("\\", 1)[-1]


def parse_hashes(raw: str | None) -> dict[str, str]:
    """« SHA256=abc,MD5=def » -> {"sha256": "abc", "md5": "def"}"""
    out: dict[str, str] = {}
    for part in str(raw or "").split(","):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip().lower()] = v.strip().lower()
    return out


def normalize_event(doc: dict[str, Any]) -> dict[str, Any]:
    """Convertit un document Wazuh (alerte ou archive) en élément normalisé."""
    src = doc.get("_source", doc)
    win = (src.get("data") or {}).get("win") or {}
    system = win.get("system") or {}
    eventdata = win.get("eventdata") or {}
    event_id = str(system.get("eventID") or "")
    provider = str(system.get("providerName") or "")
    if "Sysmon" in provider:
        event_type = SYSMON_EVENTS.get(event_id, f"sysmon_{event_id}")
    elif event_id in SECURITY_EVENTS:
        event_type = SECURITY_EVENTS[event_id]
    elif src.get("rule"):
        event_type = "wazuh_alert"
    else:
        event_type = "event"

    fields: dict[str, Any] = {}
    for key, value in eventdata.items():
        norm = FIELD_MAP.get(key)
        if norm and value not in (None, ""):
            fields[norm] = value
    if "hashes" in fields:
        hashes = parse_hashes(fields["hashes"])
        fields["hashes"] = hashes
        if "sha256" in hashes:
            fields["sha256"] = hashes["sha256"]
    for key in ("pid", "ppid", "destination_port", "source_port"):
        if key in fields:
            try:
                fields[key] = int(fields[key])
            except (TypeError, ValueError):
                pass
    if event_id:
        fields["event_id"] = event_id

    agent = src.get("agent") or {}
    host = agent.get("name") or str(system.get("computer") or "").split(".")[0] or None
    timestamp = to_iso_utc(system.get("systemTime") or src.get("timestamp") or src.get("@timestamp"))
    item: dict[str, Any] = {
        "source": "wazuh",
        "raw_ref": doc.get("_id") or src.get("id"),
        "timestamp": timestamp,
        "host": host,
        "host_ip": agent.get("ip"),
        "event_type": event_type,
        "fields": fields,
    }
    rule = src.get("rule")
    if rule:
        item["rule"] = {
            "id": str(rule.get("id", "")),
            "level": rule.get("level"),
            "description": rule.get("description"),
            "mitre": (rule.get("mitre") or {}).get("id", []),
        }
    item["summary"] = summarize(item)
    return item


def summarize(item: dict[str, Any]) -> str:
    f = item.get("fields", {})
    et = item.get("event_type")
    user = f.get("user") or f.get("subject_user") or ""
    if et == "process_creation":
        s = f"Création de processus {_basename(f.get('image'))}"
        s += f" par {user}" if user else ""
        s += f" (parent {_basename(f.get('parent_image'))})" if f.get("parent_image") else ""
        s += f" : {truncate(f.get('command_line'), 300)}" if f.get("command_line") else ""
    elif et == "network_connection":
        dst = f.get("destination_hostname") or f.get("destination_ip")
        s = f"Connexion réseau de {_basename(f.get('image'))} vers {dst}:{f.get('destination_port', '?')}"
        if f.get("destination_hostname") and f.get("destination_ip"):
            s += f" ({f.get('destination_ip')})"
    elif et == "dns_query":
        s = f"Requête DNS {f.get('query_name')} par {_basename(f.get('image'))} -> {truncate(f.get('query_results'), 80)}"
    elif et == "file_create":
        s = f"Création de fichier {f.get('target_filename')} par {_basename(f.get('image'))}"
    elif et in {"registry_value_set", "registry_object"}:
        s = f"Registre : {f.get('target_object')} = {truncate(f.get('details'), 160)} (par {_basename(f.get('image'))})"
    elif et == "process_access":
        s = (f"Accès au processus {_basename(f.get('target_image'))} par {_basename(f.get('source_image'))}"
             f" (droits {f.get('granted_access')})")
    elif et == "scheduled_task_created":
        s = f"Tâche planifiée créée : {f.get('task_name')} par {f.get('subject_user')}"
    elif et == "image_loaded":
        s = f"Chargement de {f.get('image_loaded')} par {_basename(f.get('image'))}"
    elif et == "logon":
        s = f"Ouverture de session {f.get('target_user')} (type {f.get('logon_type')}) depuis {f.get('source_ip')}"
    elif et == "service_installed":
        s = f"Service installé : {f.get('service_name')} ({f.get('service_image')})"
    else:
        s = f"Événement {et} {f.get('event_id', '')}".strip()
    rule = item.get("rule")
    if rule and rule.get("description"):
        s = f"[Alerte {rule.get('id')} niv. {rule.get('level')}] {rule.get('description')} — {s}"
    return s


def matches(item: dict[str, Any], args: SearchLogsArgs, *, is_alert: bool) -> bool:
    """Filtre équivalent à la requête OpenSearch, pour le backend de simulation."""
    # Les alertes sont dans wazuh-alerts-*, les événements bruts dans wazuh-archives-* :
    # on ne mélange pas les deux pour ne pas dupliquer un même événement.
    if args.index.startswith("wazuh-alerts") != is_alert:
        return False
    ts = parse_iso(item.get("timestamp"))
    if ts is None or not (args.start <= ts <= args.end):
        return False
    host = (item.get("host") or "").lower()
    if args.host and args.host.lower().split(".")[0] != host:
        return False
    blob = json.dumps(item, ensure_ascii=False, default=str).lower()
    if args.user:
        users = " ".join(str(item["fields"].get(k, "")) for k in ("user", "subject_user", "target_user")).lower()
        wanted = args.user.lower()
        if wanted not in users and wanted.split("\\")[-1] not in users:
            return False
    if args.ioc and args.ioc.lower() not in blob.replace("\\\\", "\\"):
        return False
    for term in args.terms:
        if term.lower() not in blob.replace("\\\\", "\\"):
            return False
    if args.event_types and item.get("event_type") not in args.event_types:
        return False
    return True


def build_process_tree(events: list[dict[str, Any]], args: ProcessTreeArgs) -> list[dict[str, Any]]:
    """Arbre de processus à partir d'événements de création normalisés."""
    lo = args.around - timedelta(minutes=args.window_minutes)
    hi = args.around + timedelta(minutes=args.window_minutes)
    host = args.host.lower().split(".")[0]
    procs = [
        e for e in events
        if e.get("event_type") == "process_creation" and (e.get("host") or "").lower() == host
        and (ts := parse_iso(e.get("timestamp"))) is not None and lo <= ts <= hi
    ]
    by_guid = {e["fields"].get("process_guid"): e for e in procs if e["fields"].get("process_guid")}

    target = None
    if args.process_guid:
        target = by_guid.get(args.process_guid)
    if target is None and args.pid is not None:
        cands = [e for e in procs if e["fields"].get("pid") == args.pid]
        target = min(cands, key=lambda e: abs((parse_iso(e["timestamp"]) - args.around).total_seconds())) if cands else None
    if target is None and args.image:
        wanted = _basename(args.image).lower()
        cands = [e for e in procs if _basename(e["fields"].get("image")).lower() == wanted]
        target = min(cands, key=lambda e: abs((parse_iso(e["timestamp"]) - args.around).total_seconds())) if cands else None
    if target is None:
        return []

    result = [dict(target, relation="target")]
    seen = {target["fields"].get("process_guid")}
    parent_guid = target["fields"].get("parent_process_guid")
    depth = 0
    while parent_guid and parent_guid in by_guid and parent_guid not in seen and depth < 10:
        parent = by_guid[parent_guid]
        result.append(dict(parent, relation="ancestor"))
        seen.add(parent_guid)
        parent_guid = parent["fields"].get("parent_process_guid")
        depth += 1
    frontier = [target["fields"].get("process_guid")]
    while frontier:
        guid = frontier.pop()
        for e in procs:
            g = e["fields"].get("process_guid")
            if e["fields"].get("parent_process_guid") == guid and g not in seen:
                result.append(dict(e, relation="child"))
                seen.add(g)
                frontier.append(g)
    result.sort(key=lambda e: e.get("timestamp") or "")
    for e in result:
        e["summary"] = f"[{e['relation']}] " + e["summary"]
    return result


class WazuhIndexerConnector:
    """Requêtes en lecture seule sur l'indexeur Wazuh (API OpenSearch)."""

    VERSION = VERSION

    def __init__(self, url: str, user: str, password: str, verify_tls: bool = False, timeout: float = 20):
        self.url = url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.auth = (user, password)
        self.session.verify = verify_tls
        self.session.headers.update({"Content-Type": "application/json"})

    def _search(self, index: str, query: dict[str, Any]) -> list[dict[str, Any]]:
        data = http_json(self.session, "POST", f"{self.url}/{index}/_search", json=query, timeout=self.timeout)
        return (data or {}).get("hits", {}).get("hits", [])

    def build_query(self, args: SearchLogsArgs) -> dict[str, Any]:
        filters: list[dict[str, Any]] = [
            {"range": {"timestamp": {"gte": args.start.isoformat(), "lte": args.end.isoformat()}}}
        ]
        must: list[dict[str, Any]] = []
        if args.host:
            filters.append({"term": {"agent.name": args.host.split(".")[0]}})
        if args.user:
            must.append({"multi_match": {"query": args.user, "type": "phrase",
                                         "fields": ["data.win.eventdata.user", "data.win.eventdata.subjectUserName",
                                                    "data.win.eventdata.targetUserName"]}})
        for value in ([args.ioc] if args.ioc else []) + list(args.terms):
            must.append({"multi_match": {"query": value, "type": "phrase", "lenient": True, "fields": ["*"]}})
        if args.event_types:
            ids = sorted({i for t in args.event_types for i in EVENT_IDS_BY_TYPE.get(t, [])})
            if ids:
                filters.append({"terms": {"data.win.system.eventID": ids}})
        return {"size": args.limit, "sort": [{"timestamp": {"order": "asc"}}],
                "query": {"bool": {"filter": filters, "must": must}}}

    def search_logs(self, args: SearchLogsArgs) -> dict[str, Any]:
        hits = self._search(args.index, self.build_query(args))
        items = [normalize_event(h) for h in hits]
        return {"items": items, "meta": {"index": args.index, "returned": len(items)}}

    def get_process_tree(self, args: ProcessTreeArgs) -> dict[str, Any]:
        lo = args.around - timedelta(minutes=args.window_minutes)
        hi = args.around + timedelta(minutes=args.window_minutes)
        query = {
            "size": 1000,
            "sort": [{"timestamp": {"order": "asc"}}],
            "query": {"bool": {"filter": [
                {"range": {"timestamp": {"gte": lo.isoformat(), "lte": hi.isoformat()}}},
                {"term": {"agent.name": args.host.split(".")[0]}},
                {"terms": {"data.win.system.eventID": ["1", "4688"]}},
            ]}},
        }
        events = [normalize_event(h) for h in self._search("wazuh-archives-*", query)]
        # Une absence de résultat n'est pas une erreur : la liste vide est renvoyée.
        tree = build_process_tree(events, args)
        return {"items": tree, "meta": {"candidates": len(events)}}
