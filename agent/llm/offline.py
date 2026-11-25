"""OfflineLLM : modèle de référence à base de règles (baseline).

Il implémente les mêmes tâches que les LLM (qualifier, planifier, agir,
rédiger le rapport) à partir du contexte structuré, sans réseau ni GPU. Il
sert à trois choses :
  - faire tourner le prototype et les tests sans clé d'API ;
  - fournir une référence d'évaluation face aux LLM (chapitre 14) ;
  - garantir un comportement déterministe et reproductible.

Ses heuristiques sont volontairement simples et documentées : elles ne
remplacent pas le raisonnement d'un LLM, elles le rendent comparable.
"""

from __future__ import annotations

import json
import re
from datetime import timedelta
from typing import Any

from agent.llm.base import BaseLLM
from connectors.base import parse_iso
from gateway.hashing import canonical_json
from gateway.observables import is_internal_ip

# ----------------------------------------------------------------------------
# Indices de comportement suspect : (nom, motif, requête ATT&CK, force)
# ----------------------------------------------------------------------------
COMMAND_RULES: list[tuple[str, re.Pattern[str], str, str]] = [
    (name, re.compile(rx, re.IGNORECASE), query, strength)
    for name, rx, query, strength in [
        ("powershell_encoded", r"powershell(\.exe)?\b.*\s-(e|en|enc|enco|encod\w*)\s+[A-Za-z0-9+/=]{16,}",
         "PowerShell execution with encoded command", "medium"),
        ("download_cradle", r"(downloadstring|downloadfile|invoke-webrequest|\biwr\b|net\.webclient|start-bitstransfer|bitsadmin\s+/transfer)",
         "download payload from internet ingress tool transfer", "strong"),
        ("certutil_download", r"certutil(\.exe)?\b.*(urlcache|-split|\s-f\s+https?://)",
         "certutil urlcache download ingress tool transfer", "strong"),
        ("lsass_dump", r"(comsvcs(\.dll)?\W+.*minidump|procdump(64)?(\.exe)?\b.*lsass|sekurlsa|mimikatz)",
         "lsass memory dump credential dumping", "strong"),
        ("run_key", r"(reg(\.exe)?\s+add\b.*\\currentversion\\run|new-itemproperty\b.*\\currentversion\\run)",
         "registry run keys persistence", "strong"),
        ("scheduled_task", r"schtasks(\.exe)?\s+/create", "scheduled task creation persistence", "strong"),
        ("whoami", r"\bwhoami(\.exe)?\b", "system owner user discovery whoami", "weak"),
        ("net_user", r"\bnet1?(\.exe)?\s+(user|localgroup)\b", "local account discovery net user", "weak"),
        ("ipconfig", r"\bipconfig(\.exe)?\b", "system network configuration discovery ipconfig", "weak"),
        ("systeminfo", r"\bsysteminfo(\.exe)?\b", "system information discovery systeminfo", "weak"),
    ]
]

LSASS_ACCESS = {"0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff", "0x1f3fff", "0x40"}
SUSPICIOUS_DIRS = re.compile(r"\\(temp|tmp|users\\public|appdata\\local\\temp|programdata|downloads)\\", re.IGNORECASE)
LOLBINS = re.compile(r"\\(powershell|pwsh|cmd|rundll32|regsvr32|mshta|certutil|bitsadmin|wscript|cscript)\.exe$",
                     re.IGNORECASE)
# Agents d'administration reconnus : leurs scripts encodés sont une source
# classique de faux positifs.
SYSTEM_DIRS = re.compile(r"^[a-z]:\\(windows|program files( \(x86\))?)\\", re.IGNORECASE)
MANAGEMENT_PARENTS = re.compile(r"\\(ccmexec|intunemanagementextension|monitoringhost)\.exe$", re.IGNORECASE)

VERDICT_RANK = {"malicious": 3, "suspicious": 2, "known": 1, "benign": 0, "unknown": -1}


def _basename(path: str | None) -> str:
    return str(path or "").replace("/", "\\").rsplit("\\", 1)[-1]


def classify_event(ev: dict[str, Any]) -> dict[str, Any] | None:
    """Indices portés par un événement : {rule, query, strength, legit} ou None."""
    ex = ev.get("excerpt") or ev
    f = ex.get("fields") or {}
    etype = ex.get("event_type") or ev.get("event_type")
    cmd = str(f.get("command_line") or "")
    parent = str(f.get("parent_image") or "")
    legit = bool(MANAGEMENT_PARENTS.search(parent))

    if etype == "process_creation" and cmd:
        for name, rx, query, strength in COMMAND_RULES:
            if rx.search(cmd):
                return {"rule": name, "query": f"{query}: {cmd[:160]}", "strength": strength, "legit": legit}
    if etype == "process_access" and _basename(f.get("target_image")).lower() == "lsass.exe":
        access = str(f.get("granted_access") or "").lower()
        if access in LSASS_ACCESS:
            return {"rule": "lsass_access", "query": "process access to lsass memory credential dumping",
                    "strength": "strong", "legit": False}
    if etype == "registry_value_set" and re.search(r"\\currentversion\\run", str(f.get("target_object")), re.I):
        return {"rule": "run_key_value", "query": "registry run keys startup persistence", "strength": "strong",
                "legit": legit}
    if etype == "scheduled_task_created":
        return {"rule": "task_created", "query": "scheduled task created persistence", "strength": "strong",
                "legit": legit}
    if etype == "network_connection":
        dst = str(f.get("destination_ip") or "")
        if dst and not is_internal_ip(dst) and LOLBINS.search(str(f.get("image") or "")):
            return {"rule": "lolbin_external_connection",
                    "query": f"application layer protocol web command and control from {_basename(f.get('image'))}",
                    "strength": "medium", "legit": legit}
    if etype == "file_create":
        target = str(f.get("target_filename") or "")
        if target.lower().endswith(".dmp") and (SUSPICIOUS_DIRS.search(target) or "lsass" in target.lower()):
            return {"rule": "memory_dump_file", "query": "lsass memory dump file written to disk credential dumping",
                    "strength": "strong", "legit": legit}
        if SUSPICIOUS_DIRS.search(target) and target.lower().endswith((".exe", ".dll", ".ps1", ".bat", ".hta")):
            return {"rule": "payload_dropped", "query": "ingress tool transfer payload written to disk",
                    "strength": "medium", "legit": legit}
    return None


def _sig(tool: str, args: dict[str, Any]) -> str:
    key = dict(args)
    key.pop("limit", None)
    return f"{tool}:{canonical_json(key)}"


def _iso(dt) -> str:
    return dt.isoformat().replace("+00:00", "Z")


class OfflineLLM(BaseLLM):
    provider = "offline"
    model = "rules-baseline-1.0"

    def generate(self, task: str, system: str, user: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
        ctx = context or {}
        handler = getattr(self, f"_task_{task}", None)
        if handler is None:
            raise ValueError(f"tâche inconnue : {task}")
        result = handler(ctx)
        # Estimation grossière pour les métriques d'efficience (aucun coût réel).
        self._count(len(user) // 4, len(json.dumps(result, ensure_ascii=False, default=str)) // 4)
        return result

    # ------------------------------------------------------------- qualifier
    def _task_qualify(self, ctx: dict[str, Any]) -> dict[str, Any]:
        alert = ctx.get("alert", {})
        level = int((alert.get("rule") or {}).get("level") or 0)
        severity = "critical" if level >= 13 else "high" if level >= 10 else "medium" if level >= 6 else "low"
        desc = (alert.get("rule") or {}).get("description") or alert.get("summary", "")
        hint = classify_event({"excerpt": alert})
        hypotheses = [
            {"id": "H1", "statement": f"Activité malveillante réelle sur {alert.get('host')} : {desc}",
             "confidence": 0.5},
            {"id": "H2", "statement": "Activité légitime (administration, outil de gestion) déclenchant la règle",
             "confidence": 0.5},
        ]
        if hint and hint["legit"]:
            hypotheses[0]["confidence"], hypotheses[1]["confidence"] = 0.35, 0.65
        return {
            "severity": severity,
            "assessment": f"Alerte de niveau {level} ({desc}). Les observables sont à vérifier dans les journaux, "
                          f"MISP et la Threat Intelligence avant de conclure.",
            "hypotheses": hypotheses,
        }

    # ------------------------------------------------------------- planifier
    def _task_plan(self, ctx: dict[str, Any]) -> dict[str, Any]:
        tools = set(ctx.get("available_tools", []))
        existing = ctx.get("steps", [])
        done_sigs = {_sig(s["tool"], s.get("args", {})) for s in existing}
        pending = [s for s in existing if s.get("status") == "pending"]
        new_steps: list[dict[str, Any]] = []
        changes: list[dict[str, str]] = []
        counter = len(existing)
        max_new = int(ctx.get("max_new_steps", 8))

        def add(tool: str, args: dict[str, Any], objective: str, justification: str,
                related: list[str] | None = None, hyps: list[str] | None = None) -> None:
            nonlocal counter
            if tool not in tools or len(new_steps) >= max_new:
                return
            sig = _sig(tool, args)
            if sig in done_sigs:
                return
            done_sigs.add(sig)
            counter += 1
            new_steps.append({"id": f"S{counter}", "objective": objective, "tool": tool, "args": args,
                              "hypothesis_ids": hyps or ["H1", "H2"], "related_evidence": related or []})
            changes.append({"change": f"ajout de S{counter} ({tool})", "justification": justification})

        alert = ctx.get("alert", {})
        host = alert.get("host")
        t0 = parse_iso(ctx.get("alert_time") or alert.get("timestamp"))
        f = alert.get("fields") or {}

        for d in ctx.get("directives", []):
            if d.get("type") == "impose_lead" and d.get("tool") in tools:
                add(d["tool"], d.get("args", {}), f"Piste imposée par l'analyste : {d.get('text', '')}",
                    "consigne de l'analyste (EF-20)")

        if ctx.get("mode") == "initial" and t0 is not None:
            add("search_logs", {"host": host, "start": _iso(t0 - timedelta(minutes=60)),
                                "end": _iso(t0 + timedelta(minutes=60)), "index": "wazuh-archives-*", "limit": 200},
                "Reconstituer l'activité de l'hôte une heure avant et après l'alerte",
                "contexte temporel indispensable à la chronologie")
            if f.get("process_guid") or f.get("image"):
                args: dict[str, Any] = {"host": host, "around": _iso(t0), "window_minutes": 60}
                if f.get("process_guid"):
                    args["process_guid"] = f["process_guid"]
                else:
                    args["image"] = f["image"]
                add("get_process_tree", args, "Identifier le processus parent et les processus enfants",
                    "la lignée du processus distingue un usage légitime d'une exécution malveillante")

        # Observables externes à vérifier : réseau d'abord, puis empreintes de
        # fichiers hors des répertoires système (les binaires Windows signés
        # n'apportent rien et consomment le quota de TI).
        candidates = {}
        for o in ctx.get("observables", []) + ctx.get("new_observables", []):
            if o.get("internal") or o["type"] not in {"ip", "domain", "url", "sha256", "sha1", "md5"}:
                continue
            if o["type"] in {"sha256", "sha1", "md5"} and SYSTEM_DIRS.search(str(o.get("context") or "")):
                continue
            candidates.setdefault(f"{o['type']}:{o['value'].lower()}", o)
        priority = {"ip": 0, "domain": 1, "url": 2, "sha256": 3, "sha1": 4, "md5": 5}
        for o in sorted(candidates.values(), key=lambda o: priority[o["type"]]):
            add("misp_lookup", {"value": o["value"], "type": o["type"]},
                f"Vérifier {o['value']} dans la base d'IOC MISP", "observable externe non encore vérifié")
            add("ti_lookup", {"value": o["value"], "type": o["type"]},
                f"Réputation de {o['value']} (VirusTotal, AbuseIPDB)", "observable externe non encore vérifié")

        mapped = {e for s in existing if s["tool"] == "attack_search" for e in s.get("related_evidence", [])}
        groups: dict[str, list[dict[str, Any]]] = {}
        for ev in ctx.get("evidence", []):
            if ev.get("tool") not in {"search_logs", "get_process_tree"}:
                continue
            groups.setdefault(ev.get("raw_ref") or ev["evidence_id"], []).append(ev)
        for evs in groups.values():
            ids = [e["evidence_id"] for e in evs]
            if any(i in mapped for i in ids):
                continue
            hint = classify_event(evs[0])
            if not hint or hint["legit"]:
                continue
            add("attack_search", {"query": hint["query"], "k": 5},
                f"Rattacher à ATT&CK : {evs[0].get('summary', '')[:90]}",
                f"comportement suspect ({hint['rule']}) non encore rattaché", related=ids, hyps=["H1"])

        if t0 is not None:
            for ioc in ctx.get("malicious_iocs", []):
                add("search_logs", {"ioc": ioc, "start": _iso(t0 - timedelta(hours=12)),
                                    "end": _iso(t0 + timedelta(hours=12)), "index": "wazuh-archives-*", "limit": 200},
                    f"Pivot : rechercher {ioc} sur tous les hôtes", "IOC malveillant confirmé (EF-11)", hyps=["H1"])

        steps = pending + new_steps
        rationale = ("Plan initial : contexte de l'hôte, lignée du processus, vérification des observables."
                     if ctx.get("mode") == "initial" else
                     f"Révision : {len(new_steps)} étape(s) ajoutée(s) à partir des observations.")
        return {"rationale": rationale, "changes": changes, "hypotheses": ctx.get("hypotheses", []), "steps": steps}

    # ------------------------------------------------------------------ agir
    def _task_act(self, ctx: dict[str, Any]) -> dict[str, Any]:
        for step in ctx.get("steps", []):
            if step.get("status") == "pending":
                return {"action": "call_tool", "step_id": step["id"], "tool": step["tool"], "args": step.get("args", {}),
                        "justification": step.get("objective", "")}
        return {"action": "conclude", "reason": "plan exécuté : toutes les vérifications prévues sont faites"}

    # ---------------------------------------------------------------- rapport
    def _task_report(self, ctx: dict[str, Any]) -> dict[str, Any]:
        alert = ctx.get("alert", {})
        host = alert.get("host")
        evidence = ctx.get("evidence", [])
        attack = ctx.get("attack", [])

        # IOC : agrégation des verdicts MISP et TI.
        iocs: dict[str, dict[str, Any]] = {}
        for ev in evidence:
            if ev.get("tool") not in {"misp_lookup", "ti_lookup"}:
                continue
            ex = ev.get("excerpt", {})
            value = ex.get("queried") or ex.get("value")
            if not value:
                continue
            otype = (ev.get("query") or {}).get("type", ex.get("type", "?"))
            cur = iocs.setdefault(value.lower(), {"type": otype, "value": value, "verdict": "unknown",
                                                  "sources": [], "evidence_ids": []})
            verdict = ex.get("verdict", "unknown")
            if verdict == "known":
                verdict = "suspicious"
            if VERDICT_RANK.get(verdict, -1) > VERDICT_RANK.get(cur["verdict"], -1):
                cur["verdict"] = verdict
            if ex.get("source") not in cur["sources"]:
                cur["sources"].append(ex.get("source"))
            cur["evidence_ids"].append(ev["evidence_id"])
        malicious_iocs = [i for i in iocs.values() if i["verdict"] == "malicious"]

        # Événements : regroupement par événement d'origine, puis classification.
        groups: dict[str, list[dict[str, Any]]] = {}
        for ev in evidence:
            if ev.get("tool") in {"search_logs", "get_process_tree"}:
                groups.setdefault(ev.get("raw_ref") or ev["evidence_id"], []).append(ev)
        ev_by_id = {e["evidence_id"]: e for e in evidence}
        tech_by_ev: dict[str, list[str]] = {}
        techniques: dict[str, dict[str, Any]] = {}
        for a in attack:
            related_hints = [classify_event(ev_by_id[i]) for i in a.get("related_evidence", []) if i in ev_by_id]
            strength = "strong" if any(h and h["strength"] == "strong" for h in related_hints) else "medium"
            if not a.get("results"):
                continue
            # Meilleur résultat, plus le second s'il est presque aussi pertinent.
            tops = a["results"][:1] + [r for r in a["results"][1:2] if float(r.get("score") or 0) >= 0.9]
            for top in tops:
                for ev_id in a.get("related_evidence", []):
                    tech_by_ev.setdefault(ev_id, []).append(top["technique_id"])
                t = techniques.setdefault(top["technique_id"], {
                    "technique_id": top["technique_id"], "name": top.get("name", ""), "tactics": top.get("tactics", []),
                    "justification": "", "confidence": 0.0, "evidence_ids": [], "fragment_ids": []})
                t["evidence_ids"] += [e for e in a.get("related_evidence", []) + [top["evidence_id"]]
                                      if e not in t["evidence_ids"]]
                if top["fragment_id"] not in t["fragment_ids"]:
                    t["fragment_ids"].append(top["fragment_id"])
                t["_hints"] = t.get("_hints", []) + [strength]
                t["_queries"] = t.get("_queries", []) + [a.get("query", "")]

        suspicious, legit, strong, timeline, network_evs = [], [], [], [], []
        injected = []
        mal_values = {i["value"].lower() for i in malicious_iocs}
        for ref, evs in groups.items():
            ids = [e["evidence_id"] for e in evs]
            head = evs[0]
            if any("injection_suspected" in (e.get("flags") or []) for e in evs):
                injected.append(ids[0])
            hint = classify_event(head)
            hits = _ioc_hits(head, mal_values)
            if hits and (hint is None or hint["legit"]):
                # Corrélation : l'événement porte un IOC confirmé malveillant (empreinte, destination).
                hint = {"rule": "ioc_match", "query": "", "strength": "strong", "legit": False}
            if hits:
                head = dict(head, summary=f"{head.get('summary', '')} — IOC malveillant : {', '.join(hits)}")
            is_alert = bool((head.get("excerpt") or {}).get("rule"))
            if hint is None and not is_alert:
                continue
            if hint and hint["legit"]:
                legit.append(ids)
                desc = head.get("summary", "") + " — lancé par un agent d'administration reconnu"
                timeline.append({"timestamp": head.get("observed_at"), "host": head.get("host"), "description": desc,
                                 "kind": "observed", "confidence": 0.9, "evidence_ids": ids, "techniques": []})
                continue
            if hint:
                suspicious.append(ids)
                if hint["strength"] == "strong":
                    strong.append(ids)
                if head.get("event_type") == "network_connection":
                    network_evs.append(head)
            techs = sorted({t for i in ids for t in tech_by_ev.get(i, [])})
            timeline.append({"timestamp": head.get("observed_at"), "host": head.get("host"),
                             "description": head.get("summary", ""), "kind": "observed",
                             "confidence": 0.9 if hint else 0.8, "evidence_ids": ids, "techniques": techs})

        # Verdict.
        if malicious_iocs or strong or len(suspicious) >= 3:
            verdict = "true_positive"
            confidence = min(0.95, 0.6 + 0.1 * len(malicious_iocs) + 0.1 * len(strong) + 0.02 * len(suspicious))
        elif not suspicious and legit:
            verdict = "false_positive"
            benign_ti = any(i["verdict"] == "benign" for i in iocs.values())
            confidence = 0.85 if benign_ti or not iocs else 0.75
        elif not suspicious and not malicious_iocs:
            verdict = "false_positive" if iocs and all(i["verdict"] in {"benign", "unknown"} for i in iocs.values()) \
                else "needs_investigation"
            confidence = 0.55
        else:
            verdict = "needs_investigation"
            confidence = 0.5

        # Rattachements ATT&CK (uniquement pour les comportements suspects retenus).
        suspicious_ids = {i for ids in suspicious for i in ids}
        tech_list = []
        for t in techniques.values():
            if not (set(t["evidence_ids"]) & suspicious_ids):
                continue
            strong_hint = "strong" in t.pop("_hints", [])
            queries = t.pop("_queries", [])
            t["confidence"] = 0.8 if strong_hint else 0.65
            t["justification"] = (f"Comportement observé ({queries[0].split(':')[0] if queries else ''}) "
                                  f"correspondant au fragment {t['fragment_ids'][0]} de la base ATT&CK.")
            tech_list.append(t)
        if verdict == "false_positive":
            tech_list = []
            for e in timeline:
                e["techniques"] = []

        # Déductions.
        for net in network_evs:
            f = (net.get("excerpt") or {}).get("fields", {})
            dst = str(f.get("destination_ip") or "").lower()
            if dst in mal_values:
                ioc_ev = next(i["evidence_ids"] for i in malicious_iocs if i["value"].lower() == dst)
                timeline.append({"timestamp": net.get("observed_at"), "host": net.get("host"),
                                 "description": f"Communication probable avec une infrastructure malveillante ({dst}) : "
                                                f"canal de commande et contrôle ou de téléchargement",
                                 "kind": "inferred", "confidence": 0.7,
                                 "evidence_ids": [net["evidence_id"]] + ioc_ev[:2], "techniques": []})
        rules = {classify_event(g[0])["rule"] for g in groups.values() if classify_event(g[0])}
        if verdict == "true_positive" and not rules & {"run_key", "run_key_value", "scheduled_task", "task_created"}:
            last = max((e["timestamp"] or "" for e in timeline), default=alert.get("timestamp"))
            timeline.append({"timestamp": last, "host": host, "description": "Aucune persistance observée dans la "
                             "fenêtre analysée : mécanismes hors fenêtre ou non journalisés à vérifier",
                             "kind": "hypothesis", "confidence": 0.3, "evidence_ids": [], "techniques": []})
        timeline.sort(key=lambda e: e["timestamp"] or "")

        users = sorted({str(((g[0].get("excerpt") or {}).get("fields") or {}).get("user"))
                        for g in groups.values() if ((g[0].get("excerpt") or {}).get("fields") or {}).get("user")
                        and classify_event(g[0])})
        hosts = sorted({g[0].get("host") for g in groups.values() if g[0].get("host") and classify_event(g[0])})

        severity = ctx.get("severity", "medium")
        if verdict == "true_positive":
            severity = "critical" if rules & {"lsass_dump", "lsass_access"} else "high"
        elif verdict == "false_positive":
            severity = "low"

        hyps = []
        for h in ctx.get("hypotheses", []):
            h = dict(h)
            if h["id"] == "H1":
                h["status"] = "supported" if verdict == "true_positive" else "refuted" if verdict == "false_positive" else "open"
            elif h["id"] == "H2":
                h["status"] = "supported" if verdict == "false_positive" else "refuted" if verdict == "true_positive" else "open"
            hyps.append(h)

        limitations = ["Rapport produit par le modèle de référence à règles (sans LLM)."]
        for fail in ctx.get("failures", []):
            limitations.append(f"Appel {fail['tool']} non abouti ({fail['status']}) : {fail['reason']}")
        if injected:
            limitations.append(f"Tentative d'injection détectée dans les données ({', '.join(injected[:5])}) : "
                               "contenu ignoré en tant qu'instruction.")
        if ctx.get("backend") == "simulation":
            limitations.append("Investigation menée sur le backend de simulation (scénario rejoué).")

        recs = _recommendations(verdict, tech_list, malicious_iocs, host, alert)
        sigma = _sigma_rules(groups) if verdict == "true_positive" else []
        desc = (alert.get("rule") or {}).get("description") or alert.get("summary", "")
        verdict_fr = {"true_positive": "vrai positif", "false_positive": "faux positif",
                      "needs_investigation": "à approfondir"}[verdict]
        summary = (f"L'alerte « {desc} » sur {host} est qualifiée de {verdict_fr} (confiance {confidence:.2f}). "
                   f"{len(suspicious)} comportement(s) suspect(s) et {len(legit)} activité(s) d'administration "
                   f"légitime(s) ont été identifiés. ")
        if tech_list:
            summary += "Techniques ATT&CK : " + ", ".join(f"{t['technique_id']} {t['name']}" for t in tech_list) + ". "
        if malicious_iocs:
            summary += "IOC malveillants confirmés : " + ", ".join(i["value"] for i in malicious_iocs) + ". "
        if injected:
            summary += "Des instructions malveillantes insérées dans les journaux ont été détectées et ignorées."
        return {
            "verdict": verdict, "severity": severity, "confidence": round(confidence, 2), "summary": summary.strip(),
            "timeline": timeline, "techniques": tech_list, "iocs": list(iocs.values()),
            "impacted_scope": {"hosts": hosts or ([host] if host and verdict == "true_positive" else []),
                               "users": users if verdict == "true_positive" else []},
            "hypotheses": hyps, "recommendations": recs, "detection_rules": sigma, "limitations": limitations,
        }

    def _task_repair(self, ctx: dict[str, Any]) -> dict[str, Any]:
        return ctx.get("report", {})


def _ioc_hits(ev: dict[str, Any], malicious: set[str]) -> list[str]:
    f = (ev.get("excerpt") or {}).get("fields") or {}
    values = [f.get("sha256"), f.get("destination_ip"), f.get("destination_hostname"), f.get("query_name")]
    return sorted({str(v) for v in values if v and str(v).lower() in malicious})


def _recommendations(verdict: str, techniques: list[dict[str, Any]], mal_iocs: list[dict[str, Any]], host: str | None,
                     alert: dict[str, Any]) -> list[str]:
    tactics = {tac for t in techniques for tac in t.get("tactics", [])}
    ids = {t["technique_id"] for t in techniques}
    if verdict == "false_positive":
        rule = (alert.get("rule") or {}).get("id", "?")
        return [f"Documenter l'activité légitime et ajouter une exception ciblée à la règle Wazuh {rule} "
                "(processus parent de l'outil d'administration, chemin du script signé).",
                "Conserver l'alerte pour les autres processus parents."]
    if verdict == "needs_investigation":
        return ["Étendre la fenêtre de recherche et collecter des journaux supplémentaires (PowerShell 4104, proxy).",
                "Faire valider la qualification par un analyste de niveau 2."]
    recs = [f"Isoler l'hôte {host} du réseau (action manuelle de l'analyste : hors du périmètre de l'agent)."]
    if "credential-access" in tactics:
        recs.append("Réinitialiser les mots de passe des comptes ayant ouvert une session sur l'hôte et rechercher "
                    "des authentifications latérales avec ces comptes.")
    if "persistence" in tactics:
        recs.append("Supprimer le mécanisme de persistance identifié (clé Run, tâche planifiée) et vérifier les autres.")
    if mal_iocs:
        recs.append("Bloquer sur le proxy et le pare-feu : " + ", ".join(i["value"] for i in mal_iocs) +
                    " ; rechercher ces IOC sur l'ensemble du parc.")
    if "T1059.001" in ids or "T1027.010" in ids:
        recs.append("Activer la journalisation des blocs de script PowerShell (événement 4104) et restreindre PowerShell "
                    "(Constrained Language Mode, AppLocker).")
    if "discovery" in tactics:
        recs.append("Surveiller les commandes de découverte enchaînées depuis un même processus parent.")
    return recs


SIGMA_TEMPLATES = {
    "powershell_encoded": ("PowerShell lancé avec une commande encodée", "\\powershell.exe", [" -enc ", " -encodedcommand "]),
    "certutil_download": ("Téléchargement via certutil", "\\certutil.exe", ["urlcache", "http"]),
    "lsass_dump": ("Dump de LSASS via comsvcs.dll", "\\rundll32.exe", ["comsvcs", "minidump"]),
    "run_key": ("Ajout d'une clé Run par reg.exe", "\\reg.exe", ["\\CurrentVersion\\Run"]),
    "scheduled_task": ("Création de tâche planifiée", "\\schtasks.exe", ["/create"]),
    "download_cradle": ("Téléchargement par PowerShell", "\\powershell.exe", ["DownloadString", "Invoke-WebRequest"]),
}


def _sigma_rules(groups: dict[str, list[dict[str, Any]]]) -> list[str]:
    rules, seen = [], set()
    for evs in groups.values():
        hint = classify_event(evs[0])
        if not hint or hint["legit"] or hint["rule"] not in SIGMA_TEMPLATES or hint["rule"] in seen:
            continue
        seen.add(hint["rule"])
        title, image, needles = SIGMA_TEMPLATES[hint["rule"]]
        contains = "\n".join(f"      - '{n}'" for n in needles)
        rules.append(
            f"title: {title} (proposée par l'agent, non déployée)\nstatus: experimental\n"
            f"logsource:\n  product: windows\n  category: process_creation\n"
            f"detection:\n  selection:\n    Image|endswith: '{image}'\n    CommandLine|contains|all:\n{contains}\n"
            f"  condition: selection\nlevel: high"
        )
        if len(rules) >= 3:
            break
    return rules
