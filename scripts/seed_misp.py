"""Crée dans MISP les IOC des scénarios (jalon J1 : « MISP répond »).

    python -m scripts.seed_misp                 # tous les scénarios
    python -m scripts.seed_misp --scenarios S1  # un seul

Utilise MISP_URL et MISP_KEY (.env). Un événement MISP est créé par scénario,
avec les attributs (IP, empreintes) attendus par la vérité terrain.
"""

from __future__ import annotations

import argparse
import sys

import requests

from config.settings import load_settings
from connectors.base import http_json
from connectors.simulation import list_scenarios, load_scenario


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Alimenter MISP avec les IOC des scénarios")
    parser.add_argument("--scenarios", nargs="*", default=None)
    args = parser.parse_args(argv)
    s = load_settings()
    if not s.misp_key:
        print("MISP_KEY n'est pas défini (.env)")
        return 1
    session = requests.Session()
    session.verify = s.misp_verify_tls
    session.headers.update({"Authorization": s.misp_key, "Accept": "application/json",
                            "Content-Type": "application/json"})
    for sid in args.scenarios or list_scenarios():
        scenario = load_scenario(sid)
        attrs = [a for values in (scenario.get("misp") or {}).values() for a in values]
        if not attrs:
            print(f"{sid} : aucun IOC à créer")
            continue
        first = attrs[0]["Event"]
        event = {"Event": {
            "info": f"[{sid}] {first['info']}", "threat_level_id": first["threat_level_id"], "analysis": "2",
            "distribution": "0", "Tag": first.get("Tag", []),
            "Attribute": [{"type": a["type"], "category": a["category"], "value": a["value"], "to_ids": a["to_ids"]}
                          for a in attrs],
        }}
        res = http_json(session, "POST", f"{s.misp_url.rstrip('/')}/events/add", json=event, timeout=30)
        print(f"{sid} : événement {res.get('Event', {}).get('id', '?')} créé avec {len(attrs)} attribut(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
