"""Interface de l'analyste (Streamlit) : lancement, suivi en temps réel,
validations, correction, rapport et audit (EF-16, EF-18 à EF-20).

    streamlit run app/ui.py          # API_URL=http://localhost:8000 par défaut
"""

from __future__ import annotations

import json
import os

import pandas as pd
import requests
import streamlit as st

API_URL = os.environ.get("API_URL", "http://localhost:8000").rstrip("/")
VERDICT_FR = {"true_positive": "🔴 Vrai positif", "false_positive": "🟢 Faux positif",
              "needs_investigation": "🟠 À approfondir"}
KIND_FR = {"observed": "Observé", "inferred": "Déduit", "hypothesis": "Hypothèse"}

st.set_page_config(page_title="Agent d'investigation", page_icon="🛡️", layout="wide")


def api(method: str, path: str, quiet: bool = False, **kwargs):
    """Appel à l'API ; `quiet` : pas de message d'erreur (ressource pas encore disponible)."""
    headers = {"Authorization": f"Bearer {st.session_state.get('token', '')}"}
    try:
        resp = requests.request(method, f"{API_URL}{path}", headers=headers, timeout=30, **kwargs)
    except requests.RequestException as exc:
        st.error(f"API injoignable ({API_URL}) : {exc}")
        return None
    if resp.status_code >= 400:
        if quiet:
            return None
        try:
            detail = resp.json().get("detail")
        except ValueError:
            detail = resp.text
        st.error(f"Erreur {resp.status_code} : {detail}")
        return None
    return resp.json() if "json" in resp.headers.get("content-type", "") else resp.text


# ----------------------------------------------------------------- connexion
with st.sidebar:
    st.title("🛡️ Agent d'investigation")
    token = st.text_input("Jeton d'accès", type="password", value=st.session_state.get("token", ""))
    if token:
        st.session_state["token"] = token
    me = api("GET", "/me") if st.session_state.get("token") else None
    if me:
        st.success(f"{me['name']} — rôle {me['role']}")
        st.caption(f"Autonomie maximale : {me['max_autonomy']} (politique SOC : {me['policy_max_level']})")
    health = api("GET", "/health")
    if health:
        st.caption(f"Backend {health['backend']} · LLM {health['llm']} · ATT&CK {health['attack_kb']}")

if not me:
    st.info("Saisissez votre jeton (python -m scripts.create_token <identifiant>).")
    st.stop()

tab_new, tab_follow, tab_approve, tab_report, tab_audit = st.tabs(
    ["Nouvelle investigation", "Suivi en temps réel", "Validations", "Rapport", "Audit"])

# ------------------------------------------------------------ lancement
with tab_new:
    st.subheader("Lancer une investigation")
    levels = [lvl for lvl in ["N0", "N1", "N2"] if lvl <= me["max_autonomy"]]
    level = st.radio("Niveau d'autonomie", levels, index=min(1, len(levels) - 1), horizontal=True,
                     help="N0 : chaque appel est approuvé · N1 : lectures internes libres · N2 : TI externe autorisée")
    source = st.radio("Alerte", ["Scénario simulé", "Alerte Wazuh (JSON)", "Saisie manuelle"], horizontal=True)
    payload: dict = {"autonomy_level": level}
    if source == "Scénario simulé":
        scenarios = api("GET", "/scenarios") or []
        choice = st.selectbox("Scénario", scenarios, format_func=lambda s: f"{s['id']} — {s['name']}")
        if choice:
            st.caption(choice["description"])
            payload["scenario_id"] = choice["id"]
    elif source == "Alerte Wazuh (JSON)":
        raw = st.text_area("Alerte Wazuh", height=220)
        if raw:
            try:
                payload["alert"] = json.loads(raw)
            except ValueError:
                st.error("JSON invalide")
    else:
        c1, c2 = st.columns(2)
        payload["alert"] = {
            "manual": True, "title": c1.text_input("Titre"), "host": c1.text_input("Hôte"),
            "user": c2.text_input("Compte"), "timestamp": c2.text_input("Horodatage (ISO 8601, UTC)"),
            "description": st.text_area("Description"),
        }
    if st.button("Lancer l'investigation", type="primary"):
        res = api("POST", "/investigations", json=payload)
        if res:
            st.session_state["current"] = res["investigation_id"]
            st.success(f"Investigation {res['investigation_id']} lancée au niveau {res['autonomy_level']}")
            for note in res.get("notes", []):
                st.warning(note)

# --------------------------------------------------------------- suivi
@st.fragment(run_every="2s")
def live_panel(sel: str) -> None:
    """Panneau rafraîchi toutes les deux secondes, sans recharger toute la page (EF-18)."""
    info = api("GET", f"/investigations/{sel}") or {}
    c1, c2, c3 = st.columns(3)
    c1.metric("Statut", info.get("live_status") or info.get("status"))
    c2.metric("Niveau", info.get("autonomy_level"))
    c3.metric("Verdict", VERDICT_FR.get(info.get("verdict"), "—"))
    if info.get("pending_approvals"):
        st.warning(f"{len(info['pending_approvals'])} validation(s) en attente : onglet « Validations ».")
    events = api("GET", f"/investigations/{sel}/events") or []
    plan = next((e for e in reversed(events) if e.get("type") == "plan"), None)
    if plan:
        st.markdown(f"**Plan v{plan['version']}** — {plan['rationale']}")
        st.dataframe(pd.DataFrame([{"étape": s["id"], "outil": s["tool"], "objectif": s["objective"],
                                    "statut": s["status"]} for s in plan["steps"]]), width="stretch")
    st.markdown("**Journal des étapes**")
    for e in events[-40:]:
        t = e.get("type")
        if t == "tool_call":
            st.write(f"➡️ `{e['tool']}` — {e.get('justification', '')}")
        elif t == "tool_result":
            st.write(f"✅ `{e['tool']}` : {e['items']} résultat(s) (audit #{e['audit_seq']})")
        elif t in {"tool_denied", "tool_rejected", "tool_error"}:
            st.write(f"⛔ `{e['tool']}` : {e.get('reason') or e.get('error')}")
        elif t == "approval_pending":
            st.write(f"⏳ validation demandée pour `{e['tool']}`")
        elif t == "injection_detected":
            st.write(f"⚠️ injection détectée dans le résultat de `{e['tool']}`")
        elif t in {"stop", "run_end", "run_error"}:
            st.write(f"🏁 {e.get('reason') or e.get('verdict') or e.get('error')}")


with tab_follow:
    invs = api("GET", "/investigations") or []
    ids = [i["id"] for i in invs]
    current = st.session_state.get("current")
    sel = st.selectbox("Investigation", ids, index=ids.index(current) if current in ids else 0) if ids else None
    if sel:
        st.session_state["current"] = sel
        live_panel(sel)
        with st.expander("Corriger l'agent (EF-20)"):
            dtype = st.selectbox("Type", ["invalidate_hypothesis", "impose_lead", "note"])
            text = st.text_input("Consigne")
            hyp = st.text_input("Hypothèse (ex. H2)") if dtype == "invalidate_hypothesis" else None
            if st.button("Envoyer la consigne") and text:
                if api("POST", f"/investigations/{sel}/directives",
                       json={"type": dtype, "text": text, "hypothesis_id": hyp}):
                    st.success("Consigne transmise : prise en compte à la prochaine révision du plan.")

# ---------------------------------------------------------- validations
with tab_approve:
    pending = api("GET", "/approvals") or []
    if not pending:
        st.info("Aucune validation en attente.")
    for p in pending:
        with st.container(border=True):
            st.markdown(f"**{p['tool']}** ({p.get('risk')}) — investigation {p['investigation_id']}")
            st.code(json.dumps(p["args"], ensure_ascii=False, indent=2), language="json")
            st.caption(f"Justification de l'agent : {p.get('justification')}")
            reason = st.text_input("Motif", key=f"reason-{p['id']}")
            c1, c2 = st.columns(2)
            if c1.button("Approuver", key=f"ok-{p['id']}", disabled=not me["can_approve"]):
                api("POST", f"/approvals/{p['id']}", json={"approve": True, "reason": reason or "approuvé"})
                st.rerun()
            if c2.button("Refuser", key=f"ko-{p['id']}", disabled=not me["can_approve"]):
                api("POST", f"/approvals/{p['id']}", json={"approve": False, "reason": reason})
                st.rerun()

# --------------------------------------------------------------- rapport
with tab_report:
    sel = st.session_state.get("current")
    data = api("GET", f"/investigations/{sel}/report", quiet=True) if sel else None
    if data:
        r = data["report"]
        c1, c2, c3 = st.columns(3)
        c1.metric("Verdict", VERDICT_FR.get(r["verdict"], r["verdict"]))
        c2.metric("Confiance", f"{r['confidence']:.2f}")
        c3.metric("Ancrage", f"{data['validation'].get('final', {}).get('grounding_ratio', 0):.0%}")
        st.write(r["summary"])
        if r["timeline"]:
            df = pd.DataFrame([{"horodatage": e["timestamp"], "hôte": e.get("host"), "événement": e["description"],
                                "nature": KIND_FR.get(e["kind"], e["kind"]), "confiance": e["confidence"],
                                "preuves": ", ".join(e["evidence_ids"]), "ATT&CK": ", ".join(e["techniques"])}
                               for e in r["timeline"]])
            df["horodatage"] = pd.to_datetime(df["horodatage"], utc=True, errors="coerce")
            st.scatter_chart(df, x="horodatage", y="hôte", color="nature", size="confiance")
            st.dataframe(df, width="stretch")
        if r["techniques"]:
            st.markdown("**Techniques ATT&CK**")
            st.dataframe(pd.DataFrame(r["techniques"]), width="stretch")
        if r["iocs"]:
            st.markdown("**IOC**")
            st.dataframe(pd.DataFrame(r["iocs"]), width="stretch")
        md = api("GET", f"/investigations/{sel}/report.md")
        if md:
            st.download_button("Exporter en Markdown", md, file_name=f"{sel}.md", mime="text/markdown")
            with st.expander("Rapport complet"):
                st.markdown(md)
    else:
        st.info("Rapport disponible à la fin de l'investigation.")

# ----------------------------------------------------------------- audit
with tab_audit:
    sel = st.session_state.get("current")
    if me["can_read_audit"] and st.button("Vérifier l'intégrité du journal"):
        res = api("GET", "/audit/verify")
        if res:
            (st.success if res["ok"] else st.error)(
                f"{'Intègre' if res['ok'] else 'ALTÉRÉ'} : {res['checked']} entrées, tête {res['head_hash'][:16]}…")
    if sel:
        entries = api("GET", f"/audit/{sel}") or []
        if entries:
            st.dataframe(pd.DataFrame([{k: e[k] for k in ("seq", "ts", "actor", "event_type", "tool", "decision",
                                                         "reason", "entry_hash")} for e in entries]),
                         width="stretch")
