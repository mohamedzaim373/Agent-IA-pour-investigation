"""Restitution : rapport Markdown, export JSON, graphique de chronologie (EF-15 à EF-17).

Chaque affirmation du rapport renvoie à ses preuves (EV-xxx), et chaque preuve à
l'entrée du journal d'audit qui a journalisé l'appel correspondant (GT-03).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agent.report_models import VERDICT_FR

KIND_FR = {"observed": "Observé", "inferred": "Déduit", "hypothesis": "Hypothèse"}
SEVERITY_FR = {"low": "Faible", "medium": "Moyenne", "high": "Élevée", "critical": "Critique"}


def _md_escape(text: Any) -> str:
    return str(text if text is not None else "").replace("|", "\\|").replace("\n", " ")


def render_markdown(report: dict[str, Any], *, evidence: list[Any], investigation: dict[str, Any],
                    validation: dict[str, Any], audit: dict[str, Any], usage: dict[str, Any] | None = None,
                    plan: dict[str, Any] | None = None, replan_log: list[dict[str, Any]] | None = None) -> str:
    ev_by_id = {e.evidence_id: e for e in evidence}
    meta = investigation.get("metadata", {})
    lines: list[str] = []
    w = lines.append

    w(f"# Rapport d'investigation {report.get('investigation_id', '')}")
    w("")
    w(f"**Alerte** : {_md_escape(report.get('alert_summary'))}  ")
    w(f"**Verdict** : {VERDICT_FR.get(report.get('verdict'), report.get('verdict'))} "
      f"(confiance {float(report.get('confidence', 0)):.2f})  ")
    w(f"**Gravité** : {SEVERITY_FR.get(report.get('severity'), report.get('severity'))}  ")
    w(f"**Analyste** : {investigation.get('analyst_id')} · **Niveau d'autonomie** : {investigation.get('autonomy_level')}  ")
    w(f"**Début** : {investigation.get('created_at')} · **Fin** : {investigation.get('finished_at') or '-'}  ")
    w(f"**Raison de l'arrêt** : {_md_escape(report.get('stop_reason'))}")
    w("")
    w("## Résumé")
    w("")
    w(report.get("summary") or "-")
    w("")

    w("## Chronologie")
    w("")
    w("| Horodatage (UTC) | Hôte | Événement | Nature | Confiance | Preuves | ATT&CK |")
    w("|---|---|---|---|---|---|---|")
    for e in report.get("timeline", []):
        ev_links = ", ".join(e.get("evidence_ids", [])) or "—"
        w(f"| {_md_escape(e.get('timestamp'))} | {_md_escape(e.get('host'))} | {_md_escape(e.get('description'))[:400]} "
          f"| {KIND_FR.get(e.get('kind'), e.get('kind'))} | {float(e.get('confidence', 0)):.2f} | {ev_links} "
          f"| {', '.join(e.get('techniques', [])) or '—'} |")
    w("")

    w("## Techniques MITRE ATT&CK")
    w("")
    if report.get("techniques"):
        w("| Technique | Tactiques | Confiance | Justification | Preuves | Fragments |")
        w("|---|---|---|---|---|---|")
        for t in report["techniques"]:
            w(f"| {t['technique_id']} {_md_escape(t.get('name'))} | {', '.join(t.get('tactics', []))} "
              f"| {float(t.get('confidence', 0)):.2f} | {_md_escape(t.get('justification'))} "
              f"| {', '.join(t.get('evidence_ids', []))} | {', '.join(t.get('fragment_ids', []))} |")
    else:
        w("Aucune technique rattachée.")
    w("")

    w("## Indicateurs de compromission")
    w("")
    if report.get("iocs"):
        w("| Type | Valeur | Verdict | Sources | Preuves |")
        w("|---|---|---|---|---|")
        for c in report["iocs"]:
            w(f"| {c.get('type')} | `{_md_escape(c.get('value'))}` | {c.get('verdict')} | {', '.join(c.get('sources', []))} "
              f"| {', '.join(c.get('evidence_ids', [])) or '—'} |")
    else:
        w("Aucun IOC vérifié.")
    w("")

    scope = report.get("impacted_scope") or {}
    w("## Périmètre impacté")
    w("")
    w(f"- Hôtes : {', '.join(scope.get('hosts', [])) or '—'}")
    w(f"- Comptes : {', '.join(scope.get('users', [])) or '—'}")
    w("")

    if report.get("hypotheses"):
        w("## Hypothèses")
        w("")
        for h in report["hypotheses"]:
            w(f"- **{h['id']}** ({h.get('status')}, confiance {float(h.get('confidence', 0)):.2f}) : "
              f"{_md_escape(h.get('statement'))}")
        w("")

    w("## Recommandations")
    w("")
    for r in report.get("recommendations", []) or ["—"]:
        w(f"- {r}")
    w("")

    if report.get("detection_rules"):
        w("## Règles de détection proposées (non déployées)")
        w("")
        for rule in report["detection_rules"]:
            w("```yaml")
            w(rule)
            w("```")
        w("")

    w("## Limites")
    w("")
    for lim in report.get("limitations", []) or ["—"]:
        w(f"- {lim}")
    w("")

    if plan:
        w("## Plan d'investigation exécuté")
        w("")
        w("| Étape | Outil | Objectif | Statut | Résultat | Audit |")
        w("|---|---|---|---|---|---|")
        for s in plan.get("steps", []):
            w(f"| {s['id']} | {s['tool']} | {_md_escape(s.get('objective'))} | {s.get('status')} "
              f"| {_md_escape(s.get('result'))[:120]} | {s.get('audit_seq') or '—'} |")
        w("")
    if replan_log:
        w("### Révisions du plan")
        w("")
        for entry in replan_log:
            w(f"- v{entry['version']} ({entry['mode']}) : {_md_escape(entry.get('rationale'))}")
            for ch in entry.get("changes", [])[:10]:
                w(f"  - {_md_escape(ch.get('change'))} — {_md_escape(ch.get('justification'))}")
        w("")

    w("## Traçabilité")
    w("")
    final = validation.get("final", {})
    w(f"- Ancrage des affirmations : {final.get('claims_grounded', 0)}/{final.get('claims_total', 0)} "
      f"({float(final.get('grounding_ratio', 0)):.0%})")
    if validation.get("corrections"):
        w(f"- Corrections automatiques : {len(validation['corrections'])}")
    w(f"- Journal d'audit : {'intègre' if audit.get('ok') else 'ALTÉRÉ'} — {audit.get('entries', 0)} entrées pour "
      f"cette investigation, tête de chaîne `{audit.get('head_hash', '')[:16]}…`")
    llm = meta.get("llm", {})
    w(f"- Modèle : {llm.get('provider')} / {llm.get('model')} · Prompts v{meta.get('prompts', {}).get('version')} "
      f"(`{meta.get('prompts', {}).get('sha256', '')[:12]}`) · Politique v{meta.get('policy', {}).get('version')} "
      f"(`{meta.get('policy', {}).get('sha256', '')[:12]}`) · Backend : {meta.get('backend')}")
    if meta.get("attack_kb"):
        w(f"- Base ATT&CK : {meta['attack_kb'].get('version')} ({meta['attack_kb'].get('embedder')})")
    if usage:
        w(f"- Consommation : {usage.get('total_calls', 0)} appels d'outils, {usage.get('tokens', 0)} jetons, "
          f"{usage.get('denied', 0)} refus, {usage.get('approvals_requested', 0)} validation(s) demandée(s), "
          f"{usage.get('elapsed_s', 0)} s")
    w("")

    cited = sorted({i for e in report.get("timeline", []) for i in e.get("evidence_ids", [])} |
                   {i for t in report.get("techniques", []) for i in t.get("evidence_ids", [])} |
                   {i for c in report.get("iocs", []) for i in c.get("evidence_ids", [])})
    w("## Annexe : preuves citées")
    w("")
    w("| Preuve | Horodatage | Source | Requête | Extrait | Empreinte | Audit |")
    w("|---|---|---|---|---|---|---|")
    for ev_id in cited:
        ev = ev_by_id.get(ev_id)
        if ev is None:
            continue
        query = json.dumps(ev.query, ensure_ascii=False)[:120]
        flag = " ⚠ injection" if "injection_suspected" in ev.flags else ""
        w(f"| {ev.evidence_id} | {ev.observed_at or '—'} | {ev.source} ({ev.tool}) | `{_md_escape(query)}` "
          f"| {_md_escape(ev.summary)[:220]}{flag} | `{ev.item_hash[:12]}` | #{ev.audit_seq} |")
    w("")
    return "\n".join(lines)


def render_timeline_chart(report: dict[str, Any], path: Path) -> Path | None:
    """Graphique de la chronologie (hôte en ordonnée, couleur selon la nature)."""
    try:  # API objet de matplotlib : aucun état global (sûr dans les threads de l'API et dans un notebook)
        import matplotlib.dates as mdates
        from matplotlib.backends.backend_agg import FigureCanvasAgg
        from matplotlib.figure import Figure
    except ImportError:  # pragma: no cover
        return None
    from connectors.base import parse_iso

    entries = [(parse_iso(e.get("timestamp")), e) for e in report.get("timeline", [])]
    entries = [(t, e) for t, e in entries if t is not None]
    if not entries:
        return None
    hosts = sorted({e.get("host") or "?" for _, e in entries})
    colors = {"observed": "#1f6feb", "inferred": "#d29922", "hypothesis": "#8b949e"}
    fig = Figure(figsize=(11, 1.2 + 0.6 * len(hosts) + 0.15 * len(entries)))
    FigureCanvasAgg(fig)
    ax = fig.add_subplot()
    for kind, color in colors.items():
        pts = [(t, hosts.index(e.get("host") or "?")) for t, e in entries if e.get("kind") == kind]
        if pts:
            ax.scatter([p[0] for p in pts], [p[1] for p in pts], color=color, s=60, label=KIND_FR[kind], zorder=3)
    for t, e in entries:
        label = (", ".join(e.get("techniques", [])) or e.get("description", "")[:28])
        ax.annotate(label, (t, hosts.index(e.get("host") or "?")), textcoords="offset points", xytext=(4, 6),
                    fontsize=7, rotation=20)
    ax.set_yticks(range(len(hosts)))
    ax.set_yticklabels(hosts)
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M:%S"))
    ax.grid(True, axis="x", alpha=0.3)
    ax.set_title(f"Chronologie — {report.get('investigation_id', '')}")
    ax.legend(loc="upper left", fontsize=8)
    fig.autofmt_xdate()
    fig.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=120)
    return path


def export_files(run_dir: Path, *, report: dict[str, Any], markdown: str) -> dict[str, str]:
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "report.md").write_text(markdown, encoding="utf-8")
    (run_dir / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    files = {"markdown": str(run_dir / "report.md"), "json": str(run_dir / "report.json")}
    chart = render_timeline_chart(report, run_dir / "timeline.png")
    if chart:
        files["timeline_png"] = str(chart)
    return files
