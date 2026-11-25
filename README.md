# Agent IA pour l'investigation d'incidents cyber

Prototype réalisé dans le cadre du projet de 5ᵉ année « Cybersécurité et Intelligence
Artificielle » (ENSA Béni Mellal), conformément au cahier des charges v2.0.

> Une alerte arrive du SIEM ; l'agent IA **planifie** l'enquête, **interroge** les journaux,
> la Threat Intelligence, la base d'IOC et MITRE ATT&CK, puis **construit une chronologie**
> dont chaque fait cite sa preuve. Toutes ses actions passent par une **passerelle** qui
> contrôle les permissions et **journalise** chaque décision.

## Principes

| Principe | Mise en œuvre |
|---|---|
| **Autonomie bornée** | Niveaux N0 à N2 (N3 décrit, non implémenté). Lecture seule. Le niveau maximal est fixé par la politique SOC : l'analyste peut l'abaisser, jamais le relever. |
| **Permissions contrôlées** | La passerelle (`gateway/`) valide chaque appel (schéma strict), applique la politique déclarative `config/policy.yaml` (classe de risque, budgets, liste blanche, observables internes), sollicite l'analyste si nécessaire. **Le LLM ne décide jamais.** |
| **Traçabilité intégrale** | Journal d'audit en ajout seul, chaîné par SHA-256 et protégé par des déclencheurs SQL. Chaque preuve (EV-xxx) est rattachée à l'entrée d'audit de l'appel qui l'a produite, et chaque affirmation du rapport à ses preuves. |

## Architecture

```
            alerte Wazuh (JSON) / saisie manuelle
                         │
                         ▼
  ┌──────────────── Agent (LangGraph) ─────────────────┐       ┌──────────────┐
  │ qualifier → planifier → agir → observer → réviser   │◄─────►│ LLM          │
  │                     └──────► conclure → valider     │       │ offline/Groq/│
  └───────────┬─────────────────────────┬──────────────┘       │ Ollama       │
              │ demandes d'appels        │ preuves              └──────────────┘
              ▼                          ▼
  ┌──────── Passerelle ────────┐   ┌── Mémoire de preuves ──┐
  │ schéma · politique · budget │   │ EV-xxx ↔ entrée d'audit │──► chronologie + rapport
  │ validation humaine (EF-19)  │   └────────────────────────┘
  │ détection d'injection       │──► journal d'audit chaîné (SHA-256, ajout seul)
  └──┬────────┬────────┬────────┬┘
     ▼        ▼        ▼        ▼
  Wazuh     MISP   VirusTotal  ATT&CK
 (Sysmon)         AbuseIPDB   (RAG hybride)
```

Détails : [docs/architecture.md](docs/architecture.md) ·
gouvernance : [docs/gouvernance.md](docs/gouvernance.md) ·
modèle de preuves : [docs/modele_preuves.md](docs/modele_preuves.md) ·
laboratoire : [docs/laboratoire.md](docs/laboratoire.md) ·
évaluation : [docs/evaluation.md](docs/evaluation.md) ·
écarts avec le cahier des charges : [docs/ecarts.md](docs/ecarts.md)

## Démarrage rapide

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env                       # LLM_PROVIDER=offline par défaut : aucune clé requise

pytest                                     # 125 tests (1 test PostgreSQL ignoré sans base)
python -m agent.runner --scenario S1 --approve auto   # une investigation complète
python -m evaluation.run_eval              # évaluation sur les 5 scénarios
python -m gateway.audit verify             # intégrité du journal d'audit
```

Service et interface :

```bash
python -m scripts.create_token jdupont     # jeton d'accès de l'analyste (affiché une fois)
uvicorn app.api:app --port 8000            # API (documentation : http://localhost:8000/docs)
streamlit run app/ui.py                    # interface : http://localhost:8501
```

Avec Docker (ENF-08) :

```bash
docker compose up -d --build                         # API + interface
docker compose --profile postgres --profile ollama up -d   # + PostgreSQL et LLM local
docker compose --profile misp up -d                  # + MISP
docker compose exec api python -m scripts.create_token jdupont
```

### Choisir le modèle de langage (ENF-07)

| `LLM_PROVIDER` | Usage | Confidentialité |
|---|---|---|
| `offline` (défaut) | Modèle de référence à règles : tests, évaluation de référence, démonstration sans clé | Local |
| `ollama` | LLM local (`OLLAMA_MODEL`, par ex. `qwen2.5:7b-instruct`) | Aucune donnée ne sort du laboratoire |
| `groq` | API (`GROQ_API_KEY`, `GROQ_MODEL`) | Comptes, hôtes, e-mails et IP internes pseudonymisés avant envoi (GP-08) |

### Choisir les sources

`BACKEND=simulation` rejoue les scénarios de `lab/scenarios/` (documents au format Wazuh,
réponses brutes MISP / VirusTotal / AbuseIPDB). `BACKEND=live` interroge le laboratoire
réel (indexeur Wazuh, MISP, API de TI) avec les paramètres du `.env`.

## Organisation du dépôt

```
config/        politique de permissions (policy.yaml), identités (analysts.yaml), configuration
agent/         graphe LangGraph, prompts, modèles du rapport, validateur, clients LLM
gateway/       passerelle, politique, schémas d'outils, audit chaîné, injection, pseudonymisation
connectors/    Wazuh (indexeur + normalisation Sysmon), MISP, VirusTotal/AbuseIPDB, simulation
rag/           base ATT&CK embarquée (STIX v18, 706 techniques), découpage, embeddings, recherche hybride
evidence/      base de données (SQLite/PostgreSQL), mémoire de preuves, rapport Markdown et graphique
lab/           scénarios S1–S5, règles et intégration Wazuh, configuration Sysmon, scripts Atomic Red Team
evaluation/    indicateurs du chapitre 14 et campagne d'évaluation
app/           API FastAPI, interface Streamlit, authentification, exécution en arrière-plan
scripts/       jetons d'accès, alimentation de MISP
tests/         tests unitaires et de bout en bout
notebooks/     démonstration
```

## Résultats (modèle de référence à règles, backend de simulation, niveau N2)

| Indicateur | Résultat | Exigence |
|---|---|---|
| Exactitude du verdict | 5/5 (dont le faux positif S4) | — |
| Précision / rappel ATT&CK | 0,79 / 0,90 | — |
| Complétude / ordre de la chronologie | 1,00 / 1,00 | — |
| Affirmations non étayées | 0 % | ENF-01 : < 5 % |
| Durée moyenne d'une investigation | < 1 s (simulation) | ENF-02 : < 10 min |
| Actions hors permission exécutées | 0, y compris sous injection (S5) | Critère de recette |
| Intégrité du journal d'audit | vérifiée | Critère de recette |

Ces chiffres valent pour le modèle de référence sur des scénarios simulés. L'évaluation
avec un LLM (`LLM_PROVIDER=groq` ou `ollama`) et sur le laboratoire réel reste à mener :
voir [docs/evaluation.md](docs/evaluation.md).

## Couverture des exigences

| Exigences | Où | Vérifié par |
|---|---|---|
| EF-01 à EF-03 : ingestion, extraction, qualification | `agent/entities.py`, nœud `qualify` | `test_agent_e2e.py` (alerte manuelle, alerte invalide) |
| EF-04 à EF-06 : plan, replanification justifiée, arrêt | `agent/graph.py` | `test_plan_is_visible…`, `test_budget_exhaustion…`, `test_n0…blocking` |
| EF-07 à EF-11 : Wazuh, TI, MISP, ATT&CK, pivot | `connectors/`, `rag/` | `test_connectors.py`, `test_rag.py` |
| EF-12 : règles Sigma proposées (non déployées) | `agent/llm/offline.py` | rapport S1 à S3, S5 |
| EF-13 à EF-15 : chronologie sourcée, fait / inférence, rapport | `agent/validator.py`, `evidence/report.py` | `test_validator.py`, `test_hallucinating_llm_is_corrected` |
| EF-16 à EF-18 : interface, export, suivi temps réel | `app/ui.py`, `app/api.py` | `test_api.py` |
| EF-19, EF-20 : validation humaine, correction | `gateway/approval.py`, directives | `test_approval_flow_at_n0`, `test_analyst_directive…` |
| GP-01 à GP-08 : moindre privilège, politique, identité, schémas, budgets, secrets, injection, confidentialité | `gateway/` | `test_gateway.py`, `test_policy.py`, `test_injection.py`, `test_privacy.py` |
| GT-01 à GT-05 : journalisation, chaînage, preuve ↔ audit, approbations, versions | `gateway/audit.py`, `evidence/store.py`, `gateway/run_metadata.py` | `test_audit_chain.py`, `test_scenario_verdict_and_traceability` |
| ENF-01 à ENF-08 | voir [docs/evaluation.md](docs/evaluation.md) | `evaluation/run_eval.py` |

## Licence des données

La base `rag/data/attack_kb.json.gz` est dérivée de MITRE ATT&CK®
(© The MITRE Corporation, reproduite selon ses conditions d'utilisation).
