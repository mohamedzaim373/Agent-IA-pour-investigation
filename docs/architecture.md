# Architecture (livrable L2)

## Séparation des responsabilités

L'architecture sépare strictement trois fonctions (cahier des charges, chapitre 6) :

| Fonction | Composant | Accès aux systèmes |
|---|---|---|
| Raisonnement | `agent/` (graphe LangGraph + LLM) | **aucun** |
| Exécution sous politique | `gateway/` (passerelle d'outils) | seul point d'entrée vers les connecteurs |
| Mémoire de preuves | `evidence/` | écrit uniquement des résultats déjà journalisés |

Règle structurante : **l'agent n'appelle jamais un connecteur directement**. Il formule une
demande (`outil`, `paramètres`, `justification`) que la passerelle accepte, soumet à
l'analyste ou refuse.

## Boucle d'investigation

```
qualifier ─► planifier ─► agir ─► observer ─┬─► agir             (étapes restantes)
                ▲                           ├─► planifier        (révision justifiée)
                └───────────────────────────┤
                                            └─► conclure ─► valider ─┬─► conclure (réparation)
                                                                     └─► fin
```

| Nœud | Rôle | Exigences |
|---|---|---|
| `qualify` | Extraction des observables (y compris décodage des commandes PowerShell `-EncodedCommand`), gravité, hypothèses vrai / faux positif | EF-01 à EF-03 |
| `plan` | Plan explicite (étapes, outil, objectif, hypothèses visées) ; en révision, chaque changement est justifié ; prise en compte des consignes de l'analyste | EF-04, EF-05, EF-20 |
| `act` | Contrôle des budgets, choix de la prochaine action (ou conclusion), appel via la passerelle | EF-06, GP-05 |
| `observe` | Enregistrement des preuves, nouveaux observables, IOC malveillants (pivot), échecs | EF-07 à EF-11 |
| `conclude` | Rapport structuré à partir des seules preuves ; modèle de secours si le LLM échoue | EF-13 à EF-15, ENF-04 |
| `validate` | Vérification des preuves, techniques et fragments ; réparation par le LLM puis correction déterministe | ENF-01, GT-03 |

Critères d'arrêt (EF-06) : conclusion du modèle ou plan épuisé ; budget d'étapes, de jetons,
d'appels ou de durée ; blocage (4 appels consécutifs refusés ou en échec). La raison est
inscrite dans le rapport (`stop_reason`).

## Exemple : PowerShell encodé (scénario S1)

1. Wazuh transmet l'alerte 100200 (`POST /alerts/wazuh` ou scénario simulé).
2. L'agent décode la commande, extrait `203.0.113.45` et l'URL de téléchargement, et planifie :
   journaux de l'hôte à ±1 h, arbre de processus, vérification des observables.
3. La passerelle autorise les lectures internes (niveau N1 ou N2) ; au niveau N1, les
   requêtes de TI externe attendent l'accord de l'analyste.
4. Les journaux révèlent une connexion au C2, un exécutable déposé dans `%TEMP%` et son
   empreinte ; l'agent révise son plan (nouveaux observables, rattachements ATT&CK).
5. MISP et VirusTotal confirment l'IP et l'empreinte ; le RAG rattache les comportements à
   T1059.001, T1027.010, T1105 et T1071.001, chacun avec le fragment qui le justifie.
6. Le rapport est validé : chaque événement de la chronologie cite ses preuves, chaque
   preuve renvoie à son entrée d'audit.

## Modules

| Module | Contenu |
|---|---|
| `agent/graph.py` | Graphe LangGraph, nœuds, routage, audit des appels au LLM |
| `agent/prompts.py` | Prompts versionnés (empreinte enregistrée, GT-05) |
| `agent/llm/` | Interface commune, Groq, Ollama, modèle à règles, pseudonymisation |
| `agent/entities.py` | Ingestion de l'alerte (Wazuh ou manuelle), extraction des observables |
| `agent/validator.py` | Validation et correction du rapport |
| `gateway/gateway.py` | Passerelle : validation, décision, approbation, exécution, injection, audit |
| `gateway/policy.py` | Moteur de politique, niveaux d'autonomie, identités |
| `gateway/tool_schemas.py` | Schémas Pydantic stricts des outils |
| `gateway/audit.py` | Journal chaîné, vérification (`python -m gateway.audit verify`) |
| `gateway/injection.py` | Balisage, détection et neutralisation |
| `gateway/privacy.py` | Pseudonymisation HMAC réversible localement |
| `connectors/` | Wazuh (OpenSearch), MISP, VirusTotal, AbuseIPDB (+ cache), simulation |
| `rag/` | Chargeur STIX, découpage en fragments `Txxxx#k`, BM25 + embeddings, RRF, reranking |
| `evidence/` | Schéma SQL, mémoire de preuves, rendu du rapport |
| `app/` | API FastAPI, interface Streamlit, jetons, exécution en arrière-plan |

## Déploiement (chapitre 11)

L'hôte Docker (192.168.56.40) exécute `docker compose` : API, interface, et en option
PostgreSQL, Ollama et MISP. Le serveur Wazuh (192.168.56.30) et les machines Windows et Kali
sont des machines virtuelles (VirtualBox ou VMware) ; voir [laboratoire.md](laboratoire.md).
