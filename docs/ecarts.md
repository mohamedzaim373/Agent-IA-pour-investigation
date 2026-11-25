# Écarts avec le cahier des charges v2.0

| Point du cahier | Réalisation | Justification |
|---|---|---|
| PostgreSQL « indispensable » (10.2) | SQLite par défaut, PostgreSQL par `DB_URL` (profil Docker `postgres`) | Même schéma (SQLAlchemy) ; SQLite simplifie le développement et les tests. Le fonctionnement sur PostgreSQL, déclencheurs d'ajout seul compris, est vérifié par `tests/test_postgres.py` |
| ChromaDB « indispensable » (10.2) | Index en mémoire par défaut ; ChromaDB en option (`VECTOR_STORE=chroma`) | ~2 700 fragments : un index en mémoire suffit et évite un service. La recherche est hybride (BM25 + dense + RRF + reranking), plus robuste qu'une recherche dense seule sur des lignes de commande |
| Modèle d'embeddings | TF-IDF + LSA par défaut ; sentence-transformers en option (`EMBEDDER=sbert`) | Aucun téléchargement de modèle, déterministe. Rappel@5 ≥ 0,85 sur le jeu de requêtes de `tests/test_rag.py` |
| « Ollama ou API d'un LLM » | Ollama et Groq (API compatible OpenAI) + modèle de référence à règles | Le modèle à règles sert de référence d'évaluation et permet de tout tester sans clé |
| TI : VirusTotal, AbuseIPDB, OTX | VirusTotal et AbuseIPDB | EF-08 exige au moins deux sources ; OTX s'ajoute comme un connecteur supplémentaire (ENF-06) |
| Laboratoire : 3 à 5 scénarios réels | 5 scénarios simulés au format Wazuh ; scripts de rejeu fournis | Le laboratoire virtualisé n'était pas disponible dans l'environnement de développement. Le jalon J3 (« une alerte réelle du lab ») reste à démontrer avec `BACKEND=live` |
| Export PDF ou Markdown (EF-17) | Markdown et JSON ; graphique PNG | Markdown satisfait EF-17 ; le PDF s'obtient par conversion (pandoc) |
| Configuration réduite à 16 Go (11.2) | Répartition corrigée dans `docs/laboratoire.md` | La somme annoncée (2 + 4 + 6 + 8 Go) dépasse 16 Go |
| Tactiques ATT&CK | Base v18 (novembre 2026) : *Defense Evasion* est scindée en *Stealth* et *Defense Impairment* | Les anciens noms sont acceptés comme alias dans le filtre par tactique |
| Rattachement ATT&CK via la passerelle | `attack_search` est un outil de la passerelle | Le schéma du chapitre 13 montre un accès direct de l'agent aux connaissances ; le passage par la passerelle garantit la journalisation (GT-01) |

## Limites connues

- Le modèle de référence à règles reconnaît un ensemble fini de comportements (commandes et
  événements listés dans `agent/llm/offline.py`) ; il ne remplace pas un LLM sur des
  attaques non couvertes.
- La détection d'injection repose sur des motifs : elle signale, mais la protection réelle
  vient du contrôle hors LLM (passerelle) et du balisage.
- Les validations automatiques de l'évaluation (`AutoApprover`) sont tracées comme telles ;
  en usage réel, l'analyste tranche dans l'interface.
- Le niveau N3 est décrit (outil déclaré, désactivé) mais non implémenté, conformément au
  périmètre.
