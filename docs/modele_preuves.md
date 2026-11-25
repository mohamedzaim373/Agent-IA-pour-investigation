# Modèle de preuves et journal d'audit (livrable L2)

## Chaîne de justification

```
affirmation du rapport ──► preuve EV-xxx ──► entrée d'audit #n ──► chaîne SHA-256 vérifiable
 (chronologie, technique,    (extrait, source,    (outil, paramètres,
  IOC)                        requête, empreinte)   empreinte du résultat)
```

1. La passerelle exécute un appel et journalise l'**empreinte du résultat complet**.
2. La mémoire de preuves n'accepte un résultat que si son empreinte correspond à celle de
   l'entrée d'audit indiquée (même investigation, même outil) : une preuve ne peut pas être
   fabriquée par l'agent (`EvidenceIntegrityError`).
3. Chaque élément du résultat devient une preuve `EV-001`, `EV-002`… avec son horodatage
   d'origine, sa source, la requête, un extrait normalisé, son empreinte et le numéro de
   l'entrée d'audit.
4. Le validateur vérifie que chaque affirmation du rapport cite des preuves existantes, que
   l'horodatage d'un fait observé correspond à ses preuves (tolérance 5 min), et que chaque
   technique ATT&CK provient d'un résultat de `attack_search` avec un fragment valide.

## Tables

| Table | Contenu |
|---|---|
| `investigations` | identifiant, analyste, niveau, alerte normalisée, versions (modèle, prompts, politique, connecteurs, base ATT&CK), statut, verdict, raison de l'arrêt |
| `audit_log` | `seq`, `ts`, investigation, acteur, type, outil, paramètres, empreinte du résultat, décision, motif, durée, détails, `prev_hash`, `entry_hash` |
| `evidence` | `evidence_id`, `audit_seq`, source, outil, requête, `observed_at`, hôte, type d'événement, résumé, extrait, empreinte, référence de l'événement d'origine, marqueurs (`injection_suspected`) |
| `reports` | rapport JSON, rendu Markdown, résultat de la validation |
| `approvals` | demandes de validation, décision, analyste, motif |
| `ti_cache` | réponses normalisées de la TI (durée de vie configurable) |

## Journal d'audit chaîné

`entry_hash = SHA-256(JSON canonique des champs de l'entrée, y compris prev_hash)`, la
première entrée ayant `prev_hash = 0…0`. `python -m gateway.audit verify` recalcule toute la
chaîne et détecte :

- une **modification** (empreinte recalculée différente) ;
- une **suppression** ou une insertion (rupture de numérotation et de lien) ;
- une modification suivie du recalcul de l'empreinte (le lien avec l'entrée suivante casse).

En complément, la base refuse `UPDATE` et `DELETE` sur `audit_log` (déclencheurs SQLite et
PostgreSQL). Pour un ancrage externe, la tête de chaîne (`head_hash`, affichée dans chaque
rapport) peut être exportée périodiquement vers un support en écriture unique.

## Rapport (EF-15)

| Champ | Contenu |
|---|---|
| `verdict`, `severity`, `confidence` | vrai positif / faux positif / à approfondir, gravité, confiance |
| `summary` | résumé |
| `timeline[]` | horodatage, hôte, description, nature (`observed`, `inferred`, `hypothesis`), confiance, preuves, techniques |
| `techniques[]` | identifiant, nom, tactiques, justification, confiance, preuves, fragments ATT&CK |
| `iocs[]` | type, valeur, verdict, sources, preuves |
| `impacted_scope` | hôtes, comptes |
| `hypotheses[]` | statut (`open`, `supported`, `refuted`) |
| `recommendations[]`, `detection_rules[]` | recommandations, règles Sigma proposées (non déployées) |
| `limitations[]`, `stop_reason` | limites (appels refusés ou en échec, injection, corrections), raison de l'arrêt |

Le rendu Markdown ajoute le plan exécuté, ses révisions, l'état du journal d'audit, les
versions utilisées et l'annexe des preuves citées. Un graphique de la chronologie
(`timeline.png`) est produit dans `investigation_lab/runs/<investigation>/`.
