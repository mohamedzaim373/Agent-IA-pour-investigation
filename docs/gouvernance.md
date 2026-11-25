# Gouvernance de l'agent (chapitre 8)

## Niveaux d'autonomie

| Niveau | Comportement | Statut |
|---|---|---|
| N0 Assistant | Chaque appel d'outil est soumis à l'analyste | Implémenté |
| N1 Lecture autonome | Lectures internes (Wazuh, MISP, ATT&CK) libres dans le budget ; TI externe soumise à approbation | Implémenté, **défaut** |
| N2 Enrichissement étendu | N1 + TI externe (VirusTotal, AbuseIPDB) sous liste blanche | Implémenté |
| N3 Réponse supervisée | Décrit (outil `isolate_host` déclaré), désactivé : toute action est refusée | Non implémenté |

Le niveau retenu est le minimum de : niveau demandé, maximum de la politique SOC
(`autonomy.max_level`), maximum du rôle de l'analyste. Toute demande supérieure est
plafonnée et le plafonnement est journalisé (`autonomy_capped`). Une action irréversible
est refusée quel que soit le niveau.

## Contrôle des permissions

| Exigence | Implémentation |
|---|---|
| GP-01 Moindre privilège | Chaque outil a une classe de risque (`read_internal`, `read_external`, `action`) dans `config/policy.yaml` |
| GP-02 Politique déclarative | Fichier YAML versionné, évalué par `gateway/policy.py` ; son empreinte est enregistrée avec chaque investigation |
| GP-03 Identité déléguée | L'agent hérite des outils et du niveau maximal du rôle de l'analyste (`config/analysts.yaml`) ; un analyste junior ne peut pas exposer d'observable à l'extérieur |
| GP-04 Validation des paramètres | Modèles Pydantic stricts (champs inconnus interdits, formats, tailles) puis contraintes de la politique (fenêtre ≤ 24 h, index autorisés, nombre de résultats) |
| GP-05 Budgets | Par outil et global : appels, étapes, jetons, durée ; arrêt sur blocage |
| GP-06 Secrets isolés | Les clés sont lues dans `.env` par `config/settings.py` et détenues par les connecteurs ; elles n'apparaissent ni dans les prompts, ni dans les paramètres d'outils, ni dans l'audit |
| GP-07 Données non fiables | Voir ci-dessous |
| GP-08 Confidentialité | LLM local possible (Ollama) ; avec une API, pseudonymisation des comptes, hôtes, e-mails et IP internes ; les observables internes ne sont jamais envoyés à la TI externe |

Ordre des contrôles dans la passerelle : outil connu → paramètres valides → outil actif →
action interdite → droits de l'analyste → contraintes → budget → niveau d'autonomie
(autoriser ou soumettre à l'analyste).

## Défense contre la prompt injection indirecte (GP-07)

1. **Balisage** : tout contenu issu des sources est inséré dans les prompts entre balises
   `<untrusted_data>` ; les balises imbriquées sont neutralisées.
2. **Détection** : chaque résultat est analysé (motifs FR/EN : « ignore les instructions »,
   changement de rôle, invocation d'outil, manipulation du verdict, faux balisage…). Les
   éléments suspects sont marqués `injection_suspected`, l'événement est journalisé et
   signalé dans le rapport.
3. **Contrôle hors LLM** : même un modèle manipulé ne peut rien exécuter d'interdit ; le
   test `test_manipulated_agent_still_blocked_by_gateway` fait demander `isolate_host`
   par l'agent : la passerelle refuse.

Le scénario S5 insère des instructions dans une ligne de commande et un nom de fichier :
elles sont détectées, aucune action interdite n'est exécutée et le verdict reste correct.

## Validation humaine (EF-19) et correction (EF-20)

Une demande soumise à l'analyste contient l'outil, les paramètres, la justification de
l'agent et la règle de politique concernée. Elle est persistée (`approvals`), tranchée via
l'API ou l'interface ; sans réponse dans le délai (`approval.timeout_s`), elle vaut refus.
Un refus exige un motif. Seuls les rôles habilités (`can_approve`) peuvent trancher.

L'analyste peut aussi invalider une hypothèse ou imposer une piste ; la consigne est prise
en compte à la révision suivante du plan et journalisée (`analyst_directive`).

## Traçabilité (GT-01 à GT-05)

| Événement journalisé | Acteur |
|---|---|
| `run_start`, `autonomy_capped`, `run_end`, `run_error` | analyste / système / agent |
| `qualification`, `plan`, `report_validation` | agent |
| `llm_call`, `llm_error` (empreinte du prompt, du résultat, jetons) | agent |
| `tool_call`, `tool_denied`, `tool_error` (paramètres, empreinte du résultat, décision, durée) | agent, pour le compte de l'analyste |
| `approval_request`, `approval_decision` (identité et motif) | agent / analyste |
| `injection_detected`, `analyst_directive` | système / analyste |

Voir [modele_preuves.md](modele_preuves.md) pour le chaînage et la vérification.
