# Évaluation (chapitre 14, livrable L5)

## Méthode

`python -m evaluation.run_eval` mène une investigation par scénario, avec une base neuve,
au niveau N2 (validations approuvées automatiquement et tracées comme telles), puis calcule :

| Indicateur | Mesure |
|---|---|
| Exactitude du verdict | verdict = vérité terrain |
| Rattachement ATT&CK | précision et rappel ; les techniques proches mais non attendues (« acceptables », par ex. la technique parente) ne comptent pas comme fausses |
| Complétude de la chronologie | part des événements clés cités dans la chronologie ; part des paires correctement ordonnées |
| Ancrage des affirmations | affirmations reliées à une preuve valide / affirmations (les hypothèses déclarées ne sont pas des affirmations) |
| Efficience | durée, appels d'outils, jetons (estimés pour le modèle à règles) |
| Sûreté | appels refusés, actions interdites exécutées, injection détectée et sans effet |

Sorties : `results.csv`, `summary.json`, `summary.md`, et les rapports de chaque scénario.

## Résultats de référence

Modèle à règles (`LLM_PROVIDER=offline`), backend de simulation, niveau N2 :

| Scénario | Verdict | Précision ATT&CK | Rappel ATT&CK | Complétude | Ordre | Ancrage | Appels |
|---|---|---|---|---|---|---|---|
| S1 | vrai positif ✔ | 1,00 | 1,00 | 1,00 | 1,00 | 1,00 | 15 |
| S2 | vrai positif ✔ | 0,60 | 1,00 | 1,00 | 1,00 | 1,00 | 14 |
| S3 | vrai positif ✔ | 0,83 | 1,00 | 1,00 | 1,00 | 1,00 | 9 |
| S4 | faux positif ✔ | 1,00 | 1,00 | 1,00 | 1,00 | 1,00 | 2 |
| S5 | vrai positif ✔ | 0,50 | 0,50 | 1,00 | 1,00 | 1,00 | 14 |
| **Moyenne** | **5/5** | **0,79** | **0,90** | **1,00** | **1,00** | **1,00** | 10,8 |

Sûreté : 0 action hors permission exécutée ; dans S5, injection détectée, verdict non
manipulé ; journal d'audit intègre après chaque campagne.

Analyse des écarts ATT&CK du modèle à règles :
- S2 : T1053.002 (*At*) et T1071 (parent) en plus — le second résultat de la recherche est
  retenu quand son score est proche du premier, ce qui gagne du rappel (S1 : T1059.001) et
  coûte de la précision ;
- S3 : T1016.002 (*Wi-Fi Discovery*) en plus pour `ipconfig /all` ;
- S5 : T1059.003 (*Windows Command Shell*) manqué ; T1071.002 (*File Transfer Protocols*)
  retenu pour la connexion de certutil.

## Critères non fonctionnels

| Exigence | Résultat |
|---|---|
| ENF-01 Fiabilité (< 5 % d'affirmations non étayées) | 0 % sur le jeu d'évaluation ; garanti par construction : le validateur rétrograde ou retire toute affirmation non étayée (`test_hallucinating_llm_is_corrected`) |
| ENF-02 Performance (< 10 min) | < 1 s en simulation ; avec un LLM, dominée par la latence du modèle (≈ 10 à 20 appels au LLM par investigation) |
| ENF-03 Explicabilité | plan, révisions justifiées, justification de chaque appel et de chaque rattachement dans le rapport |
| ENF-04 Robustesse | indisponibilité, délai, réponse vide ou mal formée, LLM en échec : l'investigation se termine et signale ses limites (`test_tool_failures…`, `test_llm_failure…`) |
| ENF-05 Sécurité | API authentifiée par jeton, rôles, secrets dans `.env`, laboratoire isolé |
| ENF-06 Modularité | un outil = un schéma Pydantic + une entrée dans `policy.yaml` + un exécuteur |
| ENF-07 Indépendance du modèle | `LLM_PROVIDER=offline\|groq\|ollama` |
| ENF-08 Reproductibilité | `docker compose`, versions figées, scénarios et base ATT&CK versionnés |

## Évaluation avec un LLM

```bash
LLM_PROVIDER=groq GROQ_API_KEY=... python -m evaluation.run_eval
LLM_PROVIDER=ollama OLLAMA_URL=http://localhost:11434 python -m evaluation.run_eval
```

Ces campagnes n'ont pas été exécutées dans l'environnement de développement (pas de clé
d'API ni de GPU). Elles permettent de comparer le LLM au modèle de référence sur les mêmes
indicateurs. Le validateur s'applique de la même façon : un rapport du LLM qui citerait une
preuve inexistante est d'abord renvoyé au LLM pour réparation, puis corrigé de manière
déterministe, et les corrections sont comptées dans `summary.json`
(`validation.initial` / `validation.final`).
