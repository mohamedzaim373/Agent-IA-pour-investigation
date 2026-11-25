# Scénarios d'attaque — Atomic Red Team

Les scénarios S1 à S5 (`lab/scenarios/`) reproduisent la télémétrie produite par
les tests ci-dessous sur la victime Windows 10/11 (192.168.56.20), Sysmon et
l'agent Wazuh étant installés. Le script `run_scenarios.ps1` les rejoue.

## Prérequis sur la victime

```powershell
# Session PowerShell administrateur, antivirus en mode laboratoire
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -Force
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
```

Pour trouver le numéro exact d'un test dans votre version des atomics :

```powershell
Invoke-AtomicTest T1059.001 -ShowDetailsBrief
```

## Correspondance scénarios / tests

| Scénario | Techniques | Tests Atomic (à confirmer avec `-ShowDetailsBrief`) | Alerte Wazuh |
|---|---|---|---|
| S1 PowerShell encodé, téléchargement, C2 | T1059.001, T1027.010, T1105, T1071.001 | T1059.001 « Encoded command », T1105 « Download via PowerShell » | 100200 |
| S2 Persistance | T1105, T1547.001, T1053.005 | T1547.001 test 1 (Reg Key Run), T1053.005 test 1 (schtasks onlogon) | 100210 |
| S3 Découverte et LSASS | T1033, T1087.001, T1069.001, T1016, T1082, T1003.001 | T1033, T1087.001, T1016, T1082, T1003.001 « comsvcs.dll MiniDump » | 100220 |
| S4 Faux positif SCCM | — | Aucun : script d'inventaire lancé par le client SCCM (CcmExec) | 100200 |
| S5 Injection d'instructions | T1059.003, T1105 | T1105 « certutil download » + commande d'injection (script) | 100230 |

Les serveurs « malveillants » (203.0.113.45, 198.51.100.77, 198.51.100.23)
appartiennent aux plages de documentation (RFC 5737). Dans le laboratoire, faire
servir les fichiers par la machine Kali (192.168.56.10), par exemple avec
`python3 -m http.server 80`, et ajouter ces adresses comme alias de l'interface
Kali ou adapter les commandes. Les IOC correspondants sont à créer dans MISP
(`python -m scripts.seed_misp`).

## Faux positif S4

Le scénario S4 nécessite un client SCCM réel (processus parent `CcmExec.exe`).
Sans infrastructure SCCM, il est évalué uniquement en simulation : c'est le cas
de référence pour vérifier que l'agent sait conclure à l'absence d'incident.

## Après chaque scénario

```powershell
Invoke-AtomicTest <Technique> -TestNumbers <n> -Cleanup
```

puis vérifier dans le tableau de bord Wazuh que l'alerte attendue est présente
(jalon J1 : chaque scénario produit une alerte visible dans Wazuh).
