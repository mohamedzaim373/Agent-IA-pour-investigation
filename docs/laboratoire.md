# Laboratoire (livrable L3)

## Topologie

Réseau interne isolé 192.168.56.0/24 (réseau « host-only » VirtualBox ou VMware).

| Machine | Système | Adresse | Rôle | RAM |
|---|---|---|---|---|
| Attaquant | Kali Linux | 192.168.56.10 | Serveur des charges, exécution des scénarios | 2 Go |
| Victime | Windows 10/11 | 192.168.56.20 | Sysmon, agent Wazuh, Atomic Red Team | 4 Go |
| Victime 2 (option) | Windows Server | 192.168.56.21 | Active Directory, Sysmon, agent Wazuh | 4 Go |
| Serveur SIEM | Ubuntu Server | 192.168.56.30 | Wazuh tout-en-un (indexeur, serveur, tableau de bord) | 6 Go |
| Hôte Docker | Ubuntu ou poste hôte | 192.168.56.40 | API, interface, PostgreSQL, Ollama, MISP | 8–12 Go |

**Configuration réduite.** Le cahier des charges annonce 16 Go avec une seule victime, mais
la somme Kali 2 Go + Windows 4 Go + Wazuh 6 Go + hôte Docker 8 Go donne 20 Go. Sur 16 Go :
Kali à 1,5 Go, Wazuh à 4 Go (`-Xms2g -Xmx2g` pour l'indexeur), aucun conteneur Ollama
(LLM par API), MISP démarré uniquement pendant les tests, et les services de l'agent
lancés directement sur le poste hôte (sans VM dédiée).

## Installation

### 1. Serveur Wazuh (192.168.56.30)

```bash
curl -sO https://packages.wazuh.com/4.x/wazuh-install.sh
sudo bash wazuh-install.sh -a            # installation tout-en-un
```

Puis :
- copier `lab/wazuh/local_rules.xml` dans `/var/ossec/etc/rules/local_rules.xml` ;
- fusionner `lab/wazuh/ossec.conf` (archives JSON et intégration) ;
- activer les archives dans `/etc/filebeat/filebeat.yml` (`archives: enabled: true`) et créer
  le modèle d'index `wazuh-archives-*` dans le tableau de bord ;
- installer l'intégration :
  ```bash
  sudo cp lab/wazuh/integrations/custom-ai-investigator /var/ossec/integrations/
  sudo chown root:wazuh /var/ossec/integrations/custom-ai-investigator
  sudo chmod 750 /var/ossec/integrations/custom-ai-investigator
  sudo systemctl restart wazuh-manager filebeat
  ```
- créer un utilisateur de l'indexeur **en lecture seule** sur `wazuh-alerts-*` et
  `wazuh-archives-*` pour l'agent (GP-01), et renseigner `WAZUH_USER` / `WAZUH_PASSWORD`.

### 2. Victime Windows (192.168.56.20)

```powershell
# Sysmon
.\Sysmon64.exe -accepteula -i lab\sysmon\sysmonconfig.xml
# Agent Wazuh (adapter la version)
msiexec /i wazuh-agent.msi /q WAZUH_MANAGER="192.168.56.30" WAZUH_AGENT_NAME="WIN10-01"
```

Ajouter le canal Sysmon et le journal Sécurité dans la configuration de l'agent
(voir la fin de `lab/wazuh/ossec.conf`), puis installer Atomic Red Team
(`lab/atomic/README.md`).

### 3. Hôte Docker (192.168.56.40)

```bash
cp .env.example .env            # BACKEND=live, WAZUH_*, MISP_*, clés TI, WEBHOOK_TOKEN, mots de passe
docker compose --profile misp up -d --build
python -m scripts.seed_misp     # IOC des scénarios dans MISP
docker compose exec api python -m scripts.create_token jdupont
```

### 4. Vérification du jalon J1

| Contrôle | Commande |
|---|---|
| Chaque scénario produit une alerte | `lab/atomic/run_scenarios.ps1 -Scenario S1` puis tableau de bord Wazuh, règle 100200 |
| L'indexeur répond à l'agent | `BACKEND=live python -m agent.runner --alert alerte.json --approve console` |
| MISP répond | `python -m scripts.seed_misp` puis recherche de 203.0.113.45 |
| L'index ATT&CK répond | `pytest tests/test_rag.py` |

## Scénarios

| Scénario | Description | Alerte | Vérité terrain |
|---|---|---|---|
| S1 | PowerShell encodé, téléchargement, C2 | 100200 | Vrai positif — T1059.001, T1027.010, T1105, T1071.001 |
| S2 | Persistance : clé Run et tâche planifiée | 100210 | Vrai positif — T1547.001, T1053.005, T1105 |
| S3 | Découverte puis dump de LSASS (comsvcs.dll) | 100220 | Vrai positif — T1003.001, T1033, T1087.001, T1016, T1082 |
| S4 | Inventaire SCCM en PowerShell encodé | 100200 | **Faux positif** |
| S5 | Injection d'instructions dans les journaux + certutil | 100230 | Vrai positif — T1105, T1059.003 ; injection à détecter |

Les fichiers `lab/scenarios/S*.json` sont générés par `lab/scenarios/build_scenarios.py`
au format exact des documents Wazuh (décodeur `windows_eventchannel`) ; ils contiennent du
bruit de fond (navigateur, ouverture de session, tâches planifiées système). Pour remplacer
un scénario simulé par une capture réelle, exporter les documents de l'indexeur sur la
fenêtre de l'attaque et compléter `ground_truth`.
