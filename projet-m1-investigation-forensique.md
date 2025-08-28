# PROJET M1 - Guide d'Investigation Forensique
## Analyse Post-Attaque avec les Outils Spécialisés

### 🎯 Objectif de l'Investigation
Analyser les artefacts laissés par l'attaque Silver C2 en utilisant une approche forensique méthodique pour :
- Détecter la présence de malware en mémoire vive
- Analyser les traces sur le disque dur
- Reconstruire la timeline de l'attaque
- Identifier les techniques utilisées par l'attaquant

---

## 🧰 Arsenal d'Outils Forensiques

### Outils Principaux du Projet M1
| Outil | Version | Fonction Principale | VM d'Utilisation |
|-------|---------|-------------------|-------------------|
| **Volatility** | 3.x | Analyse mémoire vive | VM3 (Ubuntu) |
| **Autopsy** | 4.20+ | Interface forensique complète | VM3 (Ubuntu) |
| **The Sleuth Kit** | 4.x | Analyse filesystem | VM3 (Ubuntu) |
| **Belkasoft RAM Capturer** | 2024.x | Capture mémoire Windows | VM2 (Windows) |
| **FTK Imager** | 4.x | Imagerie forensique | VM2/VM3 |
| **TheHive** | 5.x | Gestion de cas (optionnel) | VM3 (Ubuntu) |

---

## 🔬 Phase 1 : Collecte de Preuves

### Étape 1.1 : Capture de la Mémoire Vive (VM2)

#### Installation et utilisation de Belkasoft RAM Capturer
```powershell
# Sur VM2 (Windows 10) - À exécuter AVANT de terminer l'attaque

# Télécharger Belkasoft RAM Capturer (version gratuite)
# https://belkasoft.com/ram-capturer

# Exécuter la capture (en tant qu'administrateur)
# Interface graphique : 
# 1. Lancer RamCapturer64.exe en tant qu'admin
# 2. Sélectionner le lecteur de destination (C:\Evidence\)
# 3. Cliquer sur "Capture!"

# Alternative ligne de commande
& "C:\Tools\BelkasoftRAMCapturer\RamCapturer64.exe" "C:\Evidence\memory-dump.mem"
```

#### Vérification de la capture mémoire
```powershell
# Vérifier la taille et l'intégrité
dir C:\Evidence\memory-dump.mem
Get-FileHash C:\Evidence\memory-dump.mem -Algorithm SHA256
```

### Étape 1.2 : Imagerie du Disque avec FTK Imager

#### Installation FTK Imager sur VM2
```powershell
# Télécharger AccessData FTK Imager (gratuit)
# https://www.exterro.com/ftk-imager

# Créer une image du disque système
# Interface graphique FTK Imager :
# 1. File > Create Disk Image
# 2. Source : Physical Drive (Disque C:)
# 3. Destination : Raw (dd) format
# 4. Location : C:\Evidence\disk-image.dd
# 5. Fragmentation : 2GB par fichier
```

#### Script PowerShell pour automatiser la collecte
```powershell
# Script de collecte automatique sur VM2
$evidenceDir = "C:\Evidence"
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

# Créer le répertoire d'evidence
New-Item -ItemType Directory -Force -Path $evidenceDir

# Collecte d'informations système
Write-Host "Collecte des informations système..."
systeminfo > "$evidenceDir\systeminfo-$timestamp.txt"
Get-Process > "$evidenceDir\processes-$timestamp.txt"
netstat -an > "$evidenceDir\netstat-$timestamp.txt"
Get-WmiObject Win32_Service | Select Name,State,StartMode,PathName > "$evidenceDir\services-$timestamp.txt"

# Registre - Clés importantes
Write-Host "Export des clés de registre importantes..."
reg export "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" "$evidenceDir\reg-run-user-$timestamp.reg"
reg export "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" "$evidenceDir\reg-run-machine-$timestamp.reg"
reg export "HKLM\System\CurrentControlSet\Services" "$evidenceDir\reg-services-$timestamp.reg"

# Tâches programmées
schtasks /query /fo csv > "$evidenceDir\scheduled-tasks-$timestamp.csv"

Write-Host "Collecte terminée dans $evidenceDir"
```

### Étape 1.3 : Transfert des Preuves vers VM3
```bash
# Sur VM3 (Ubuntu) - Préparer l'environnement
mkdir -p ~/forensics/evidence/vm2/{memory,disk,logs,registry}

# Utiliser scp pour transférer (si SSH configuré)
scp user@192.168.56.20:C:/Evidence/memory-dump.mem ~/forensics/evidence/vm2/memory/
scp user@192.168.56.20:C:/Evidence/disk-image.dd ~/forensics/evidence/vm2/disk/
scp user@192.168.56.20:C:/Evidence/*.txt ~/forensics/evidence/vm2/logs/
scp user@192.168.56.20:C:/Evidence/*.reg ~/forensics/evidence/vm2/registry/

# Alternative : serveur HTTP temporaire sur VM2 puis wget sur VM3
```

---

## 🧠 Phase 2 : Analyse de la Mémoire avec Volatility

### Étape 2.1 : Installation et Configuration de Volatility 3
```bash
# Sur VM3 (Ubuntu)
# Installation via apt (si disponible)
sudo apt update
sudo apt install volatility3

# Installation via pip (version la plus récente)
pip3 install volatility3

# Installation depuis les sources
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
python3 setup.py install

# Vérifier l'installation
vol -h
```

### Étape 2.2 : Analyse Initiale de la Mémoire
```bash
# Chemin vers le dump mémoire
MEMDUMP="~/forensics/evidence/vm2/memory/memory-dump.mem"

# 1. Identification du profil/OS
echo "=== Identification du Système ==="
vol -f $MEMDUMP windows.info

# 2. Liste des processus
echo "=== Liste des Processus ==="
vol -f $MEMDUMP windows.pslist > ~/forensics/analysis/pslist.txt
vol -f $MEMDUMP windows.pstree > ~/forensics/analysis/pstree.txt

# 3. Processus cachés ou suspects
echo "=== Détection de Processus Cachés ==="
vol -f $MEMDUMP windows.psxview > ~/forensics/analysis/psxview.txt
```

### Étape 2.3 : Détection des Malwares et Injections
```bash
# Détection de code injecté
echo "=== Détection d'Injections de Code ==="
vol -f $MEMDUMP windows.malfind > ~/forensics/analysis/malfind.txt

# Analyse des processus suspects (rechercher SystemOptimizer.exe)
vol -f $MEMDUMP windows.dlllist --pid <PID_SUSPECT> > ~/forensics/analysis/dlllist-suspect.txt

# Hooks et modifications système
vol -f $MEMDUMP windows.ssdt > ~/forensics/analysis/ssdt.txt

# Recherche de patterns Silver C2
vol -f $MEMDUMP windows.strings --strings-file ~/forensics/patterns/silver-strings.txt
```

### Étape 2.4 : Analyse des Connexions Réseau
```bash
# Connexions réseau actives
echo "=== Connexions Réseau ==="
vol -f $MEMDUMP windows.netstat > ~/forensics/analysis/netstat-memory.txt
vol -f $MEMDUMP windows.netscan > ~/forensics/analysis/netscan.txt

# Recherche d'IPs suspectes (192.168.56.10 - notre serveur C2)
grep "192.168.56.10" ~/forensics/analysis/netstat-memory.txt
grep "8080\|8443" ~/forensics/analysis/netscan.txt
```

### Étape 2.5 : Extraction d'Artefacts Spécifiques
```bash
# Extraction du processus suspect
echo "=== Extraction de Processus ==="
vol -f $MEMDUMP windows.memmap --pid <PID_SYSTEMOPTIMIZER> --dump

# Recherche de clés de chiffrement ou tokens
vol -f $MEMDUMP windows.strings | grep -i "bearer\|token\|key\|password"

# Historique des commandes
vol -f $MEMDUMP windows.cmdline > ~/forensics/analysis/cmdline.txt

# Registre en mémoire
vol -f $MEMDUMP windows.registry.hivelist > ~/forensics/analysis/registry-hivelist.txt
vol -f $MEMDUMP windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run" > ~/forensics/analysis/registry-run.txt
```

---

## 🔍 Phase 3 : Analyse du Disque avec The Sleuth Kit

### Étape 3.1 : Installation et Configuration
```bash
# Installation The Sleuth Kit
sudo apt update
sudo apt install sleuthkit

# Vérifier l'installation
tsk_version
```

### Étape 3.2 : Analyse de l'Image Disque
```bash
# Chemin vers l'image disque
DISKIMG="~/forensics/evidence/vm2/disk/disk-image.dd"

# 1. Information sur l'image
echo "=== Informations Image Disque ==="
img_stat $DISKIMG > ~/forensics/analysis/disk-info.txt

# 2. Analyse des partitions
mmls $DISKIMG > ~/forensics/analysis/partitions.txt

# 3. Analyse du système de fichiers (partition principale, généralement offset 2048)
OFFSET=2048  # Ajuster selon mmls
fsstat -o $OFFSET $DISKIMG > ~/forensics/analysis/filesystem.txt
```

### Étape 3.3 : Timeline et Analyse Temporelle
```bash
# Création d'une timeline complète
echo "=== Création de la Timeline ==="
fls -r -o $OFFSET $DISKIMG > ~/forensics/analysis/file-list.txt

# Timeline avec métadonnées détaillées
ils -o $OFFSET $DISKIMG | mactime -b > ~/forensics/analysis/timeline-full.txt

# Timeline pour la période de l'attaque (ajuster les dates)
mactime -b -d ~/forensics/analysis/timeline-full.txt 2024-08-27..2024-08-28 > ~/forensics/analysis/timeline-attack.txt
```

### Étape 3.4 : Recherche de Fichiers Spécifiques
```bash
# Rechercher les payloads Silver
echo "=== Recherche de Fichiers Malveillants ==="
fls -r -o $OFFSET $DISKIMG | grep -i "systemoptimizer\|optimization\|winupdate"

# Recherche par hash (si connus)
# Calculer le hash des payloads originaux sur VM1
# md5sum ~/project-m1/payloads/*.exe

# Rechercher les fichiers supprimés
fls -r -d -o $OFFSET $DISKIMG > ~/forensics/analysis/deleted-files.txt

# Récupération de fichiers spécifiques
# icat -o $OFFSET $DISKIMG <inode> > ~/forensics/recovered/filename
```

### Étape 3.5 : Analyse du Registre Windows
```bash
# Localiser les ruches de registre
fls -r -o $OFFSET $DISKIMG | grep -i "\.reg\|SAM\|SYSTEM\|SOFTWARE\|NTUSER"

# Extraire les ruches importantes
# Exemples d'inodes (à adapter selon votre système)
icat -o $OFFSET $DISKIMG <INODE_SOFTWARE> > ~/forensics/registry/SOFTWARE
icat -o $OFFSET $DISKIMG <INODE_SYSTEM> > ~/forensics/registry/SYSTEM
icat -o $OFFSET $DISKIMG <INODE_SAM> > ~/forensics/registry/SAM
```

---

## 🖥️ Phase 4 : Analyse Complète avec Autopsy

### Étape 4.1 : Installation et Configuration d'Autopsy
```bash
# Prérequis Java
sudo apt install default-jdk

# Télécharger Autopsy
wget https://github.com/sleuthkit/autopsy/releases/download/autopsy-4.20.0/autopsy-4.20.0.zip
unzip autopsy-4.20.0.zip -d ~/forensics/tools/

# Installation
cd ~/forensics/tools/autopsy-4.20.0
sudo ./unix_setup.sh

# Démarrage
./autopsy
# Interface web disponible sur http://localhost:9999/autopsy
```

### Étape 4.2 : Création d'un Cas dans Autopsy
```
Interface Web Autopsy :

1. New Case
   - Case Name: "Projet-M1-Silver-C2-Investigation"
   - Case Directory: ~/forensics/cases/
   - Investigator: [Votre nom]

2. Add Host
   - Host Name: "VM2-Windows10-Victim"
   - Description: "Machine victime de l'attaque Silver C2"
   - Time Zone: Europe/Paris

3. Add Image
   - Location: ~/forensics/evidence/vm2/disk/disk-image.dd
   - Type: Disk
   - Import Method: Copy
```

### Étape 4.3 : Analyse avec Autopsy
```
Modules d'analyse automatique à activer :

1. File Analysis
   ✓ File Type Identification
   ✓ Extension Mismatch Detector
   ✓ Hash Database (si hashes de malware disponibles)
   ✓ Embedded File Extractor

2. Data Artifacts
   ✓ Recent Activity
   ✓ Web Activity
   ✓ Registry
   ✓ Installed Programs

3. Timeline Analysis
   ✓ Plaso (log2timeline)

4. Keyword Search
   - Mots-clés : "Silver", "SystemOptimizer", "OptimizationService"
   - "192.168.56.10", "8080", "8443"
   - "payload", "beacon", "C2"
```

### Étape 4.4 : Investigation Ciblée dans Autopsy
```
Navigation dans l'interface :

1. Data Sources > VM2-Windows10-Victim > File System
   - Analyser : C:\Windows\System32\OptimizationService.exe
   - Analyser : C:\Windows\Temp\.system\
   - Analyser : C:\Users\[user]\Downloads\

2. Views > File Types > Executables
   - Rechercher les .exe suspects
   - Vérifier les propriétés et métadonnées

3. Views > Deleted Files
   - Rechercher les fichiers supprimés pendant l'attaque

4. Data Artifacts > Operating System Information
   - Services installés
   - Programmes démarrés au boot
   - Tâches programmées

5. Timeline
   - Filtrer par date/heure de l'attaque
   - Rechercher les activités suspectes
```

---

## 📊 Phase 5 : Analyse Avancée et Corrélation

### Étape 5.1 : Création de Profils Volatility pour Silver C2
```bash
# Créer un fichier de signatures pour Silver C2
cat > ~/forensics/patterns/silver-signatures.txt << EOF
# Signatures Silver C2 pour Volatility
rule Silver_C2_Implant
{
    strings:
        $s1 = "sliver"
        $s2 = "beacon"
        $s3 = "session"
        $s4 = "implant"
        $s5 = { 50 72 6F 74 6F 62 75 66 }  # "Protobuf" en hex
    condition:
        2 of them
}
EOF

# Recherche avec YARA dans le dump mémoire
yara ~/forensics/patterns/silver-signatures.txt $MEMDUMP
```

### Étape 5.2 : Analyse des Logs Windows
```bash
# Extraction et analyse des logs d'événements Windows
# (si extraits du disque avec icat)

# Convertir les logs .evtx en format lisible
sudo apt install python3-evtx

# Analyser les logs de sécurité
evtx_dump.py ~/forensics/evidence/vm2/logs/Security.evtx > ~/forensics/analysis/security-events.txt

# Rechercher les événements suspects
grep -i "process\|login\|privilege" ~/forensics/analysis/security-events.txt | head -100

# Timeline des événements
evtx_dump.py ~/forensics/evidence/vm2/logs/System.evtx --timeline > ~/forensics/analysis/system-timeline.txt
```

### Étape 5.3 : Corrélation Multi-Sources
```bash
# Script de corrélation temporelle
cat > ~/forensics/scripts/correlate-evidence.py << 'EOF'
#!/usr/bin/env python3
"""
Script de corrélation des preuves pour le Projet M1
Corrèle les données de mémoire, disque et logs
"""

import re
import datetime
from collections import defaultdict

def parse_volatility_pslist(file_path):
    """Parse la sortie de vol windows.pslist"""
    processes = []
    with open(file_path, 'r') as f:
        for line in f:
            if 'SystemOptimizer' in line or 'OptimizationService' in line:
                parts = line.split()
                if len(parts) >= 6:
                    processes.append({
                        'name': parts[1],
                        'pid': parts[2],
                        'ppid': parts[3],
                        'threads': parts[4],
                        'create_time': ' '.join(parts[7:9]) if len(parts) > 8 else 'N/A'
                    })
    return processes

def parse_autopsy_timeline(file_path):
    """Parse la timeline d'Autopsy"""
    events = []
    with open(file_path, 'r') as f:
        for line in f:
            if any(keyword in line.lower() for keyword in ['systemoptimizer', 'optimization', 'payload']):
                events.append(line.strip())
    return events

def correlate_evidence():
    """Corrélation des preuves"""
    print("=== CORRÉLATION DES PREUVES - PROJET M1 ===")
    
    # Analyser les processus suspects
    try:
        processes = parse_volatility_pslist('~/forensics/analysis/pslist.txt')
        print(f"\nProcessus suspects trouvés : {len(processes)}")
        for proc in processes:
            print(f"  - {proc['name']} (PID: {proc['pid']}, Créé: {proc['create_time']})")
    except Exception as e:
        print(f"Erreur analyse processus : {e}")
    
    # Analyser la timeline
    try:
        events = parse_autopsy_timeline('~/forensics/analysis/timeline-attack.txt')
        print(f"\nÉvénements timeline : {len(events)}")
        for event in events[:10]:  # Premiers 10 événements
            print(f"  - {event}")
    except Exception as e:
        print(f"Erreur analyse timeline : {e}")

if __name__ == "__main__":
    correlate_evidence()
EOF

chmod +x ~/forensics/scripts/correlate-evidence.py
python3 ~/forensics/scripts/correlate-evidence.py
```

---

## 🎯 Phase 6 : Détection Spécifique Silver C2

### Étape 6.1 : Signatures et Indicateurs Silver C2
```bash
# Créer une base de signatures Silver C2
cat > ~/forensics/patterns/silver-indicators.txt << EOF
# Indicateurs de compromission Silver C2

## Noms de fichiers typiques
SystemOptimizer.exe
OptimizationService.exe
WinUpdate.exe
msvcr120.dll

## Strings caractéristiques
sliver
implant
beacon
session_
task_
protobuf

## Ports réseau typiques
8080/tcp
8443/tcp
53/udp
31337/tcp

## Clés de registre
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\OptimizationService
HKLM\System\CurrentControlSet\Services\OptimizationSvc

## Processus parent suspects
explorer.exe -> SystemOptimizer.exe
svchost.exe -> OptimizationService.exe

## Connexions réseau suspectes
192.168.56.10:8080
192.168.56.10:8443
EOF
```

### Étape 6.2 : Recherche Automatisée des IoCs
```bash
# Script de détection automatique
cat > ~/forensics/scripts/detect-silver-c2.sh << 'EOF'
#!/bin/bash

echo "=== DÉTECTION SILVER C2 - PROJET M1 ==="

EVIDENCE_DIR="~/forensics/evidence/vm2"
ANALYSIS_DIR="~/forensics/analysis"

# 1. Recherche dans la mémoire
echo "1. Analyse mémoire pour Silver C2..."
if [ -f "$ANALYSIS_DIR/pslist.txt" ]; then
    grep -i "systemoptimizer\|optimization" "$ANALYSIS_DIR/pslist.txt" && echo "✓ Processus Silver détectés"
fi

if [ -f "$ANALYSIS_DIR/netstat-memory.txt" ]; then
    grep "192.168.56.10\|8080\|8443" "$ANALYSIS_DIR/netstat-memory.txt" && echo "✓ Connexions C2 détectées"
fi

# 2. Recherche sur disque
echo "2. Analyse disque pour Silver C2..."
if [ -f "$ANALYSIS_DIR/file-list.txt" ]; then
    grep -i "systemoptimizer\|optimization\|winupdate" "$ANALYSIS_DIR/file-list.txt" && echo "✓ Fichiers malveillants détectés"
fi

# 3. Recherche dans les logs
echo "3. Analyse des logs..."
find "$EVIDENCE_DIR/logs" -name "*.txt" -exec grep -l "OptimizationService\|SystemOptimizer" {} \; && echo "✓ Références dans les logs"

# 4. Analyse du registre
echo "4. Analyse du registre..."
find "$EVIDENCE_DIR/registry" -name "*.reg" -exec grep -l "OptimizationService" {} \; && echo "✓ Persistance registre détectée"

echo "=== DÉTECTION TERMINÉE ==="
EOF

chmod +x ~/forensics/scripts/detect-silver-c2.sh
./~/forensics/scripts/detect-silver-c2.sh
```

---

## 📝 Phase 7 : Gestion de Cas avec TheHive (Optionnel)

### Étape 7.1 : Installation TheHive
```bash
# Installation via Docker (méthode recommandée)
sudo apt install docker.io docker-compose

# Créer la configuration TheHive
mkdir -p ~/forensics/thehive
cd ~/forensics/thehive

cat > docker-compose.yml << 'EOF'
version: '3.8'
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.17.0
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
    ports:
      - "9200:9200"
    volumes:
      - elasticsearch_data:/usr/share/elasticsearch/data

  thehive:
    image: thehiveproject/thehive4:latest
    depends_on:
      - elasticsearch
    ports:
      - "9000:9000"
    environment:
      - TH_DB_PROVIDER=elasticsearch
      - TH_DB_HOSTS=elasticsearch:9200
    volumes:
      - thehive_data:/opt/thp/thehive/data

volumes:
  elasticsearch_data:
  thehive_data:
EOF

# Démarrer TheHive
docker-compose up -d
```

### Étape 7.2 : Création du Cas dans TheHive
```
Interface Web TheHive (http://localhost:9000) :

1. Créer un nouveau cas
   - Title: "Projet M1 - Silver C2 Incident"
   - Severity: Medium (2)
   - TLP: WHITE
   - PAP: WHITE
   - Tags: silver-c2, post-exploitation, vm-lab

2. Ajouter des observables
   - IP Address: 192.168.56.10 (serveur C2)
   - Filename: SystemOptimizer.exe
   - Filename: OptimizationService.exe
   - Registry Key: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\OptimizationService

3. Créer des tâches
   - "Analyse mémoire avec Volatility"
   - "Analyse disque avec Autopsy"
   - "Corrélation des preuves"
   - "Rédaction du rapport final"
```

---

## 📊 Phase 8 : Synthèse et Rapport

### Étape 8.1 : Compilation des Résultats
```bash
# Script de génération de rapport automatique
cat > ~/forensics/scripts/generate-report.sh << 'EOF'
#!/bin/bash

REPORT_DIR="~/forensics/reports"
ANALYSIS_DIR="~/forensics/analysis"
TIMESTAMP=$(date +"%Y%m%d-%H%M%S")

mkdir -p $REPORT_DIR

cat > "$REPORT_DIR/investigation-summary-$TIMESTAMP.md" << EOL
# RAPPORT D'INVESTIGATION - PROJET M1
## Simulation d'Attaque Silver C2

### Résumé Exécutif
Date d'investigation : $(date)
Investigateur : [Nom]
Incident : Simulation d'attaque post-exploitation avec Silver C2

### Preuves Collectées
- Dump mémoire : $(ls -lh ~/forensics/evidence/vm2/memory/*.mem | awk '{print $9, $5}')
- Image disque : $(ls -lh ~/forensics/evidence/vm2/disk/*.dd | awk '{print $9, $5}')
- Logs système : $(find ~/forensics/evidence/vm2/logs -name "*.txt" | wc -l) fichiers

### Artefacts Identifiés

#### Processus Malveillants
EOL

# Ajouter les processus suspects trouvés
if [ -f "$ANALYSIS_DIR/pslist.txt" ]; then
    echo "```" >> "$REPORT_DIR/investigation-summary-$TIMESTAMP.md"
    grep -i "systemoptimizer\|optimization" "$ANALYSIS_DIR/pslist.txt" >> "$REPORT_DIR/investigation-summary-$TIMESTAMP.md"
    echo "```" >> "$REPORT_DIR/investigation-summary-$TIMESTAMP.md"
fi

cat >> "$REPORT_DIR/investigation-summary-$TIMESTAMP.md" << EOL

#### Connexions Réseau Suspectes
EOL

# Ajouter les connexions réseau
if [ -f "$ANALYSIS_DIR/netstat-memory.txt" ]; then
    echo "```" >> "$REPORT_DIR/investigation-summary-$TIMESTAMP.md"
    grep "192.168.56.10\|8080\|8443" "$ANALYSIS_DIR/netstat-memory.txt" >> "$REPORT_DIR/investigation-summary-$TIMESTAMP.md"
    echo "```" >> "$REPORT_DIR/investigation-summary-$TIMESTAMP.md"
fi

cat >> "$REPORT_DIR/investigation-summary-$TIMESTAMP.md" << EOL

### Recommandations
1. Renforcement de la détection d'endpoints
2. Monitoring des connexions réseau sortantes
3. Surveillance des mécanismes de persistance
4. Formation des utilisateurs

### Conclusion
L'investigation confirme la présence de l'implant Silver C2 et permet de reconstruire la timeline complète de l'attaque.

EOL

echo "Rapport généré : $REPORT_DIR/investigation-summary-$TIMESTAMP.md"
EOF

chmod +x ~/forensics/scripts/generate-report.sh
./~/forensics/scripts/generate-report.sh
```

---

## ✅ Checklist d'Investigation Complète

### Preuves Collectées
- [ ] Dump mémoire avec Belkasoft RAM Capturer
- [ ] Image disque avec FTK Imager
- [ ] Logs système et événements Windows
- [ ] Export des clés de registre importantes
- [ ] Informations système et réseau

### Analyse Mémoire (Volatility)
- [ ] Identification des processus malveillants
- [ ] Détection des injections de code
- [ ] Analyse des connexions réseau
- [ ] Extraction d'artefacts spécifiques
- [ ] Recherche de signatures Silver C2

### Analyse Disque (Sleuth Kit + Autopsy)
- [ ] Timeline complète du système
- [ ] Localisation des fichiers malveillants
- [ ] Récupération des fichiers supprimés
- [ ] Analyse des métadonnées
- [ ] Corrélation temporelle

### Détection Silver C2
- [ ] Identification des processus Silver
- [ ] Localisation des mécanismes de persistance
- [ ] Trace des connexions C2
- [ ] Reconstruction de la chaîne d'attaque
- [ ] Documentation des IoCs

### Rapport Final
- [ ] Synthèse des découvertes
- [ ] Timeline de l'attaque
- [ ] Preuves techniques
- [ ] Recommandations de sécurité
- [ ] Archivage des preuves

---

**Prochaine étape** : Templates de rapport et documentation de l'investigation.

---

*Guide d'Investigation Forensique pour Projet M1 - Cyber Forensics*