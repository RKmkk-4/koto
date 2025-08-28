# PROJET M1 - Simulation d'Attaque Post-Exploitation avec Silver C2
## Guide de Configuration de l'Infrastructure

### 🎯 Objectif du Projet
Simulation complète d'une attaque post-exploitation à l'aide du framework Silver C2 et conduite d'une investigation numérique approfondie visant à :
- Détecter, analyser et démontrer une intrusion informatique
- Exploiter des preuves issues de la mémoire vive et du disque dur
- Utiliser des outils spécialisés de forensique numérique

---

## 🏗️ Architecture de l'Infrastructure

### Vue d'ensemble
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   VM1 - KALI    │    │  VM2 - WINDOWS  │    │  VM3 - UBUNTU   │
│   (ATTAQUANT)   │───▶│   (VICTIME)     │───▶│   (ANALYSTE)    │
│                 │    │                 │    │                 │
│ • Silver C2     │    │ • Windows 10    │    │ • Volatility    │
│ • Payload Gen   │    │ • Target App    │    │ • Autopsy      │
│ • C2 Server     │    │ • RAM Capture   │    │ • Sleuth Kit   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
        │                        │                        │
        └────────── Réseau Local (NAT/Host-Only) ──────────┘
```

---

## 🖥️ Configuration des Machines Virtuelles

### VM1 - Kali Linux (Attaquant)
**Rôle** : Serveur Silver C2 et génération de payloads

#### Spécifications recommandées
- **OS** : Kali Linux 2024.x (dernière version)
- **RAM** : 4 GB minimum (8 GB recommandé)
- **Stockage** : 40 GB minimum
- **CPU** : 2 cœurs minimum
- **Réseau** : NAT + Host-Only Adapter

#### Configuration réseau
```bash
# Interface principale (NAT pour Internet)
auto eth0
iface eth0 inet dhcp

# Interface Host-Only pour communication inter-VMs
auto eth1
iface eth1 inet static
    address 192.168.56.10
    netmask 255.255.255.0
```

#### Logiciels à installer
```bash
# Mise à jour du système
sudo apt update && sudo apt upgrade -y

# Outils essentiels
sudo apt install -y curl wget git build-essential
sudo apt install -y python3-pip python3-venv
sudo apt install -y nmap netcat-traditional

# Silver C2 Framework (via script automatique fourni)
./install-silver-c2.sh
```

---

### VM2 - Windows 10 (Victime)
**Rôle** : Machine cible pour l'attaque et collecte d'artefacts

#### Spécifications recommandées
- **OS** : Windows 10 Pro (version récente)
- **RAM** : 4 GB minimum
- **Stockage** : 50 GB minimum
- **CPU** : 2 cœurs minimum
- **Réseau** : Host-Only Adapter

#### Configuration réseau
- **IP statique** : 192.168.56.20
- **Masque** : 255.255.255.0
- **Passerelle** : 192.168.56.1
- **DNS** : 8.8.8.8, 8.8.4.4

#### Configuration système
```powershell
# Désactiver Windows Defender temporairement (pour le laboratoire)
Set-MpPreference -DisableRealtimeMonitoring $true

# Configurer l'IP statique
netsh interface ip set address "Ethernet" static 192.168.56.20 255.255.255.0 192.168.56.1

# Activer RDP (optionnel pour l'administration)
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -Value 0
```

#### Logiciels requis
- **Belkasoft RAM Capturer** : Pour capturer la mémoire vive
- **Applications cibles** : Navigateur web, éditeur de texte, etc.
- **PowerShell** : Version récente
- **WinRAR/7-Zip** : Pour tests d'extraction

---

### VM3 - Ubuntu (Analyste Forensique)
**Rôle** : Station d'analyse forensique et investigation

#### Spécifications recommandées
- **OS** : Ubuntu 22.04 LTS Desktop
- **RAM** : 8 GB minimum (16 GB recommandé)
- **Stockage** : 100 GB minimum
- **CPU** : 4 cœurs minimum
- **Réseau** : NAT + Host-Only Adapter

#### Configuration réseau
```bash
# Interface Host-Only
auto enp0s8
iface enp0s8 inet static
    address 192.168.56.30
    netmask 255.255.255.0
```

#### Installation des outils forensiques
```bash
#!/bin/bash
# Installation automatique des outils forensiques

# Mise à jour du système
sudo apt update && sudo apt upgrade -y

# Dépendances de base
sudo apt install -y build-essential python3-pip python3-dev
sudo apt install -y git curl wget unzip

# Volatility Framework
sudo apt install -y volatility3
pip3 install volatility3

# Autopsy (Interface graphique pour Sleuth Kit)
wget https://github.com/sleuthkit/autopsy/releases/download/autopsy-4.20.0/autopsy-4.20.0.zip
unzip autopsy-4.20.0.zip
sudo apt install -y default-jdk

# The Sleuth Kit
sudo apt install -y sleuthkit

# Autres outils forensiques
sudo apt install -y binwalk hexedit foremost
sudo apt install -y wireshark tcpdump

# YARA pour la détection de malware
sudo apt install -y yara

# TheHive (optionnel - pour gestion de cas)
# Suivre la documentation officielle TheHive
```

---

## 🌐 Configuration du Réseau

### Réseau Host-Only
Créer un réseau Host-Only dans VirtualBox/VMware :

#### VirtualBox
```bash
# Créer le réseau Host-Only
VBoxManage hostonlyif create
VBoxManage hostonlyif ipconfig vboxnet0 --ip 192.168.56.1 --netmask 255.255.255.0

# Configurer DHCP (optionnel)
VBoxManage dhcpserver add --netname HostInterfaceNetworking-vboxnet0 \
    --ip 192.168.56.1 --netmask 255.255.255.0 \
    --lowerip 192.168.56.100 --upperip 192.168.56.200
```

#### Plan d'adressage
| Machine | Rôle | IP Address | Fonction |
|---------|------|------------|----------|
| VM1 | Kali (Attaquant) | 192.168.56.10 | Silver C2 Server |
| VM2 | Windows (Victime) | 192.168.56.20 | Target Machine |
| VM3 | Ubuntu (Analyste) | 192.168.56.30 | Forensic Station |

---

## 🔧 Configuration de Sécurité

### VM1 - Kali (Attaquant)
```bash
# Configuration du firewall pour Silver C2
sudo ufw allow 8080/tcp    # HTTP Listener
sudo ufw allow 8443/tcp    # HTTPS Listener
sudo ufw allow 53/udp     # DNS Listener
sudo ufw enable

# Configuration SSH pour administration
sudo systemctl enable ssh
sudo systemctl start ssh
```

### VM2 - Windows (Victime)
```powershell
# Désactiver le firewall Windows (pour le laboratoire)
netsh advfirewall set allprofiles state off

# Créer un utilisateur test
net user testuser P@ssw0rd123 /add
net localgroup administrators testuser /add
```

### VM3 - Ubuntu (Analyste)
```bash
# Configuration sécurisée
sudo ufw enable
sudo ufw allow ssh

# Création de répertoires de travail
mkdir -p ~/forensics/{memory-dumps,disk-images,reports,tools}
mkdir -p ~/forensics/evidence/{vm1,vm2}
```

---

## 📁 Structure des Répertoires

### VM1 - Kali
```
/home/kali/
├── silver-workspace/
│   ├── payloads/          # Implants générés
│   ├── logs/              # Logs Silver C2
│   ├── configs/           # Configurations
│   └── scripts/           # Scripts d'automatisation
└── project-m1/
    ├── attack-scenarios/   # Scénarios d'attaque
    ├── reports/           # Rapports d'attaque
    └── evidence/          # Preuves collectées
```

### VM2 - Windows
```
C:\
├── Tools\
│   ├── BelkasoftRAMCapturer\
│   └── Logs\
├── Evidence\              # Répertoire pour artefacts
└── Temp\                  # Répertoire temporaire
```

### VM3 - Ubuntu
```
/home/analyst/
├── forensics/
│   ├── memory-dumps/      # Dumps mémoire
│   ├── disk-images/       # Images disque
│   ├── reports/           # Rapports d'analyse
│   ├── tools/             # Outils personnalisés
│   └── evidence/
│       ├── vm1/           # Preuves de VM1
│       └── vm2/           # Preuves de VM2
├── volatility-profiles/   # Profils Volatility
└── case-management/       # Gestion de cas
```

---

## ✅ Tests de Connectivité

### Script de test réseau
```bash
#!/bin/bash
# test-connectivity.sh

echo "=== Test de connectivité inter-VMs ==="

# Depuis VM1 (Kali)
echo "Test depuis VM1 (Kali):"
ping -c 3 192.168.56.20  # VM2
ping -c 3 192.168.56.30  # VM3

# Test des ports Silver C2
nmap -p 8080,8443 192.168.56.10

echo "Test terminé."
```

### Vérifications essentielles
1. **Connectivité réseau** : Toutes les VMs peuvent se voir
2. **Résolution DNS** : Fonctionnelle sur toutes les VMs
3. **Accès Internet** : VM1 et VM3 ont accès (pour mises à jour)
4. **Isolation** : VM2 isolée mais accessible depuis VM1/VM3

---

## 🔒 Considérations de Sécurité

### Isolation du laboratoire
- Utiliser des réseaux Host-Only ou isolés
- Aucune connexion directe aux réseaux de production
- Snapshots avant chaque test pour restauration rapide

### Sauvegarde et restauration
```bash
# Créer des snapshots avant tests
# VirtualBox
VBoxManage snapshot "VM1-Kali" take "Pre-Attack-Baseline"
VBoxManage snapshot "VM2-Windows" take "Clean-State"
VBoxManage snapshot "VM3-Ubuntu" take "Tools-Configured"

# Restauration si nécessaire
VBoxManage snapshot "VM2-Windows" restore "Clean-State"
```

---

## 🚀 Validation de l'Installation

### Checklist finale
- [ ] VM1 : Silver C2 installé et fonctionnel
- [ ] VM1 : Connectivité réseau vers VM2 et VM3
- [ ] VM2 : Windows 10 configuré, Belkasoft installé
- [ ] VM2 : Accessible depuis VM1
- [ ] VM3 : Tous les outils forensiques installés
- [ ] VM3 : Connectivité vers VM1 et VM2
- [ ] Réseau : Toutes les VMs communiquent
- [ ] Snapshots : États de base sauvegardés

### Test final
```bash
# Depuis VM1 (Kali)
sliver-server version
sliver-client

# Depuis VM3 (Ubuntu)
volatility3 --help
autopsy
sleuthkit
```

---

**Prochaine étape** : Configuration détaillée de Silver C2 sur VM1 et préparation des scénarios d'attaque.

---

*Guide créé pour le Projet M1 - Cyber Forensics*