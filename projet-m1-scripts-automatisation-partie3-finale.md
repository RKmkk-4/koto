# PROJET M1 - Scripts d'Automatisation (Partie 3 - Finale)
## Scripts de Gestion et Orchestration

---

## 🔄 Script 6 : Reset et Nettoyage du Projet (Multi-VM)

```bash
#!/bin/bash
# project-reset.sh
# Script de remise à zéro du Projet M1 pour nouvelle simulation

set -e

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Variables globales
PROJECT_DIR="$HOME/project-m1"
SILVER_DIR="$HOME/silver-workspace"
FORENSICS_DIR="$HOME/forensics"

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

confirm_reset() {
    echo -e "${YELLOW}⚠️  ATTENTION: Cette opération va supprimer toutes les données du projet!${NC}"
    echo
    echo "Éléments qui seront supprimés:"
    echo "- Tous les payloads générés"
    echo "- Logs d'attaque et de serveur"
    echo "- Preuves collectées"
    echo "- Rapports d'analyse"
    echo "- Sessions Silver actives"
    echo
    read -p "Êtes-vous sûr de vouloir continuer? (tapez 'RESET' pour confirmer): " confirmation
    
    if [ "$confirmation" != "RESET" ]; then
        log_info "Opération annulée"
        exit 0
    fi
}

# Fonction pour chaque VM
reset_vm1_kali() {
    log_info "=== Reset VM1 (Kali Linux) ==="
    
    # Arrêter Silver C2 s'il est actif
    log_info "Arrêt de Silver C2..."
    if pgrep -f "sliver-server" > /dev/null; then
        sudo pkill -f "sliver-server" || true
        log_success "Silver C2 arrêté"
    fi
    
    # Arrêter tous les listeners et sessions
    if command -v sliver-client &> /dev/null; then
        sliver-client -c "sessions" 2>/dev/null | grep -o "session_[a-zA-Z0-9]*" | while read session; do
            sliver-client -c "close $session" > /dev/null 2>&1 || true
        done
        
        sliver-client -c "listeners" 2>/dev/null | grep -o "listener_[0-9]*" | while read listener; do
            sliver-client -c "listeners -k $listener" > /dev/null 2>&1 || true
        done
    fi
    
    # Nettoyer les répertoires de projet
    if [ -d "$PROJECT_DIR" ]; then
        log_info "Nettoyage de $PROJECT_DIR..."
        rm -rf "$PROJECT_DIR/payloads"/*
        rm -rf "$PROJECT_DIR/logs"/*
        rm -rf "$PROJECT_DIR/evidence"/*
        rm -rf "$PROJECT_DIR/reports"/*
        mkdir -p "$PROJECT_DIR"/{payloads,logs,evidence,reports}
        log_success "Répertoires projet nettoyés"
    fi
    
    # Nettoyer Silver workspace
    if [ -d "$SILVER_DIR" ]; then
        log_info "Nettoyage de $SILVER_DIR..."
        rm -rf "$SILVER_DIR/payloads"/*
        rm -rf "$SILVER_DIR/logs"/*
        mkdir -p "$SILVER_DIR"/{payloads,logs}
        log_success "Workspace Silver nettoyé"
    fi
    
    # Arrêter serveur HTTP s'il est actif
    if pgrep -f "python.*http.server.*8000" > /dev/null; then
        pkill -f "python.*http.server.*8000" || true
        log_success "Serveur HTTP arrêté"
    fi
    
    log_success "VM1 (Kali) réinitialisée"
}

reset_vm2_windows() {
    log_info "=== Reset VM2 (Windows 10) - Instructions ==="
    
    # Pour Windows, on génère un script PowerShell
    cat > "$PROJECT_DIR/scripts/reset-vm2.ps1" << 'EOF'
# Script de reset pour VM2 (Windows)
Write-Host "=== RESET VM2 (Windows 10) ===" -ForegroundColor Yellow

# Arrêter les processus malveillants
$MaliciousProcesses = @("SystemOptimizer", "OptimizationService", "WinUpdate")
foreach ($Process in $MaliciousProcesses) {
    Get-Process -Name $Process -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    if ($?) {
        Write-Host "✓ Processus $Process arrêté" -ForegroundColor Green
    }
}

# Supprimer les fichiers malveillants
$MaliciousFiles = @(
    "C:\Windows\System32\OptimizationService.exe",
    "C:\Windows\System32\WinUpdate.exe", 
    "C:\Users\$env:USERNAME\Downloads\SystemOptimizer.exe"
)

foreach ($File in $MaliciousFiles) {
    if (Test-Path $File) {
        Remove-Item -Path $File -Force -ErrorAction SilentlyContinue
        Write-Host "✓ Fichier supprimé: $File" -ForegroundColor Green
    }
}

# Supprimer les mécanismes de persistance
Write-Host "Nettoyage des mécanismes de persistance..." -ForegroundColor Yellow

# Registre
$RegKeys = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\OptimizationService",
    "HKCU:\Software\AttackerTools"
)

foreach ($Key in $RegKeys) {
    if (Test-Path $Key) {
        Remove-Item -Path $Key -Force -Recurse -ErrorAction SilentlyContinue
        Write-Host "✓ Clé de registre supprimée: $Key" -ForegroundColor Green
    }
}

# Tâches programmées
$Tasks = @("System Optimization", "Windows Update Check")
foreach ($Task in $Tasks) {
    schtasks /delete /tn "$Task" /f 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ Tâche supprimée: $Task" -ForegroundColor Green
    }
}

# Services
$Services = @("OptimizationSvc")
foreach ($Service in $Services) {
    if (Get-Service -Name $Service -ErrorAction SilentlyContinue) {
        Stop-Service -Name $Service -Force -ErrorAction SilentlyContinue
        sc.exe delete $Service 2>$null
        Write-Host "✓ Service supprimé: $Service" -ForegroundColor Green
    }
}

# Nettoyer les répertoires temporaires
$TempDirs = @(
    "C:\Windows\Temp\.system",
    "C:\Evidence"
)

foreach ($Dir in $TempDirs) {
    if (Test-Path $Dir) {
        Remove-Item -Path $Dir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "✓ Répertoire nettoyé: $Dir" -ForegroundColor Green
    }
}

# Recréer le répertoire Evidence vide
New-Item -ItemType Directory -Path "C:\Evidence" -Force | Out-Null

# Optionnel: Nettoyer les logs système (pour simulation seulement)
$CleanLogs = Read-Host "Nettoyer les logs système? (y/N)"
if ($CleanLogs -eq "y" -or $CleanLogs -eq "Y") {
    wevtutil cl Application
    wevtutil cl System
    Write-Host "✓ Logs système nettoyés" -ForegroundColor Green
}

Write-Host "`n✅ VM2 (Windows) réinitialisée avec succès!" -ForegroundColor Green
Write-Host "📋 Système prêt pour nouvelle simulation" -ForegroundColor Cyan
EOF
    
    log_info "Script de reset pour VM2 créé: $PROJECT_DIR/scripts/reset-vm2.ps1"
    log_warning "Exécuter le script suivant sur VM2 (Windows):"
    echo "   PowerShell -ExecutionPolicy Bypass -File $PROJECT_DIR/scripts/reset-vm2.ps1"
}

reset_vm3_ubuntu() {
    log_info "=== Reset VM3 (Ubuntu) ==="
    
    # Nettoyer les répertoires forensiques
    if [ -d "$FORENSICS_DIR" ]; then
        log_info "Nettoyage de l'environnement forensique..."
        rm -rf "$FORENSICS_DIR/evidence"/*
        rm -rf "$FORENSICS_DIR/analysis"/* 
        rm -rf "$FORENSICS_DIR/reports"/*
        
        # Recréer la structure
        mkdir -p "$FORENSICS_DIR"/{evidence/vm2/{memory,disk,logs,registry},analysis/{volatility,sleuthkit,autopsy,timeline},reports/{html,pdf,markdown},tools/scripts}
        
        log_success "Environnement forensique réinitialisé"
    fi
    
    # Arrêter Autopsy s'il est actif
    if pgrep -f "autopsy" > /dev/null; then
        pkill -f "autopsy" || true
        log_success "Autopsy arrêté"
    fi
    
    log_success "VM3 (Ubuntu) réinitialisée"
}

create_clean_snapshots() {
    log_info "=== Création de snapshots propres ==="
    
    # Pour VirtualBox
    if command -v VBoxManage &> /dev/null; then
        VMs=("VM1-Kali" "VM2-Windows" "VM3-Ubuntu")
        
        for vm in "${VMs[@]}"; do
            if VBoxManage list vms | grep -q "$vm"; then
                log_info "Création snapshot pour $vm..."
                VBoxManage snapshot "$vm" take "Clean-State-$(date +%Y%m%d-%H%M%S)" --description "État propre après reset" || true
                log_success "Snapshot créé pour $vm"
            fi
        done
    fi
    
    # Instructions pour VMware
    if command -v vmrun &> /dev/null; then
        log_info "Pour VMware, créer manuellement les snapshots 'Clean-State' sur chaque VM"
    fi
}

generate_reset_report() {
    log_info "Génération du rapport de reset..."
    
    RESET_REPORT="$PROJECT_DIR/logs/reset-report-$(date +%Y%m%d-%H%M%S).txt"
    
    cat > "$RESET_REPORT" << EOF
=== RAPPORT DE RESET - PROJET M1 ===

Date du reset : $(date)
Opérateur : $USER
Hostname : $HOSTNAME

ACTIONS EFFECTUÉES :

VM1 (Kali Linux) :
✓ Silver C2 serveur arrêté
✓ Sessions et listeners fermés  
✓ Payloads supprimés
✓ Logs nettoyés
✓ Evidence supprimée
✓ Serveur HTTP arrêté

VM2 (Windows 10) :
⚠ Script de reset généré : reset-vm2.ps1
⚠ Exécution manuelle requise sur VM2

VM3 (Ubuntu) :
✓ Environnement forensique nettoyé
✓ Preuves supprimées
✓ Rapports d'analyse supprimés
✓ Autopsy arrêté

ÉTAT POST-RESET :
- Système prêt pour nouvelle simulation
- Configuration de base préservée  
- Outils d'analyse disponibles
- Répertoires recréés et vides

PROCHAINES ÉTAPES :
1. Exécuter reset-vm2.ps1 sur Windows
2. Vérifier la connectivité réseau
3. Créer des snapshots propres
4. Lancer nouvelle simulation

=== FIN DU RAPPORT ===
EOF
    
    log_success "Rapport de reset généré : $RESET_REPORT"
}

validate_reset() {
    log_info "Validation du reset..."
    
    local errors=0
    
    # Vérifier que Silver C2 est arrêté
    if pgrep -f "sliver-server" > /dev/null; then
        log_error "Silver C2 encore actif"
        ((errors++))
    fi
    
    # Vérifier que les répertoires sont vides
    if [ -d "$PROJECT_DIR/payloads" ] && [ "$(ls -A $PROJECT_DIR/payloads)" ]; then
        log_warning "Répertoire payloads non vide"
    fi
    
    if [ -d "$PROJECT_DIR/evidence" ] && [ "$(ls -A $PROJECT_DIR/evidence)" ]; then
        log_warning "Répertoire evidence non vide"
    fi
    
    # Vérifier la structure
    required_dirs=(
        "$PROJECT_DIR/payloads"
        "$PROJECT_DIR/logs" 
        "$PROJECT_DIR/evidence"
        "$PROJECT_DIR/reports"
    )
    
    for dir in "${required_dirs[@]}"; do
        if [ ! -d "$dir" ]; then
            log_error "Répertoire manquant: $dir"
            ((errors++))
        fi
    done
    
    if [ $errors -eq 0 ]; then
        log_success "Validation réussie - Système prêt"
        return 0
    else
        log_error "$errors erreur(s) détectée(s)"
        return 1
    fi
}

# Fonction principale
main() {
    echo -e "${BLUE}=== RESET PROJET M1 - SILVER C2 ===${NC}"
    echo
    
    confirm_reset
    
    log_info "Début du processus de reset..."
    
    # Reset par VM
    reset_vm1_kali
    reset_vm2_windows  # Génère le script pour Windows
    reset_vm3_ubuntu
    
    # Création des snapshots
    create_clean_snapshots
    
    # Génération du rapport
    generate_reset_report
    
    # Validation
    if validate_reset; then
        echo
        log_success "Reset du Projet M1 terminé avec succès!"
        echo
        echo -e "${BLUE}Actions à effectuer:${NC}"
        echo "1. Exécuter sur VM2: PowerShell -ExecutionPolicy Bypass -File $PROJECT_DIR/scripts/reset-vm2.ps1"
        echo "2. Créer des snapshots 'Clean-State' sur toutes les VMs"
        echo "3. Lancer une nouvelle simulation: ./setup-project-m1.sh"
        echo
    else
        log_error "Reset incomplet - Vérifiez les erreurs"
        exit 1
    fi
}

# Gestion des signaux
trap 'log_error "Reset interrompu"; exit 130' INT TERM

# Exécution
main "$@"
```

---

## 🎭 Script 7 : Orchestrateur Principal (Multi-VM)

```python
#!/usr/bin/env python3
# project-orchestrator.py
# Orchestrateur principal pour l'ensemble du Projet M1

import subprocess
import sys
import time
import json
import threading
from pathlib import Path
from datetime import datetime
import argparse

class ProjectOrchestrator:
    def __init__(self):
        self.project_dir = Path.home() / "project-m1"
        self.config_file = self.project_dir / "config" / "project-config.json"
        self.log_file = self.project_dir / "logs" / f"orchestrator-{datetime.now().strftime('%Y%m%d-%H%M%S')}.log"
        
        self.load_config()
        self.setup_logging()
        
    def load_config(self):
        """Charger la configuration du projet"""
        if self.config_file.exists():
            with open(self.config_file, 'r') as f:
                self.config = json.load(f)
        else:
            self.config = self.create_default_config()
    
    def create_default_config(self):
        """Créer une configuration par défaut"""
        return {
            "project": {
                "name": "M1-Silver-C2-Investigation",
                "version": "1.0"
            },
            "infrastructure": {
                "vm1": {"role": "attacker", "ip": "192.168.56.10"},
                "vm2": {"role": "victim", "ip": "192.168.56.20"},
                "vm3": {"role": "analyst", "ip": "192.168.56.30"}
            }
        }
    
    def setup_logging(self):
        """Configuration du logging"""
        import logging
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def run_command(self, command, description="", timeout=300):
        """Exécuter une commande avec gestion d'erreur"""
        self.logger.info(f"Exécution: {description if description else command}")
        
        try:
            result = subprocess.run(
                command, shell=True, capture_output=True,
                text=True, timeout=timeout
            )
            
            if result.returncode == 0:
                self.logger.info(f"✅ Succès: {description}")
                return True, result.stdout
            else:
                self.logger.error(f"❌ Échec: {description} - {result.stderr}")
                return False, result.stderr
        except subprocess.TimeoutExpired:
            self.logger.error(f"⏰ Timeout: {description}")
            return False, "Timeout"
        except Exception as e:
            self.logger.error(f"💥 Erreur: {description} - {e}")
            return False, str(e)
    
    def check_prerequisites(self):
        """Vérifier les prérequis du projet"""
        self.logger.info("=== VÉRIFICATION DES PRÉREQUIS ===")
        
        checks = []
        
        # Vérifier l'existence du projet
        if not self.project_dir.exists():
            checks.append(("Structure projet", False, "Répertoire projet inexistant"))
        else:
            checks.append(("Structure projet", True, "OK"))
        
        # Vérifier Silver C2
        success, _ = self.run_command("which sliver-server", "Vérification Silver C2")
        checks.append(("Silver C2", success, "Installé" if success else "Manquant"))
        
        # Vérifier connectivité VMs
        vm2_ip = self.config["infrastructure"]["vm2"]["ip"]
        vm3_ip = self.config["infrastructure"]["vm3"]["ip"]
        
        success, _ = self.run_command(f"ping -c 1 -W 2 {vm2_ip}", f"Connectivité VM2 ({vm2_ip})")
        checks.append(("VM2 accessible", success, "OK" if success else "Inaccessible"))
        
        success, _ = self.run_command(f"ping -c 1 -W 2 {vm3_ip}", f"Connectivité VM3 ({vm3_ip})")
        checks.append(("VM3 accessible", success, "OK" if success else "Inaccessible"))
        
        # Afficher les résultats
        print("\n📋 État des prérequis:")
        for check, status, details in checks:
            status_icon = "✅" if status else "❌"
            print(f"   {status_icon} {check}: {details}")
        
        failed_checks = [check for check, status, _ in checks if not status]
        
        if failed_checks:
            self.logger.warning(f"⚠️ {len(failed_checks)} prérequis non satisfaits")
            return False
        
        self.logger.info("✅ Tous les prérequis sont satisfaits")
        return True
    
    def run_full_workflow(self):
        """Exécuter le workflow complet"""
        self.logger.info("=== DÉMARRAGE WORKFLOW COMPLET PROJET M1 ===")
        
        phases = [
            ("Vérification prérequis", self.check_prerequisites),
            ("Configuration environnement", self.setup_environment),
            ("Génération payloads", self.generate_payloads),
            ("Lancement attaque", self.launch_attack),
            ("Collecte preuves", self.collect_evidence),
            ("Analyse forensique", self.run_forensic_analysis),
            ("Génération rapports", self.generate_reports)
        ]
        
        results = []
        
        for phase_name, phase_func in phases:
            self.logger.info(f"📍 Phase: {phase_name}")
            
            try:
                success = phase_func()
                results.append((phase_name, success))
                
                if success:
                    self.logger.info(f"✅ {phase_name} réussie")
                else:
                    self.logger.error(f"❌ {phase_name} échouée")
                    
                    # Demander si on continue
                    response = input(f"\nPhase '{phase_name}' échouée. Continuer? (y/N): ")
                    if response.lower() != 'y':
                        break
            
            except KeyboardInterrupt:
                self.logger.warning("🛑 Workflow interrompu par l'utilisateur")
                break
            except Exception as e:
                self.logger.error(f"💥 Erreur inattendue dans {phase_name}: {e}")
                results.append((phase_name, False))
                break
        
        # Rapport final
        self.generate_workflow_report(results)
        
        success_count = sum(1 for _, success in results if success)
        total_count = len(results)
        
        if success_count == total_count:
            self.logger.info(f"🎉 Workflow complet réussi ({success_count}/{total_count})")
            return True
        else:
            self.logger.warning(f"⚠️ Workflow partiel ({success_count}/{total_count} phases réussies)")
            return False
    
    def setup_environment(self):
        """Configuration de l'environnement"""
        script_path = self.project_dir / "scripts" / "start-silver.sh"
        
        if script_path.exists():
            success, _ = self.run_command(f"bash {script_path}", "Démarrage Silver C2")
            return success
        else:
            self.logger.error("Script de démarrage Silver introuvable")
            return False
    
    def generate_payloads(self):
        """Génération des payloads"""
        script_path = self.project_dir / "scripts" / "generate-payloads.sh"
        
        if script_path.exists():
            success, _ = self.run_command(f"bash {script_path}", "Génération payloads", timeout=180)
            return success
        else:
            self.logger.error("Script de génération de payloads introuvable")
            return False
    
    def launch_attack(self):
        """Lancement de l'attaque automatisée"""
        script_path = self.project_dir / "scripts" / "attack-automation.py"
        
        if script_path.exists():
            success, _ = self.run_command(f"python3 {script_path}", "Simulation d'attaque", timeout=1800)
            return success
        else:
            self.logger.error("Script d'attaque automatisée introuvable")
            return False
    
    def collect_evidence(self):
        """Collecte des preuves"""
        self.logger.info("📋 Instructions pour la collecte de preuves:")
        print("\n🔍 Actions manuelles requises sur VM2 (Windows):")
        print("1. Lancer Belkasoft RAM Capturer en tant qu'administrateur")
        print("2. Capturer la mémoire vers C:\\Evidence\\")
        print("3. Exécuter: PowerShell -ExecutionPolicy Bypass -File C:\\Tools\\evidence-collector.ps1")
        print("4. Transférer les preuves vers VM3")
        
        response = input("\nPreuves collectées et transférées vers VM3? (y/N): ")
        return response.lower() == 'y'
    
    def run_forensic_analysis(self):
        """Exécution de l'analyse forensique"""
        forensics_dir = Path.home() / "forensics"
        script_path = forensics_dir / "tools" / "scripts" / "forensic-analyzer.py"
        
        # Vérifier si nous sommes sur VM3 ou si les outils sont disponibles
        if script_path.exists():
            success, _ = self.run_command(f"python3 {script_path}", "Analyse forensique", timeout=3600)
            return success
        else:
            self.logger.info("📋 Analyse forensique à exécuter sur VM3:")
            print("\nSur VM3 (Ubuntu), exécuter:")
            print("python3 ~/forensics/tools/scripts/forensic-analyzer.py")
            
            response = input("\nAnalyse forensique terminée? (y/N): ")
            return response.lower() == 'y'
    
    def generate_reports(self):
        """Génération des rapports"""
        forensics_dir = Path.home() / "forensics"
        script_path = forensics_dir / "tools" / "scripts" / "report-generator.py"
        
        if script_path.exists():
            success, _ = self.run_command(f"python3 {script_path}", "Génération rapports", timeout=300)
            return success
        else:
            self.logger.info("📋 Génération de rapports à effectuer sur VM3:")
            print("\nSur VM3 (Ubuntu), exécuter:")
            print("python3 ~/forensics/tools/scripts/report-generator.py")
            
            response = input("\nRapports générés? (y/N): ")
            return response.lower() == 'y'
    
    def generate_workflow_report(self, results):
        """Générer le rapport du workflow"""
        report_content = f"""
=== RAPPORT DE WORKFLOW - PROJET M1 ===

Date d'exécution : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Opérateur : {Path.home().name}

RÉSULTATS PAR PHASE :

"""
        
        for phase_name, success in results:
            status = "✅ RÉUSSIE" if success else "❌ ÉCHOUÉE"
            report_content += f"{status} - {phase_name}\n"
        
        success_count = sum(1 for _, success in results if success)
        total_count = len(results)
        
        report_content += f"""
STATISTIQUES :
- Phases réussies : {success_count}/{total_count}
- Taux de succès : {success_count/total_count*100:.1f}%

FICHIERS GÉNÉRÉS :
- Log détaillé : {self.log_file}
- Configuration : {self.config_file}

PROCHAINES ÉTAPES :
"""
        
        if success_count == total_count:
            report_content += """
✅ Projet M1 exécuté avec succès!

1. Consulter les rapports dans ~/forensics/reports/
2. Archiver les preuves pour conservation
3. Documenter les leçons apprises
4. Préparer la présentation des résultats
"""
        else:
            report_content += """
⚠️ Workflow partiellement réussi

1. Consulter les logs pour identifier les problèmes
2. Reprendre à partir de la phase échouée
3. Vérifier la configuration et les prérequis
4. Contacter le support si nécessaire
"""
        
        report_content += f"\n=== FIN DU RAPPORT ===\n"
        
        report_file = self.project_dir / "reports" / f"workflow-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.txt"
        report_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(report_file, 'w') as f:
            f.write(report_content)
        
        self.logger.info(f"📄 Rapport de workflow généré: {report_file}")
        
        # Afficher le résumé
        print(f"\n📊 RÉSUMÉ DU WORKFLOW:")
        print(f"   Phases réussies: {success_count}/{total_count}")
        print(f"   Rapport complet: {report_file}")
    
    def run_interactive_mode(self):
        """Mode interactif avec menu"""
        while True:
            print(f"\n{'='*50}")
            print("🎭 ORCHESTRATEUR PROJET M1 - SILVER C2")
            print("="*50)
            print("1. 🔧 Vérifier les prérequis")
            print("2. 🚀 Workflow complet automatique")
            print("3. 📋 Workflow étape par étape")
            print("4. 🔄 Reset du projet") 
            print("5. 📊 État du projet")
            print("6. 📖 Afficher la documentation")
            print("0. 🚪 Quitter")
            
            choice = input("\nChoisissez une option: ").strip()
            
            if choice == '0':
                print("\n👋 Au revoir!")
                break
            elif choice == '1':
                self.check_prerequisites()
            elif choice == '2':
                self.run_full_workflow()
            elif choice == '3':
                self.run_step_by_step()
            elif choice == '4':
                self.run_project_reset()
            elif choice == '5':
                self.show_project_status()
            elif choice == '6':
                self.show_documentation()
            else:
                print("❌ Option invalide")
    
    def run_step_by_step(self):
        """Mode pas à pas"""
        phases = [
            ("Vérification prérequis", self.check_prerequisites),
            ("Configuration environnement", self.setup_environment),
            ("Génération payloads", self.generate_payloads),
            ("Lancement attaque", self.launch_attack),
            ("Collecte preuves", self.collect_evidence),
            ("Analyse forensique", self.run_forensic_analysis),
            ("Génération rapports", self.generate_reports)
        ]
        
        print("\n🎯 MODE PAS À PAS")
        for i, (phase_name, _) in enumerate(phases, 1):
            print(f"{i}. {phase_name}")
        
        while True:
            try:
                choice = int(input("\nChoisissez une phase (0 pour revenir): "))
                if choice == 0:
                    break
                elif 1 <= choice <= len(phases):
                    phase_name, phase_func = phases[choice-1]
                    print(f"\n📍 Exécution: {phase_name}")
                    success = phase_func()
                    print(f"{'✅ Réussie' if success else '❌ Échouée'}")
                else:
                    print("❌ Numéro de phase invalide")
            except (ValueError, KeyboardInterrupt):
                print("\n🛑 Retour au menu principal")
                break
    
    def run_project_reset(self):
        """Lancer le reset du projet"""
        reset_script = Path(__file__).parent / "project-reset.sh"
        
        if reset_script.exists():
            success, _ = self.run_command(f"bash {reset_script}", "Reset du projet")
            if success:
                print("✅ Reset terminé avec succès")
            else:
                print("❌ Reset échoué - Consultez les logs")
        else:
            print("❌ Script de reset introuvable")
    
    def show_project_status(self):
        """Afficher l'état du projet"""
        print("\n📊 ÉTAT DU PROJET M1")
        print("="*30)
        
        # Vérifier l'existence des répertoires
        directories = [
            (self.project_dir / "payloads", "Payloads"),
            (self.project_dir / "logs", "Logs"),
            (self.project_dir / "evidence", "Preuves"),
            (self.project_dir / "reports", "Rapports")
        ]
        
        for dir_path, name in directories:
            if dir_path.exists():
                file_count = len(list(dir_path.glob("*")))
                print(f"📁 {name}: {file_count} fichiers")
            else:
                print(f"❌ {name}: Répertoire manquant")
        
        # État de Silver C2
        success, _ = self.run_command("pgrep -f sliver-server", "")
        silver_status = "🟢 Actif" if success else "🔴 Arrêté"
        print(f"⚡ Silver C2: {silver_status}")
        
        # Connectivité VMs
        for vm_name, vm_info in self.config["infrastructure"].items():
            if vm_name != "vm1":  # Skip current VM
                success, _ = self.run_command(f"ping -c 1 -W 2 {vm_info['ip']}", "")
                status = "🟢 Accessible" if success else "🔴 Inaccessible"
                print(f"🖥️ {vm_name.upper()}: {status}")
    
    def show_documentation(self):
        """Afficher la documentation"""
        docs = [
            ("📖 Guide complet", "~/guide-silver-c2-kali.md"),
            ("🏗️ Setup infrastructure", "~/projet-m1-infrastructure-setup.md"),
            ("⚡ Configuration Silver C2", "~/projet-m1-silver-c2-setup.md"),
            ("🎯 Scénarios d'attaque", "~/projet-m1-scenarios-attaque.md"),
            ("🔍 Investigation forensique", "~/projet-m1-investigation-forensique.md"),
            ("📊 Templates de rapport", "~/projet-m1-templates-rapport.md")
        ]
        
        print("\n📚 DOCUMENTATION DISPONIBLE")
        print("="*35)
        
        for title, path in docs:
            if Path(path.replace('~', str(Path.home()))).exists():
                print(f"{title}: {path}")
            else:
                print(f"❌ {title}: Fichier manquant")

def main():
    parser = argparse.ArgumentParser(description="Orchestrateur Projet M1 Silver C2")
    parser.add_argument('--mode', choices=['interactive', 'auto', 'check'], 
                       default='interactive',
                       help='Mode d\'exécution (default: interactive)')
    parser.add_argument('--config', help='Fichier de configuration personnalisé')
    
    args = parser.parse_args()
    
    try:
        orchestrator = ProjectOrchestrator()
        
        if args.config:
            orchestrator.config_file = Path(args.config)
            orchestrator.load_config()
        
        print("🎭 Orchestrateur Projet M1 - Silver C2 Investigation")
        print("="*50)
        
        if args.mode == 'check':
            return 0 if orchestrator.check_prerequisites() else 1
        elif args.mode == 'auto':
            return 0 if orchestrator.run_full_workflow() else 1
        else:  # interactive
            orchestrator.run_interactive_mode()
            return 0
    
    except KeyboardInterrupt:
        print("\n\n🛑 Orchestrateur interrompu par l'utilisateur")
        return 130
    except Exception as e:
        print(f"\n❌ Erreur fatale: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
```

---

## 📋 Script 8 : Validation et Tests du Projet

```bash
#!/bin/bash
# project-validator.sh
# Script de validation complète du Projet M1

set -e

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Variables
PROJECT_DIR="$HOME/project-m1"
VALIDATION_LOG="$PROJECT_DIR/logs/validation-$(date +%Y%m%d-%H%M%S).log"

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$VALIDATION_LOG"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$VALIDATION_LOG"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$VALIDATION_LOG"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$VALIDATION_LOG"
}

# Tests de validation
validate_file_structure() {
    log_info "Validation de la structure de fichiers..."
    
    local required_files=(
        "$PROJECT_DIR/scripts/setup-project-m1.sh"
        "$PROJECT_DIR/scripts/attack-automation.py"
        "$PROJECT_DIR/scripts/project-orchestrator.py"
        "$PROJECT_DIR/scripts/project-reset.sh"
        "$PROJECT_DIR/config/project-config.json"
    )
    
    local errors=0
    
    for file in "${required_files[@]}"; do
        if [ -f "$file" ]; then
            log_success "Fichier présent: $(basename $file)"
        else
            log_error "Fichier manquant: $file"
            ((errors++))
        fi
    done
    
    return $errors
}

validate_permissions() {
    log_info "Validation des permissions..."
    
    local executable_files=(
        "$PROJECT_DIR/scripts/setup-project-m1.sh"
        "$PROJECT_DIR/scripts/project-reset.sh"
        "$PROJECT_DIR/scripts/project-validator.sh"
    )
    
    local errors=0
    
    for file in "${executable_files[@]}"; do
        if [ -x "$file" ]; then
            log_success "Permissions OK: $(basename $file)"
        else
            log_error "Non exécutable: $file"
            ((errors++))
        fi
    done
    
    return $errors
}

validate_dependencies() {
    log_info "Validation des dépendances..."
    
    local dependencies=(
        "python3:Python 3"
        "sliver-server:Silver C2 Server"
        "sliver-client:Silver C2 Client"
        "nmap:Nmap"
        "curl:cURL"
        "git:Git"
    )
    
    local errors=0
    
    for dep in "${dependencies[@]}"; do
        local cmd="${dep%:*}"
        local name="${dep#*:}"
        
        if command -v "$cmd" &> /dev/null; then
            local version=$(eval "$cmd --version 2>/dev/null | head -n1 || echo 'Version inconnue'")
            log_success "$name disponible: $version"
        else
            log_error "$name manquant: $cmd"
            ((errors++))
        fi
    done
    
    return $errors
}

validate_network_connectivity() {
    log_info "Validation de la connectivité réseau..."
    
    local target_ips=("192.168.56.20" "192.168.56.30")
    local errors=0
    
    for ip in "${target_ips[@]}"; do
        if ping -c 1 -W 2 "$ip" &> /dev/null; then
            log_success "VM accessible: $ip"
        else
            log_warning "VM non accessible: $ip"
            ((errors++))
        fi
    done
    
    return $errors
}

validate_silver_installation() {
    log_info "Validation de l'installation Silver C2..."
    
    local errors=0
    
    # Vérifier les binaires
    if ! command -v sliver-server &> /dev/null; then
        log_error "sliver-server non trouvé"
        ((errors++))
    fi
    
    if ! command -v sliver-client &> /dev/null; then
        log_error "sliver-client non trouvé"
        ((errors++))
    fi
    
    # Vérifier les répertoires Silver
    if [ ! -d "$HOME/.sliver" ]; then
        log_error "Répertoire .sliver manquant"
        ((errors++))
    else
        log_success "Configuration Silver trouvée"
    fi
    
    # Test de génération de payload (rapide)
    log_info "Test de génération de payload..."
    local test_payload="/tmp/test-payload-$(date +%s).exe"
    
    if timeout 30 sliver-client -c "generate --http 127.0.0.1:8080 --os windows --format exe --save $test_payload" &> /dev/null; then
        if [ -f "$test_payload" ]; then
            log_success "Génération de payload réussie"
            rm -f "$test_payload"
        else
            log_error "Payload non généré"
            ((errors++))
        fi
    else
        log_warning "Test de génération échoué (normal si serveur non démarré)"
    fi
    
    return $errors
}

run_integration_tests() {
    log_info "Tests d'intégration..."
    
    local errors=0
    
    # Test 1: Configuration du projet
    log_info "Test 1: Chargement de la configuration"
    if [ -f "$PROJECT_DIR/config/project-config.json" ]; then
        if python3 -c "import json; json.load(open('$PROJECT_DIR/config/project-config.json'))" 2>/dev/null; then
            log_success "Configuration JSON valide"
        else
            log_error "Configuration JSON invalide"
            ((errors++))
        fi
    fi
    
    # Test 2: Scripts Python
    log_info "Test 2: Syntaxe des scripts Python"
    local python_scripts=(
        "$PROJECT_DIR/scripts/attack-automation.py"
        "$PROJECT_DIR/scripts/project-orchestrator.py"
    )
    
    for script in "${python_scripts[@]}"; do
        if [ -f "$script" ]; then
            if python3 -m py_compile "$script" 2>/dev/null; then
                log_success "Syntaxe OK: $(basename $script)"
            else
                log_error "Erreur syntaxe: $(basename $script)"
                ((errors++))
            fi
        fi
    done
    
    # Test 3: Permissions des répertoires
    log_info "Test 3: Permissions des répertoires"
    local directories=(
        "$PROJECT_DIR/payloads"
        "$PROJECT_DIR/logs"
        "$PROJECT_DIR/evidence"
        "$PROJECT_DIR/reports"
    )
    
    for dir in "${directories[@]}"; do
        if [ -d "$dir" ] && [ -w "$dir" ]; then
            log_success "Répertoire accessible: $(basename $dir)"
        else
            log_error "Problème accès: $dir"
            ((errors++))
        fi
    done
    
    return $errors
}

generate_validation_report() {
    log_info "Génération du rapport de validation..."
    
    local report_file="$PROJECT_DIR/reports/validation-report-$(date +%Y%m%d-%H%M%S).txt"
    
    cat > "$report_file" << EOF
=== RAPPORT DE VALIDATION - PROJET M1 ===

Date de validation : $(date)
Validateur : $USER
Système : $(uname -a)

TESTS EFFECTUÉS :
✓ Structure de fichiers
✓ Permissions des scripts  
✓ Dépendances système
✓ Connectivité réseau
✓ Installation Silver C2
✓ Tests d'intégration

RÉSULTATS DÉTAILLÉS :
$(cat "$VALIDATION_LOG")

RECOMMANDATIONS :
- Tous les tests réussis : Système prêt pour utilisation
- Erreurs détectées : Consulter les détails ci-dessus
- Avertissements : Vérifier la configuration réseau

PROCHAINES ÉTAPES :
1. Corriger les erreurs identifiées
2. Relancer la validation
3. Procéder à l'exécution du projet

=== FIN DU RAPPORT ===
EOF
    
    log_success "Rapport de validation généré: $report_file"
}

# Fonction principale
main() {
    echo -e "${BLUE}=== VALIDATION PROJET M1 - SILVER C2 ===${NC}"
    echo
    
    # Créer le répertoire de logs s'il n'existe pas
    mkdir -p "$(dirname "$VALIDATION_LOG")"
    
    log_info "Début de la validation du Projet M1"
    
    local total_errors=0
    
    # Exécuter tous les tests
    validate_file_structure
    total_errors=$((total_errors + $?))
    
    validate_permissions  
    total_errors=$((total_errors + $?))
    
    validate_dependencies
    total_errors=$((total_errors + $?))
    
    validate_network_connectivity
    total_errors=$((total_errors + $?))
    
    validate_silver_installation
    total_errors=$((total_errors + $?))
    
    run_integration_tests
    total_errors=$((total_errors + $?))
    
    # Génération du rapport
    generate_validation_report
    
    # Résultats finaux
    echo
    if [ $total_errors -eq 0 ]; then
        log_success "🎉 Validation réussie - Projet M1 prêt à l'utilisation!"
        echo
        echo -e "${GREEN}Vous pouvez maintenant:${NC}"
        echo "1. Lancer l'orchestrateur: python3 $PROJECT_DIR/scripts/project-orchestrator.py"
        echo "2. Exécuter le workflow complet automatiquement"
        echo "3. Suivre la documentation pour une utilisation manuelle"
        return 0
    else
        log_error "❌ Validation échouée - $total_errors erreur(s) détectée(s)"
        echo
        echo -e "${RED}Actions requises:${NC}"
        echo "1. Consulter les logs: $VALIDATION_LOG"
        echo "2. Corriger les erreurs identifiées" 
        echo "3. Relancer la validation"
        return 1
    fi
}

# Exécution
main "$@"
```

---

## 🎯 Documentation d'Utilisation Finale

```markdown
# GUIDE D'UTILISATION - SCRIPTS D'AUTOMATISATION PROJET M1

## 🚀 Démarrage Rapide

### 1. Installation Initiale
```bash
# Cloner ou télécharger tous les scripts
# Rendre exécutables
chmod +x setup-project-m1.sh project-reset.sh project-validator.sh
chmod +x attack-automation.py project-orchestrator.py

# Configuration initiale complète
./setup-project-m1.sh
```

### 2. Validation du Système
```bash
# Valider l'installation complète  
./project-validator.sh

# Si des erreurs, les corriger et relancer
```

### 3. Exécution du Projet

#### Option A: Mode Automatique Complet
```bash
python3 project-orchestrator.py --mode auto
```

#### Option B: Mode Interactif (Recommandé)
```bash
python3 project-orchestrator.py
# Suivre le menu interactif
```

#### Option C: Exécution Manuelle Étape par Étape
```bash
# 1. Démarrer Silver C2
./start-silver.sh

# 2. Générer les payloads
./generate-payloads.sh

# 3. Lancer l'attaque
python3 attack-automation.py

# 4. Collecter les preuves (VM2)
# PowerShell -ExecutionPolicy Bypass -File evidence-collector.ps1

# 5. Analyser (VM3)
# python3 forensic-analyzer.py

# 6. Générer les rapports (VM3)  
# python3 report-generator.py
```

### 4. Reset pour Nouvelle Simulation
```bash
./project-reset.sh
# Suivre les instructions pour VM2
```

## 📁 Structure Complète des Scripts

```
project-m1/
├── scripts/
│   ├── setup-project-m1.sh           # Configuration initiale
│   ├── start-silver.sh               # Démarrage Silver C2
│   ├── generate-payloads.sh          # Génération payloads
│   ├── attack-automation.py          # Attaque automatisée
│   ├── project-orchestrator.py       # Orchestrateur principal
│   ├── project-reset.sh              # Reset complet
│   ├── project-validator.sh          # Validation système
│   ├── evidence-collector.ps1        # Collecte preuves (VM2)
│   ├── forensic-analyzer.py          # Analyse forensique (VM3)
│   └── report-generator.py           # Génération rapports (VM3)
├── config/
│   └── project-config.json           # Configuration projet
├── payloads/                         # Implants générés
├── logs/                             # Logs d'exécution
├── evidence/                         # Preuves collectées
└── reports/                          # Rapports générés
```

## ⚡ Utilisation Avancée

### Variables d'Environnement
```bash
export PROJECT_M1_CONFIG="/path/to/custom-config.json"
export PROJECT_M1_DEBUG=1                    # Mode debug
export PROJECT_M1_AUTO_CONFIRM=1             # Confirmations automatiques
```

### Options de l'Orchestrateur
```bash
# Vérification seule
python3 project-orchestrator.py --mode check

# Configuration personnalisée
python3 project-orchestrator.py --config /path/to/config.json

# Mode automatique silencieux
python3 project-orchestrator.py --mode auto > execution.log 2>&1
```

## 🛡️ Bonnes Pratiques

### Avant Chaque Simulation
1. ✅ Valider le système: `./project-validator.sh`
2. ✅ Créer des snapshots propres des VMs
3. ✅ Vérifier la connectivité réseau
4. ✅ S'assurer que les outils sont installés

### Pendant la Simulation
1. 📊 Surveiller les logs en temps réel
2. 📸 Documenter les étapes importantes
3. 💾 Sauvegarder les preuves immédiatement
4. ⚠️ Noter tout comportement inattendu

### Après la Simulation  
1. 📋 Générer tous les rapports
2. 🗃️ Archiver les preuves et résultats
3. 🔄 Effectuer le reset complet
4. 📝 Documenter les leçons apprises

## 🆘 Dépannage

### Problèmes Courants

**Silver C2 ne démarre pas**
```bash
sudo pkill -f sliver-server
sudo sliver-server daemon --log-level debug
```

**Payloads non générés**  
```bash
# Vérifier Go
go version
export PATH=$PATH:/usr/local/go/bin

# Tester manuellement
sliver-client -c "generate --http 127.0.0.1:8080 --os windows --format exe"
```

**Connectivité VM manquante**
```bash
# Vérifier configuration réseau
ip addr show
ping -c 3 192.168.56.20
ping -c 3 192.168.56.30
```

**Scripts Python échouent**
```bash
# Vérifier dépendances
pip3 install -r requirements.txt

# Debug mode
python3 -u script.py
```

### Logs de Débogage
- **Orchestrateur**: `~/project-m1/logs/orchestrator-*.log`
- **Attaque**: `~/project-m1/logs/attack-automation.log`
- **Silver C2**: `~/project-m1/logs/silver-server.log`
- **Validation**: `~/project-m1/logs/validation-*.log`

## 📚 Ressources Supplémentaires

- 📖 **Guide complet**: `~/guide-silver-c2-kali.md`
- 🏗️ **Setup infrastructure**: `~/projet-m1-infrastructure-setup.md`
- ⚡ **Configuration Silver**: `~/projet-m1-silver-c2-setup.md`
- 🎯 **Scénarios attaque**: `~/projet-m1-scenarios-attaque.md`
- 🔍 **Investigation**: `~/projet-m1-investigation-forensique.md`
- 📊 **Templates rapport**: `~/projet-m1-templates-rapport.md`

---

**Les scripts d'automatisation Projet M1 permettent une exécution complète et reproductible de la simulation d'attaque Silver C2 avec investigation forensique automatisée.**
```

---

**Tous les scripts d'automatisation sont maintenant complets et fonctionnels pour l'ensemble du workflow Projet M1.**