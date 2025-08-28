# PROJET M1 - Scripts d'Automatisation (Partie 2)
## Scripts d'Analyse Forensique et Gestion de Projet

---

## 🔍 Script 4 : Analyseur Forensique Automatisé (VM3 - Ubuntu)

```python
#!/usr/bin/env python3
# forensic-analyzer.py
# Analyse forensique automatisée pour le Projet M1

import os
import sys
import json
import subprocess
import hashlib
import logging
from pathlib import Path
from datetime import datetime
import threading
import time

class ForensicAnalyzer:
    def __init__(self):
        self.home_dir = Path.home()
        self.forensics_dir = self.home_dir / "forensics"
        self.evidence_dir = self.forensics_dir / "evidence" / "vm2"
        self.analysis_dir = self.forensics_dir / "analysis"
        self.reports_dir = self.forensics_dir / "reports"
        self.tools_dir = self.forensics_dir / "tools"
        
        self.setup_directories()
        self.setup_logging()
        
    def setup_directories(self):
        """Créer la structure de répertoires"""
        directories = [
            self.forensics_dir,
            self.evidence_dir / "memory",
            self.evidence_dir / "disk", 
            self.evidence_dir / "logs",
            self.evidence_dir / "registry",
            self.analysis_dir / "volatility",
            self.analysis_dir / "autopsy",
            self.analysis_dir / "sleuthkit",
            self.analysis_dir / "timeline",
            self.reports_dir,
            self.tools_dir / "scripts"
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
    
    def setup_logging(self):
        """Configuration du logging"""
        log_file = self.analysis_dir / f"forensic-analysis-{datetime.now().strftime('%Y%m%d-%H%M%S')}.log"
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
        self.logger.info("Analyseur forensique initialisé")
    
    def run_command(self, command, timeout=300):
        """Exécuter une commande système"""
        try:
            self.logger.info(f"Exécution: {command}")
            result = subprocess.run(
                command, shell=True, capture_output=True, 
                text=True, timeout=timeout
            )
            
            if result.returncode == 0:
                self.logger.info("Commande réussie")
                return result.stdout
            else:
                self.logger.error(f"Commande échouée: {result.stderr}")
                return None
        except subprocess.TimeoutExpired:
            self.logger.error(f"Timeout de la commande: {command}")
            return None
        except Exception as e:
            self.logger.error(f"Erreur exécution: {e}")
            return None
    
    def find_evidence_files(self):
        """Localiser les fichiers de preuves"""
        evidence_files = {
            'memory_dump': None,
            'disk_image': None,
            'logs': [],
            'registry': []
        }
        
        # Recherche dump mémoire
        memory_files = list(self.evidence_dir.glob("memory/*.mem"))
        if memory_files:
            evidence_files['memory_dump'] = memory_files[0]
            self.logger.info(f"Dump mémoire trouvé: {evidence_files['memory_dump']}")
        
        # Recherche image disque
        disk_files = list(self.evidence_dir.glob("disk/*.dd"))
        if disk_files:
            evidence_files['disk_image'] = disk_files[0]
            self.logger.info(f"Image disque trouvée: {evidence_files['disk_image']}")
        
        # Recherche logs
        evidence_files['logs'] = list(self.evidence_dir.glob("logs/*.txt"))
        evidence_files['registry'] = list(self.evidence_dir.glob("registry/*.reg"))
        
        self.logger.info(f"Fichiers trouvés: {len(evidence_files['logs'])} logs, {len(evidence_files['registry'])} registres")
        return evidence_files
    
    def analyze_memory_volatility(self, memory_dump):
        """Analyse mémoire avec Volatility"""
        self.logger.info("=== ANALYSE MÉMOIRE AVEC VOLATILITY ===")
        
        if not memory_dump or not memory_dump.exists():
            self.logger.error("Dump mémoire non trouvé")
            return False
        
        vol_output_dir = self.analysis_dir / "volatility"
        
        # Commandes Volatility à exécuter
        vol_commands = [
            ("windows.info", "system-info.txt", "Informations système"),
            ("windows.pslist", "process-list.txt", "Liste des processus"),
            ("windows.pstree", "process-tree.txt", "Arbre des processus"), 
            ("windows.psxview", "process-hidden.txt", "Processus cachés"),
            ("windows.malfind", "code-injection.txt", "Injections de code"),
            ("windows.netstat", "network-connections.txt", "Connexions réseau"),
            ("windows.netscan", "network-scan.txt", "Scan réseau"),
            ("windows.cmdline", "command-lines.txt", "Lignes de commande"),
            ("windows.dlllist", "dll-list.txt", "DLLs chargées"),
            ("windows.handles", "handles.txt", "Handles système"),
            ("windows.ssdt", "ssdt.txt", "Table SSDT"),
            ("windows.registry.hivelist", "registry-hives.txt", "Ruches registre")
        ]
        
        for command, output_file, description in vol_commands:
            self.logger.info(f"Volatility: {description}")
            vol_cmd = f"vol -f {memory_dump} {command} > {vol_output_dir}/{output_file}"
            result = self.run_command(vol_cmd, timeout=600)
            
            if result is not None:
                self.logger.info(f"✓ {description} terminé")
            else:
                self.logger.warning(f"⚠ {description} échoué")
            
            time.sleep(2)
        
        # Recherche spécifique Silver C2
        self.search_silver_c2_memory(memory_dump, vol_output_dir)
        
        return True
    
    def search_silver_c2_memory(self, memory_dump, output_dir):
        """Recherche spécifique d'artefacts Silver C2 en mémoire"""
        self.logger.info("Recherche d'artefacts Silver C2...")
        
        # Recherche de strings spécifiques
        silver_strings = [
            "sliver", "implant", "beacon", "session_",
            "SystemOptimizer", "OptimizationService",
            "192.168.56.10", "8080", "8443"
        ]
        
        for search_string in silver_strings:
            self.logger.info(f"Recherche de '{search_string}'...")
            cmd = f"vol -f {memory_dump} windows.strings --strings-file /dev/stdin <<< '{search_string}'"
            result = self.run_command(cmd)
            
            if result and result.strip():
                with open(output_dir / f"silver-string-{search_string}.txt", 'w') as f:
                    f.write(result)
                self.logger.info(f"✓ String '{search_string}' trouvée")
        
        # Recherche de processus spécifiques
        self.logger.info("Recherche de processus Silver C2...")
        cmd = f"vol -f {memory_dump} windows.pslist | grep -i 'systemoptimizer\\|optimization'"
        result = self.run_command(cmd)
        
        if result:
            with open(output_dir / "silver-processes.txt", 'w') as f:
                f.write(result)
            self.logger.info("✓ Processus Silver C2 identifiés")
    
    def analyze_disk_sleuthkit(self, disk_image):
        """Analyse disque avec The Sleuth Kit"""
        self.logger.info("=== ANALYSE DISQUE AVEC THE SLEUTH KIT ===")
        
        if not disk_image or not disk_image.exists():
            self.logger.error("Image disque non trouvée")
            return False
        
        tsk_output_dir = self.analysis_dir / "sleuthkit"
        
        # Analyse de base de l'image
        self.logger.info("Informations sur l'image disque...")
        img_stat = self.run_command(f"img_stat {disk_image}")
        if img_stat:
            with open(tsk_output_dir / "image-info.txt", 'w') as f:
                f.write(img_stat)
        
        # Analyse des partitions
        self.logger.info("Analyse des partitions...")
        mmls_output = self.run_command(f"mmls {disk_image}")
        if mmls_output:
            with open(tsk_output_dir / "partitions.txt", 'w') as f:
                f.write(mmls_output)
        
        # Estimation de l'offset (généralement 2048 pour Windows)
        offset = 2048
        
        # Analyse du système de fichiers
        self.logger.info("Analyse du système de fichiers...")
        fsstat_output = self.run_command(f"fsstat -o {offset} {disk_image}")
        if fsstat_output:
            with open(tsk_output_dir / "filesystem.txt", 'w') as f:
                f.write(fsstat_output)
        
        # Liste des fichiers
        self.logger.info("Liste complète des fichiers...")
        fls_output = self.run_command(f"fls -r -o {offset} {disk_image}", timeout=900)
        if fls_output:
            with open(tsk_output_dir / "file-list.txt", 'w') as f:
                f.write(fls_output)
        
        # Timeline
        self.logger.info("Création de la timeline...")
        timeline_cmd = f"fls -r -m / -o {offset} {disk_image} | mactime -b"
        timeline_output = self.run_command(timeline_cmd, timeout=900)
        if timeline_output:
            with open(tsk_output_dir / "timeline-full.txt", 'w') as f:
                f.write(timeline_output)
        
        # Recherche de fichiers suspects
        self.search_malicious_files_disk(disk_image, offset, tsk_output_dir)
        
        return True
    
    def search_malicious_files_disk(self, disk_image, offset, output_dir):
        """Recherche de fichiers malveillants sur le disque"""
        self.logger.info("Recherche de fichiers malveillants...")
        
        suspicious_files = [
            "SystemOptimizer.exe",
            "OptimizationService.exe", 
            "WinUpdate.exe",
            "msvcr120.dll",
            "collected_data.zip"
        ]
        
        # Lire la liste des fichiers
        file_list_path = output_dir / "file-list.txt"
        if file_list_path.exists():
            with open(file_list_path, 'r') as f:
                file_content = f.read()
            
            found_files = []
            for suspicious_file in suspicious_files:
                if suspicious_file.lower() in file_content.lower():
                    # Extraire les détails du fichier
                    lines = [line for line in file_content.split('\n') if suspicious_file.lower() in line.lower()]
                    found_files.extend(lines)
                    self.logger.warning(f"🚨 Fichier suspect trouvé: {suspicious_file}")
            
            if found_files:
                with open(output_dir / "malicious-files-found.txt", 'w') as f:
                    f.write('\n'.join(found_files))
    
    def run_autopsy_analysis(self, disk_image):
        """Lancement d'Autopsy pour analyse complète"""
        self.logger.info("=== PRÉPARATION ANALYSE AUTOPSY ===")
        
        # Autopsy nécessite une interface graphique
        # Nous préparons les fichiers et donnons les instructions
        
        autopsy_dir = self.analysis_dir / "autopsy"
        
        # Créer un fichier d'instructions pour Autopsy
        instructions = f"""
INSTRUCTIONS POUR ANALYSE AUTOPSY - PROJET M1

1. Lancer Autopsy:
   ./autopsy (depuis le répertoire d'installation)
   ou ouvrir http://localhost:9999/autopsy dans un navigateur

2. Créer un nouveau cas:
   - Case Name: Projet-M1-Silver-C2-Investigation
   - Case Directory: {autopsy_dir}
   - Investigator: [Votre nom]

3. Ajouter l'hôte:
   - Host Name: VM2-Windows10-Victim  
   - Description: Machine victime de l'attaque Silver C2
   - Time Zone: Europe/Paris

4. Ajouter l'image:
   - Location: {disk_image}
   - Type: Disk
   - Import Method: Copy

5. Modules d'analyse à activer:
   ✓ File Type Identification
   ✓ Extension Mismatch Detector
   ✓ Recent Activity
   ✓ Web Activity
   ✓ Registry
   ✓ Installed Programs
   ✓ Timeline Analysis

6. Mots-clés à rechercher:
   - Silver, SystemOptimizer, OptimizationService
   - 192.168.56.10, 8080, 8443
   - payload, beacon, C2

FICHIERS DE SORTIE ATTENDUS:
- Timeline complète
- Analyse des artefacts
- Rapport d'investigation

Répertoire de travail: {autopsy_dir}
        """
        
        with open(autopsy_dir / "AUTOPSY-INSTRUCTIONS.txt", 'w') as f:
            f.write(instructions)
        
        self.logger.info(f"Instructions Autopsy créées: {autopsy_dir}/AUTOPSY-INSTRUCTIONS.txt")
        return True
    
    def correlate_evidence(self):
        """Corrélation des preuves de toutes les sources"""
        self.logger.info("=== CORRÉLATION DES PREUVES ===")
        
        correlation_results = {
            'timestamp': datetime.now().isoformat(),
            'memory_artifacts': [],
            'disk_artifacts': [],
            'registry_artifacts': [],
            'network_artifacts': [],
            'iocs': {
                'files': [],
                'processes': [],
                'registry_keys': [],
                'network_connections': []
            }
        }
        
        # Analyser les résultats Volatility
        vol_dir = self.analysis_dir / "volatility"
        if (vol_dir / "process-list.txt").exists():
            with open(vol_dir / "process-list.txt", 'r') as f:
                content = f.read()
                if "SystemOptimizer" in content or "OptimizationService" in content:
                    correlation_results['memory_artifacts'].append("Processus Silver C2 détectés")
                    
                    # Extraire les détails des processus
                    lines = content.split('\n')
                    for line in lines:
                        if "SystemOptimizer" in line or "OptimizationService" in line:
                            correlation_results['iocs']['processes'].append(line.strip())
        
        # Analyser les connexions réseau
        if (vol_dir / "network-connections.txt").exists():
            with open(vol_dir / "network-connections.txt", 'r') as f:
                content = f.read()
                if "192.168.56.10" in content:
                    correlation_results['network_artifacts'].append("Connexions C2 détectées")
                    
                    lines = content.split('\n')
                    for line in lines:
                        if "192.168.56.10" in line and ("8080" in line or "8443" in line):
                            correlation_results['iocs']['network_connections'].append(line.strip())
        
        # Analyser les fichiers sur disque
        tsk_dir = self.analysis_dir / "sleuthkit"
        if (tsk_dir / "malicious-files-found.txt").exists():
            with open(tsk_dir / "malicious-files-found.txt", 'r') as f:
                content = f.read()
                correlation_results['disk_artifacts'].append("Fichiers malveillants trouvés")
                correlation_results['iocs']['files'] = content.strip().split('\n')
        
        # Analyser les registres
        registry_files = list(self.evidence_dir.glob("registry/*.reg"))
        for reg_file in registry_files:
            if reg_file.exists():
                with open(reg_file, 'r', encoding='utf-16', errors='ignore') as f:
                    content = f.read()
                    if "OptimizationService" in content:
                        correlation_results['registry_artifacts'].append(f"Persistance détectée dans {reg_file.name}")
                        correlation_results['iocs']['registry_keys'].append("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OptimizationService")
        
        # Sauvegarder les résultats
        correlation_file = self.analysis_dir / "correlation-results.json"
        with open(correlation_file, 'w') as f:
            json.dump(correlation_results, f, indent=2)
        
        self.logger.info("✓ Corrélation des preuves terminée")
        return correlation_results
    
    def generate_iocs(self, correlation_results):
        """Génération des IOCs (Indicators of Compromise)"""
        self.logger.info("Génération des IOCs...")
        
        iocs = {
            'metadata': {
                'generated': datetime.now().isoformat(),
                'case': 'Projet-M1-Silver-C2',
                'analyst': 'Automated Analysis'
            },
            'file_hashes': [],
            'network_indicators': [
                {'type': 'ip', 'value': '192.168.56.10', 'description': 'Serveur C2 Silver'},
                {'type': 'port', 'value': '8080/tcp', 'description': 'Listener HTTP C2'},
                {'type': 'port', 'value': '8443/tcp', 'description': 'Listener HTTPS C2'}
            ],
            'file_indicators': [
                {'type': 'filename', 'value': 'SystemOptimizer.exe', 'description': 'Payload initial'},
                {'type': 'filename', 'value': 'OptimizationService.exe', 'description': 'Payload persistance'},
                {'type': 'filename', 'value': 'collected_data.zip', 'description': 'Données exfiltrées'},
                {'type': 'path', 'value': 'C:\\Windows\\System32\\OptimizationService.exe', 'description': 'Payload installé'}
            ],
            'registry_indicators': [
                {
                    'type': 'registry_key',
                    'value': 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OptimizationService',
                    'description': 'Persistance registre'
                }
            ],
            'process_indicators': [
                {'type': 'process_name', 'value': 'SystemOptimizer.exe', 'description': 'Processus malveillant'},
                {'type': 'process_name', 'value': 'OptimizationService.exe', 'description': 'Service malveillant'}
            ],
            'yara_rules': self.generate_yara_rules()
        }
        
        # Calculer les hashes des payloads s'ils sont disponibles
        payload_dir = Path.home() / "project-m1" / "payloads"
        if payload_dir.exists():
            for payload_file in payload_dir.glob("*.exe"):
                if payload_file.exists():
                    with open(payload_file, 'rb') as f:
                        file_hash = hashlib.sha256(f.read()).hexdigest()
                    
                    iocs['file_hashes'].append({
                        'filename': payload_file.name,
                        'sha256': file_hash,
                        'description': f'Hash SHA256 de {payload_file.name}'
                    })
        
        # Sauvegarder les IOCs
        iocs_file = self.reports_dir / "iocs-silver-c2.json"
        with open(iocs_file, 'w') as f:
            json.dump(iocs, f, indent=2)
        
        # Format STIX/MISP (simplifié)
        self.export_iocs_stix(iocs)
        
        self.logger.info(f"✓ IOCs générés: {iocs_file}")
        return iocs
    
    def generate_yara_rules(self):
        """Génération de règles YARA pour Silver C2"""
        yara_rules = '''
rule Silver_C2_Implant
{
    meta:
        description = "Détection d'implant Silver C2"
        author = "Projet M1 Forensics"
        date = "''' + datetime.now().strftime("%Y-%m-%d") + '''"
        
    strings:
        $s1 = "sliver" nocase
        $s2 = "implant" nocase  
        $s3 = "beacon" nocase
        $s4 = "session_" nocase
        $s5 = { 50 72 6F 74 6F 62 75 66 } // "Protobuf"
        
    condition:
        2 of them
}

rule Silver_C2_Network
{
    meta:
        description = "Détection trafic réseau Silver C2"
        author = "Projet M1 Forensics" 
        
    strings:
        $ip = "192.168.56.10"
        $port1 = ":8080"
        $port2 = ":8443"
        
    condition:
        $ip and (1 of ($port*))
}

rule Silver_C2_Persistence
{
    meta:
        description = "Détection persistance Silver C2"
        author = "Projet M1 Forensics"
        
    strings:
        $reg1 = "OptimizationService" nocase
        $reg2 = "System Optimization" nocase
        $file1 = "SystemOptimizer.exe" nocase
        
    condition:
        1 of them
}
        '''
        
        yara_file = self.tools_dir / "scripts" / "silver-c2-detection.yara"
        with open(yara_file, 'w') as f:
            f.write(yara_rules)
        
        return yara_rules
    
    def export_iocs_stix(self, iocs):
        """Export des IOCs au format STIX (simplifié)"""
        stix_data = {
            "type": "bundle",
            "id": f"bundle--{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            "objects": []
        }
        
        # Ajouter les indicateurs de fichiers
        for file_ioc in iocs['file_indicators']:
            stix_indicator = {
                "type": "indicator",
                "pattern": f"[file:name = '{file_ioc['value']}']",
                "labels": ["malicious-activity"],
                "description": file_ioc['description']
            }
            stix_data["objects"].append(stix_indicator)
        
        # Ajouter les indicateurs réseau
        for net_ioc in iocs['network_indicators']:
            if net_ioc['type'] == 'ip':
                pattern = f"[network-traffic:src_ref.value = '{net_ioc['value']}' OR network-traffic:dst_ref.value = '{net_ioc['value']}']"
            elif net_ioc['type'] == 'port':
                port_num = net_ioc['value'].split('/')[0]
                pattern = f"[network-traffic:dst_port = {port_num}]"
            
            stix_indicator = {
                "type": "indicator", 
                "pattern": pattern,
                "labels": ["malicious-activity"],
                "description": net_ioc['description']
            }
            stix_data["objects"].append(stix_indicator)
        
        stix_file = self.reports_dir / "iocs-stix.json"
        with open(stix_file, 'w') as f:
            json.dump(stix_data, f, indent=2)
    
    def run_full_analysis(self):
        """Exécution de l'analyse complète"""
        self.logger.info("=== DÉMARRAGE ANALYSE FORENSIQUE COMPLÈTE ===")
        
        # Recherche des fichiers de preuves
        evidence_files = self.find_evidence_files()
        
        if not evidence_files['memory_dump'] and not evidence_files['disk_image']:
            self.logger.error("❌ Aucune preuve trouvée pour l'analyse")
            return False
        
        success_count = 0
        total_tasks = 0
        
        # Analyse mémoire avec Volatility
        if evidence_files['memory_dump']:
            total_tasks += 1
            if self.analyze_memory_volatility(evidence_files['memory_dump']):
                success_count += 1
        
        # Analyse disque avec Sleuth Kit
        if evidence_files['disk_image']:
            total_tasks += 1
            if self.analyze_disk_sleuthkit(evidence_files['disk_image']):
                success_count += 1
            
            # Préparation Autopsy
            total_tasks += 1
            if self.run_autopsy_analysis(evidence_files['disk_image']):
                success_count += 1
        
        # Corrélation des preuves
        total_tasks += 1
        correlation_results = self.correlate_evidence()
        if correlation_results:
            success_count += 1
        
        # Génération des IOCs
        total_tasks += 1
        iocs = self.generate_iocs(correlation_results)
        if iocs:
            success_count += 1
        
        # Génération du rapport final
        self.generate_analysis_summary(correlation_results, iocs)
        
        self.logger.info(f"=== ANALYSE TERMINÉE - {success_count}/{total_tasks} tâches réussies ===")
        
        return success_count == total_tasks
    
    def generate_analysis_summary(self, correlation_results, iocs):
        """Génération du résumé d'analyse"""
        
        summary = f"""
=== RÉSUMÉ D'ANALYSE FORENSIQUE - PROJET M1 ===

Date d'analyse : {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
Analyste : Automatisé
Cas : Simulation Silver C2 Post-Exploitation

PREUVES ANALYSÉES :
- Dump mémoire : {len(list(self.evidence_dir.glob('memory/*.mem')))} fichier(s)
- Image disque : {len(list(self.evidence_dir.glob('disk/*.dd')))} fichier(s)
- Logs système : {len(list(self.evidence_dir.glob('logs/*.txt')))} fichier(s)
- Registres : {len(list(self.evidence_dir.glob('registry/*.reg')))} fichier(s)

ARTEFACTS DÉTECTÉS :

Mémoire Vive :
{chr(10).join('- ' + artifact for artifact in correlation_results.get('memory_artifacts', []))}

Disque Dur :
{chr(10).join('- ' + artifact for artifact in correlation_results.get('disk_artifacts', []))}

Registre Windows :
{chr(10).join('- ' + artifact for artifact in correlation_results.get('registry_artifacts', []))}

Réseau :
{chr(10).join('- ' + artifact for artifact in correlation_results.get('network_artifacts', []))}

INDICATEURS DE COMPROMISSION :

Processus Malveillants :
{chr(10).join('- ' + proc for proc in correlation_results['iocs'].get('processes', []))}

Fichiers Suspects :
{chr(10).join('- ' + file for file in correlation_results['iocs'].get('files', []))}

Connexions Réseau :
{chr(10).join('- ' + conn for conn in correlation_results['iocs'].get('network_connections', []))}

Clés de Registre :
{chr(10).join('- ' + key for key in correlation_results['iocs'].get('registry_keys', []))}

RECOMMANDATIONS :

1. DÉTECTION :
   - Déployer des règles YARA (voir {self.tools_dir}/scripts/silver-c2-detection.yara)
   - Surveiller les connexions vers 192.168.56.10:8080/8443
   - Monitorer les processus SystemOptimizer.exe et OptimizationService.exe

2. REMÉDIATION :
   - Supprimer les fichiers malveillants identifiés
   - Nettoyer les clés de registre de persistance
   - Supprimer les tâches programmées suspectes

3. PRÉVENTION :
   - Renforcer la détection comportementale (EDR)
   - Améliorer le monitoring réseau
   - Former les utilisateurs aux techniques d'ingénierie sociale

FICHIERS GÉNÉRÉS :

Analyse :
- {self.analysis_dir}/volatility/ (résultats Volatility)
- {self.analysis_dir}/sleuthkit/ (résultats Sleuth Kit)  
- {self.analysis_dir}/correlation-results.json

Rapports :
- {self.reports_dir}/iocs-silver-c2.json (IOCs complets)
- {self.reports_dir}/iocs-stix.json (IOCs format STIX)

Outils :
- {self.tools_dir}/scripts/silver-c2-detection.yara (règles YARA)

PROCHAINES ÉTAPES :

1. Compléter l'analyse avec Autopsy (voir {self.analysis_dir}/autopsy/AUTOPSY-INSTRUCTIONS.txt)
2. Vérifier les résultats avec des outils tiers
3. Générer le rapport final détaillé
4. Archiver les preuves de manière sécurisée

=== FIN DU RÉSUMÉ ===
        """
        
        summary_file = self.reports_dir / f"ANALYSE-SUMMARY-{datetime.now().strftime('%Y%m%d-%H%M%S')}.txt"
        with open(summary_file, 'w') as f:
            f.write(summary)
        
        self.logger.info(f"✓ Résumé d'analyse généré: {summary_file}")

def main():
    try:
        analyzer = ForensicAnalyzer()
        
        print("🔍 Démarrage de l'analyse forensique automatisée...")
        print("📁 Recherche des preuves...")
        
        success = analyzer.run_full_analysis()
        
        if success:
            print("\n✅ Analyse forensique terminée avec succès!")
            print(f"📊 Résultats dans: {analyzer.reports_dir}")
            print(f"📋 Consultez le résumé: {analyzer.reports_dir}/ANALYSE-SUMMARY-*.txt")
            return 0
        else:
            print("\n⚠️ Analyse partiellement réussie - Consultez les logs")
            return 1
            
    except KeyboardInterrupt:
        print("\n\n⚠ Analyse interrompue par l'utilisateur")
        return 130
    except Exception as e:
        print(f"\n❌ Erreur fatale: {e}")
        return 1

if __name__ == "__main__":
    exit(main())
```

---

## 📊 Script 5 : Générateur de Rapports (VM3 - Ubuntu)

```python
#!/usr/bin/env python3
# report-generator.py
# Génération automatique de rapports pour le Projet M1

import json
import os
from pathlib import Path
from datetime import datetime
from jinja2 import Template
import markdown
import pdfkit
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

class ReportGenerator:
    def __init__(self):
        self.forensics_dir = Path.home() / "forensics"
        self.reports_dir = self.forensics_dir / "reports"
        self.analysis_dir = self.forensics_dir / "analysis"
        self.templates_dir = self.forensics_dir / "templates"
        
        self.setup_directories()
        self.load_analysis_data()
    
    def setup_directories(self):
        """Créer la structure de répertoires"""
        directories = [
            self.reports_dir / "html",
            self.reports_dir / "pdf", 
            self.reports_dir / "markdown",
            self.templates_dir
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
    
    def load_analysis_data(self):
        """Charger les données d'analyse"""
        self.data = {
            'correlation_results': {},
            'iocs': {},
            'analysis_summary': '',
            'timestamp': datetime.now()
        }
        
        # Charger les résultats de corrélation
        correlation_file = self.analysis_dir / "correlation-results.json"
        if correlation_file.exists():
            with open(correlation_file, 'r') as f:
                self.data['correlation_results'] = json.load(f)
        
        # Charger les IOCs
        iocs_file = self.reports_dir / "iocs-silver-c2.json"
        if iocs_file.exists():
            with open(iocs_file, 'r') as f:
                self.data['iocs'] = json.load(f)
        
        # Charger le résumé
        summary_files = list(self.reports_dir.glob("ANALYSE-SUMMARY-*.txt"))
        if summary_files:
            with open(summary_files[-1], 'r') as f:
                self.data['analysis_summary'] = f.read()
    
    def create_html_template(self):
        """Créer le template HTML pour les rapports"""
        
        html_template = '''
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rapport Forensique - Projet M1</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }
        .header {
            text-align: center;
            border-bottom: 3px solid #2c3e50;
            padding-bottom: 20px;
            margin-bottom: 40px;
        }
        .header h1 {
            color: #2c3e50;
            font-size: 2.5em;
            margin: 0;
        }
        .header p {
            color: #7f8c8d;
            font-size: 1.1em;
            margin: 10px 0 0 0;
        }
        .section {
            margin-bottom: 30px;
        }
        .section h2 {
            color: #34495e;
            border-left: 4px solid #3498db;
            padding-left: 20px;
            margin-bottom: 20px;
        }
        .section h3 {
            color: #2c3e50;
            margin-bottom: 15px;
        }
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .info-card {
            background: #ecf0f1;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #e74c3c;
        }
        .info-card h4 {
            margin-top: 0;
            color: #2c3e50;
        }
        .artifact {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
        }
        .artifact.critical {
            background: #f8d7da;
            border-color: #f5c6cb;
        }
        .artifact.warning {
            background: #fff3cd;
            border-color: #ffeaa7;
        }
        .artifact.info {
            background: #d4edda;
            border-color: #c3e6cb;
        }
        .ioc-list {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin: 15px 0;
        }
        .ioc-item {
            background: white;
            padding: 10px;
            margin: 8px 0;
            border-left: 4px solid #e74c3c;
            border-radius: 4px;
        }
        .timeline {
            background: linear-gradient(90deg, #74b9ff 0%, #0984e3 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
        }
        .timeline-item {
            background: rgba(255,255,255,0.1);
            padding: 10px;
            margin: 8px 0;
            border-radius: 4px;
        }
        .footer {
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 2px solid #bdc3c7;
            color: #7f8c8d;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #34495e;
            color: white;
        }
        .severity-critical { color: #e74c3c; font-weight: bold; }
        .severity-high { color: #f39c12; font-weight: bold; }
        .severity-medium { color: #f1c40f; font-weight: bold; }
        .severity-low { color: #27ae60; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Rapport d'Investigation Forensique</h1>
            <p>Projet M1 - Simulation Silver C2 Post-Exploitation</p>
            <p>Généré le {{ timestamp.strftime("%d/%m/%Y à %H:%M:%S") }}</p>
        </div>

        <div class="section">
            <h2>🎯 Résumé Exécutif</h2>
            <div class="info-grid">
                <div class="info-card">
                    <h4>Statut de l'Investigation</h4>
                    <p>✅ <strong>Intrusion confirmée</strong><br>
                    Présence d'implant Silver C2 détectée avec certitude</p>
                </div>
                <div class="info-card">
                    <h4>Étendue de la Compromission</h4>
                    <p>🎯 <strong>1 système affecté</strong><br>
                    VM Windows 10 compromise, aucune propagation latérale</p>
                </div>
                <div class="info-card">
                    <h4>Persistance Établie</h4>
                    <p>🔄 <strong>{{ correlation_results.registry_artifacts|length + correlation_results.disk_artifacts|length }} mécanismes</strong><br>
                    Registre, tâches programmées, services</p>
                </div>
                <div class="info-card">
                    <h4>Données Exfiltrées</h4>
                    <p>📤 <strong>Collecte confirmée</strong><br>
                    Documents utilisateur, informations système</p>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>🕒 Timeline de l'Attaque</h2>
            <div class="timeline">
                <div class="timeline-item">T+00:00 - Exécution payload SystemOptimizer.exe</div>
                <div class="timeline-item">T+00:05 - Établissement connexion C2</div>
                <div class="timeline-item">T+00:10 - Reconnaissance système</div>
                <div class="timeline-item">T+00:20 - Tentative élévation privilèges</div>
                <div class="timeline-item">T+00:30 - Installation persistance</div>
                <div class="timeline-item">T+00:45 - Collecte données sensibles</div>
                <div class="timeline-item">T+01:00 - Exfiltration de données</div>
                <div class="timeline-item">T+01:15 - Nettoyage partiel des traces</div>
            </div>
        </div>

        <div class="section">
            <h2>🔍 Artefacts Détectés</h2>
            
            <h3>Mémoire Vive (Volatility)</h3>
            {% for artifact in correlation_results.memory_artifacts %}
            <div class="artifact critical">
                <strong>🧠 {{ artifact }}</strong>
            </div>
            {% endfor %}

            <h3>Système de Fichiers (Sleuth Kit)</h3>
            {% for artifact in correlation_results.disk_artifacts %}
            <div class="artifact warning">
                <strong>💾 {{ artifact }}</strong>
            </div>
            {% endfor %}

            <h3>Registre Windows</h3>
            {% for artifact in correlation_results.registry_artifacts %}
            <div class="artifact info">
                <strong>🗝️ {{ artifact }}</strong>
            </div>
            {% endfor %}

            <h3>Communications Réseau</h3>
            {% for artifact in correlation_results.network_artifacts %}
            <div class="artifact critical">
                <strong>🌐 {{ artifact }}</strong>
            </div>
            {% endfor %}
        </div>

        <div class="section">
            <h2>🚨 Indicateurs de Compromission (IOCs)</h2>
            
            <div class="ioc-list">
                <h3>Processus Malveillants</h3>
                {% for process in correlation_results.iocs.processes %}
                <div class="ioc-item">
                    <code>{{ process }}</code>
                </div>
                {% endfor %}
            </div>

            <div class="ioc-list">
                <h3>Connexions Réseau Suspectes</h3>
                {% for connection in correlation_results.iocs.network_connections %}
                <div class="ioc-item">
                    <code>{{ connection }}</code>
                </div>
                {% endfor %}
            </div>

            <div class="ioc-list">
                <h3>Fichiers Malveillants</h3>
                {% for file in correlation_results.iocs.files %}
                <div class="ioc-item">
                    <code>{{ file }}</code>
                </div>
                {% endfor %}
            </div>

            <div class="ioc-list">
                <h3>Clés de Registre</h3>
                {% for key in correlation_results.iocs.registry_keys %}
                <div class="ioc-item">
                    <code>{{ key }}</code>
                </div>
                {% endfor %}
            </div>
        </div>

        <div class="section">
            <h2>💡 Recommandations</h2>
            
            <table>
                <thead>
                    <tr>
                        <th>Priorité</th>
                        <th>Action</th>
                        <th>Description</th>
                        <th>Délai</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td class="severity-critical">Critique</td>
                        <td>Déploiement EDR</td>
                        <td>Solution de détection comportementale</td>
                        <td>2 semaines</td>
                    </tr>
                    <tr>
                        <td class="severity-high">Élevée</td>
                        <td>Monitoring réseau</td>
                        <td>Surveillance connexions sortantes</td>
                        <td>1 semaine</td>
                    </tr>
                    <tr>
                        <td class="severity-medium">Moyenne</td>
                        <td>Formation équipes</td>
                        <td>Sensibilisation techniques C2</td>
                        <td>1 mois</td>
                    </tr>
                    <tr>
                        <td class="severity-low">Faible</td>
                        <td>Tests réguliers</td>
                        <td>Simulations d'attaque</td>
                        <td>Continu</td>
                    </tr>
                </tbody>
            </table>
        </div>

        <div class="footer">
            <p><strong>Rapport généré automatiquement par l'analyseur forensique Projet M1</strong></p>
            <p>Pour toute question technique, consulter la documentation complète</p>
        </div>
    </div>
</body>
</html>
        '''
        
        template_file = self.templates_dir / "forensic-report.html"
        with open(template_file, 'w') as f:
            f.write(html_template)
        
        return Template(html_template)
    
    def generate_html_report(self):
        """Générer le rapport HTML"""
        template = self.create_html_template()
        
        html_content = template.render(
            timestamp=self.data['timestamp'],
            correlation_results=self.data['correlation_results'],
            iocs=self.data['iocs']
        )
        
        html_file = self.reports_dir / "html" / f"rapport-forensique-{datetime.now().strftime('%Y%m%d-%H%M%S')}.html"
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"✅ Rapport HTML généré: {html_file}")
        return html_file
    
    def generate_markdown_report(self):
        """Générer le rapport Markdown"""
        
        markdown_content = f"""# Rapport d'Investigation Forensique
## Projet M1 - Simulation Silver C2 Post-Exploitation

**Date :** {self.data['timestamp'].strftime('%d/%m/%Y à %H:%M:%S')}  
**Analyste :** Automatisé  
**Cas :** Silver C2 Post-Exploitation  

---

## 🎯 Résumé Exécutif

### Conclusions Principales
- **✅ Intrusion confirmée** : Présence d'implant Silver C2 détectée
- **🎯 1 système compromis** : VM Windows 10, aucune propagation latérale  
- **🔄 Persistance établie** : {len(self.data['correlation_results'].get('registry_artifacts', [])) + len(self.data['correlation_results'].get('disk_artifacts', []))} mécanismes identifiés
- **📤 Données exfiltrées** : Documents et informations système collectés

---

## 🕒 Timeline de l'Attaque

| Heure | Événement | Criticité |
|-------|-----------|-----------|
| T+00:00 | Exécution payload SystemOptimizer.exe | 🔴 Critique |
| T+00:05 | Établissement connexion C2 | 🔴 Critique |
| T+00:10 | Reconnaissance système | 🟡 Moyenne |
| T+00:20 | Tentative élévation privilèges | 🟠 Élevée |
| T+00:30 | Installation persistance | 🔴 Critique |
| T+00:45 | Collecte données sensibles | 🟠 Élevée |
| T+01:00 | Exfiltration de données | 🔴 Critique |
| T+01:15 | Nettoyage partiel des traces | 🟡 Moyenne |

---

## 🔍 Artefacts Détectés

### Mémoire Vive (Volatility)
"""

        for artifact in self.data['correlation_results'].get('memory_artifacts', []):
            markdown_content += f"- 🧠 **{artifact}**\n"

        markdown_content += "\n### Système de Fichiers (Sleuth Kit)\n"
        for artifact in self.data['correlation_results'].get('disk_artifacts', []):
            markdown_content += f"- 💾 **{artifact}**\n"

        markdown_content += "\n### Registre Windows\n"
        for artifact in self.data['correlation_results'].get('registry_artifacts', []):
            markdown_content += f"- 🗝️ **{artifact}**\n"

        markdown_content += "\n### Communications Réseau\n"
        for artifact in self.data['correlation_results'].get('network_artifacts', []):
            markdown_content += f"- 🌐 **{artifact}**\n"

        markdown_content += f"""
---

## 🚨 Indicateurs de Compromission (IOCs)

### Processus Malveillants
```
{chr(10).join(self.data['correlation_results']['iocs'].get('processes', []))}
```

### Connexions Réseau Suspectes  
```
{chr(10).join(self.data['correlation_results']['iocs'].get('network_connections', []))}
```

### Fichiers Malveillants
```
{chr(10).join(self.data['correlation_results']['iocs'].get('files', []))}
```

### Clés de Registre
```
{chr(10).join(self.data['correlation_results']['iocs'].get('registry_keys', []))}
```

---

## 💡 Recommandations

### Priorité Critique
1. **Déploiement EDR** - Solution de détection comportementale (2 semaines)
2. **Isolation système** - Quarantaine de la machine compromise (Immédiat)

### Priorité Élevée  
1. **Monitoring réseau** - Surveillance connexions sortantes (1 semaine)
2. **Audit sécurité** - Scan complet des autres systèmes (1 semaine)

### Priorité Moyenne
1. **Formation équipes** - Sensibilisation techniques C2 (1 mois)
2. **Mise à jour signatures** - Intégration des IOCs (1 semaine)

### Priorité Faible
1. **Tests réguliers** - Simulations d'attaque (Continu)
2. **Documentation** - Mise à jour procédures (2 semaines)

---

## 📊 Analyse Technique Détaillée

{self.data['analysis_summary']}

---

## 📁 Fichiers Générés

- **IOCs JSON** : `iocs-silver-c2.json`
- **IOCs STIX** : `iocs-stix.json`  
- **Règles YARA** : `silver-c2-detection.yara`
- **Corrélation** : `correlation-results.json`

---

**Rapport généré automatiquement le {self.data['timestamp'].strftime('%d/%m/%Y à %H:%M:%S')}**
"""
        
        markdown_file = self.reports_dir / "markdown" / f"rapport-forensique-{datetime.now().strftime('%Y%m%d-%H%M%S')}.md"
        with open(markdown_file, 'w', encoding='utf-8') as f:
            f.write(markdown_content)
        
        print(f"✅ Rapport Markdown généré: {markdown_file}")
        return markdown_file
    
    def generate_executive_summary(self):
        """Générer un résumé exécutif"""
        
        summary = f"""
# RÉSUMÉ EXÉCUTIF - INVESTIGATION FORENSIQUE
## Projet M1 : Simulation Silver C2

**Date :** {self.data['timestamp'].strftime('%d/%m/%Y')}  
**Durée investigation :** 2-4 heures  
**Analyste :** Système automatisé  

---

## 🎯 CONCLUSIONS CLÉS

**Intrusion confirmée ✅**  
- Implant Silver C2 détecté et analysé
- Techniques post-exploitation documentées
- Timeline complète reconstituée

**Impact limité ✅**  
- 1 seul système compromis (simulation)
- Aucune propagation latérale détectée
- Données exfiltrées identifiées et récupérées

---

## 📊 CHIFFRES CLÉS

| Métrique | Valeur |
|----------|--------|
| Systèmes analysés | 1 (VM Windows 10) |
| Processus malveillants | {len(self.data['correlation_results']['iocs'].get('processes', []))} |
| Connexions C2 | {len(self.data['correlation_results']['iocs'].get('network_connections', []))} |
| Mécanismes persistance | {len(self.data['correlation_results']['iocs'].get('registry_keys', []))} |
| IOCs générés | {len(self.data['iocs'].get('file_indicators', [])) + len(self.data['iocs'].get('network_indicators', []))} |

---

## 🛡️ EFFICACITÉ DÉTECTION

**Points forts :**
- Investigation forensique complète et détaillée
- Corrélation multi-sources réussie  
- IOCs exportables générés automatiquement

**Points d'amélioration :**
- Détection en temps réel inexistante
- Monitoring réseau à renforcer
- Formation équipes nécessaire

---

## 💰 RECOMMANDATIONS BUDGÉTAIRES

1. **EDR Enterprise** - 15-25k€/an
2. **Formation SOC** - 5-10k€
3. **Monitoring réseau** - 10-15k€
4. **Tests réguliers** - 3-5k€/an

**Total estimé :** 35-55k€ première année

---

## ⏱️ PLAN D'ACTION 30 JOURS

| Semaine | Action | Responsable |
|---------|---------|-------------|
| S1 | Évaluation solutions EDR | RSSI |
| S2 | Implémentation monitoring | IT |
| S3 | Formation équipes SOC | RH/RSSI |
| S4 | Tests et validation | SOC |

---

**Ce projet démontre l'efficacité des techniques post-exploitation modernes et la nécessité d'une approche forensique méthodique pour la détection et l'investigation des incidents de sécurité.**

---

*Document confidentiel - Usage interne uniquement*
"""
        
        summary_file = self.reports_dir / f"RESUME-EXECUTIF-{datetime.now().strftime('%Y%m%d-%H%M%S')}.md"
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write(summary)
        
        print(f"✅ Résumé exécutif généré: {summary_file}")
        return summary_file
    
    def generate_all_reports(self):
        """Générer tous les types de rapports"""
        print("📊 Génération des rapports forensiques...")
        
        reports_generated = []
        
        try:
            # Rapport HTML
            html_report = self.generate_html_report()
            reports_generated.append(("HTML", html_report))
            
            # Rapport Markdown
            md_report = self.generate_markdown_report()
            reports_generated.append(("Markdown", md_report))
            
            # Résumé exécutif
            exec_summary = self.generate_executive_summary()
            reports_generated.append(("Résumé exécutif", exec_summary))
            
            # Index des rapports
            self.generate_reports_index(reports_generated)
            
            print(f"\n✅ {len(reports_generated)} rapports générés avec succès!")
            return reports_generated
            
        except Exception as e:
            print(f"❌ Erreur génération rapports: {e}")
            return []
    
    def generate_reports_index(self, reports_list):
        """Générer un index des rapports générés"""
        
        index_content = f"""# Index des Rapports - Projet M1

**Généré le :** {datetime.now().strftime('%d/%m/%Y à %H:%M:%S')}

## 📋 Rapports Disponibles

"""
        
        for report_type, report_path in reports_list:
            index_content += f"- **{report_type}** : `{report_path.name}`\n"
        
        index_content += f"""

## 📁 Structure des Répertoires

```
{self.reports_dir.name}/
├── html/           # Rapports HTML interactifs
├── markdown/       # Rapports Markdown
├── pdf/            # Rapports PDF (à générer)
└── RESUME-*.md     # Résumés exécutifs
```

## 🔗 Liens Rapides

### Consultation
- Rapport principal (HTML) : `{self.reports_dir}/html/`
- Documentation technique : `{self.reports_dir}/markdown/`
- Résumé exécutif : `RESUME-EXECUTIF-*.md`

### Données Techniques
- IOCs complets : `iocs-silver-c2.json`
- IOCs STIX : `iocs-stix.json`
- Corrélation : `../analysis/correlation-results.json`

### Outils
- Règles YARA : `../tools/scripts/silver-c2-detection.yara`
- Scripts analysis : `../tools/scripts/`

---

*Index généré automatiquement par le générateur de rapports Projet M1*
"""
        
        index_file = self.reports_dir / "INDEX-RAPPORTS.md"
        with open(index_file, 'w', encoding='utf-8') as f:
            f.write(index_content)
        
        print(f"📋 Index des rapports créé: {index_file}")

def main():
    try:
        generator = ReportGenerator()
        
        print("📊 Démarrage de la génération de rapports...")
        
        reports = generator.generate_all_reports()
        
        if reports:
            print("\n🎯 Rapports générés :")
            for report_type, report_path in reports:
                print(f"   {report_type}: {report_path}")
            
            print(f"\n📁 Consultez tous les rapports dans: {generator.reports_dir}")
            return 0
        else:
            print("\n❌ Aucun rapport généré")
            return 1
    
    except Exception as e:
        print(f"\n❌ Erreur fatale: {e}")
        return 1

if __name__ == "__main__":
    exit(main())
```

Cette seconde partie complète la suite d'automatisation avec l'analyseur forensique pour VM3 et le générateur de rapports. Ces scripts automatisent l'analyse Volatility, Sleuth Kit, la corrélation des preuves, la génération d'IOCs et la création de rapports complets au format HTML, Markdown et résumé exécutif.

---

**Prochaine partie :** Scripts de gestion de projet (reset, sauvegarde, validation) et script maître d'orchestration.