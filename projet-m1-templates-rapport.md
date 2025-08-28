# PROJET M1 - Templates de Rapport d'Investigation
## Modèles de Documentation Forensique

---

## 📋 Template 1 : Rapport Technique Complet

```markdown
# RAPPORT D'INVESTIGATION FORENSIQUE
## Incident de Sécurité - Silver C2 Post-Exploitation

### INFORMATIONS GÉNÉRALES

**Référence du Cas :** PROJ-M1-[YYYYMMDD]-001  
**Date d'Investigation :** [Date]  
**Investigateur Principal :** [Nom, Titre]  
**Analyste Technique :** [Nom, Titre]  
**Statut :** [En cours / Terminé]  
**Classification :** [TLP:WHITE / TLP:GREEN / TLP:AMBER / TLP:RED]  

---

### RÉSUMÉ EXÉCUTIF

#### Contexte de l'Incident
[Description brève de l'incident simulé avec Silver C2]

#### Conclusions Principales
- **Confirmation d'intrusion :** [OUI/NON]
- **Vecteur d'attaque identifié :** [Détails]
- **Étendue de la compromission :** [Locale/Réseau/Inconnue]
- **Données exfiltrées :** [Type et volume]
- **Persistance établie :** [OUI/NON]

#### Impact Estimé
- **Sévérité :** [Critique/Élevée/Moyenne/Faible]
- **Systèmes affectés :** [Nombre]
- **Durée estimée de la compromission :** [Période]
- **Coût estimé :** [Si applicable]

---

### MÉTHODOLOGIE D'INVESTIGATION

#### Outils Utilisés
| Outil | Version | Fonction | Plateforme |
|-------|---------|----------|------------|
| Volatility | 3.x | Analyse mémoire | Ubuntu |
| Autopsy | 4.20+ | Investigation disque | Ubuntu |
| The Sleuth Kit | 4.x | Analyse filesystem | Ubuntu |
| Belkasoft RAM Capturer | 2024.x | Capture mémoire | Windows |
| FTK Imager | 4.x | Imagerie forensique | Windows |

#### Preuves Collectées
- **Dump mémoire :** [Taille, Hash SHA256]
- **Image disque :** [Taille, Hash SHA256]
- **Logs système :** [Nombre de fichiers, période couverte]
- **Artefacts réseau :** [Captures, logs]
- **Registre Windows :** [Ruches extraites]

---

### TIMELINE DE L'INCIDENT

| Heure | Événement | Source | Criticité |
|-------|-----------|--------|-----------|
| T+00:00 | Exécution initiale de SystemOptimizer.exe | Logs système | Élevée |
| T+00:05 | Connexion C2 vers 192.168.56.10:8080 | Analyse réseau | Critique |
| T+00:10 | Énumération système débutée | Analyse mémoire | Moyenne |
| T+00:20 | Élévation de privilèges tentée | Logs sécurité | Élevée |
| T+00:30 | Persistance installée (Registre) | Analyse registre | Critique |
| T+00:45 | Collecte de données sensibles | Analyse filesystem | Élevée |
| T+01:00 | Exfiltration de données | Analyse réseau | Critique |
| T+01:15 | Nettoyage partiel des traces | Logs système | Moyenne |

---

### ANALYSE TECHNIQUE DÉTAILLÉE

#### 1. Analyse de la Mémoire Vive

**Processus Malveillants Identifiés :**
```
PID    Nom du Processus    PPID   Threads   Heure de Création
----   -----------------   ----   -------   -----------------
[PID]  SystemOptimizer.exe [PPID] [Nb]      [Timestamp]
[PID]  OptimizationSvc.exe [PPID] [Nb]      [Timestamp]
```

**Connexions Réseau Suspectes :**
```
Processus          Adresse Locale    Adresse Distante      État
---------          -------------     ----------------      ----
SystemOptimizer    192.168.56.20:X   192.168.56.10:8080   ESTABLISHED
SystemOptimizer    192.168.56.20:Y   192.168.56.10:8443   ESTABLISHED
```

**Injections de Code Détectées :**
- **Processus cible :** [Nom, PID]
- **Type d'injection :** [Process Hollowing/DLL Injection/etc.]
- **Adresse mémoire :** [Offset]
- **Taille du code injecté :** [Bytes]

#### 2. Analyse du Système de Fichiers

**Fichiers Malveillants :**
| Chemin Complet | Taille | Hash MD5 | Date Création | Date Modification |
|----------------|--------|----------|---------------|-------------------|
| C:\Windows\System32\OptimizationService.exe | [Size] | [Hash] | [Date] | [Date] |
| C:\Users\[User]\Downloads\SystemOptimizer.exe | [Size] | [Hash] | [Date] | [Date] |

**Mécanismes de Persistance :**
- **Registre :** `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\OptimizationService`
- **Tâche programmée :** `System Optimization` (Démarrage utilisateur)
- **Service Windows :** `OptimizationSvc` (Démarrage automatique)

**Données Exfiltrées :**
- **Fichier :** C:\Windows\Temp\.system\collected_data.zip
- **Taille :** [Size]
- **Contenu :** Documents utilisateur, credentials, informations système
- **Méthode d'exfiltration :** HTTP POST vers 192.168.56.10

#### 3. Analyse Réseau

**Infrastructure C2 Identifiée :**
- **Serveur C2 :** 192.168.56.10
- **Ports utilisés :** 8080 (HTTP), 8443 (HTTPS)
- **Protocole :** Silver C2 Framework
- **Fréquence de beacon :** [Intervalle]
- **Jitter observé :** [Variation]

**Communications Interceptées :**
```
Timestamp                 Source -> Destination     Taille   Contenu
------------------------  -----------------------   ------   -------
[Time] 192.168.56.20:X -> 192.168.56.10:8080      [Size]   Beacon initial
[Time] 192.168.56.10:8080 -> 192.168.56.20:X      [Size]   Commandes C2
[Time] 192.168.56.20:Y -> 192.168.56.10:8080      [Size]   Exfiltration
```

---

### INDICATEURS DE COMPROMISSION (IOCs)

#### Fichiers
```
Hash MD5/SHA256                                  Nom du Fichier
-------------------------------------------     ----------------
[Hash1]                                         SystemOptimizer.exe
[Hash2]                                         OptimizationService.exe
[Hash3]                                         collected_data.zip
```

#### Réseau
```
Type          Valeur                    Description
----          ------                    -----------
IP            192.168.56.10             Serveur C2 Silver
Port          8080/tcp                  Listener HTTP C2
Port          8443/tcp                  Listener HTTPS C2
Domain        project.local             Domaine DNS C2 (si utilisé)
```

#### Registre
```
Clé de Registre                                               Valeur
---------------------------------------------------------------  ------
HKCU\Software\Microsoft\Windows\CurrentVersion\Run           OptimizationService
HKLM\System\CurrentControlSet\Services\OptimizationSvc       Service malveillant
```

#### Processus
```
Nom du Processus        PID Range    Ligne de Commande
----------------        ---------    -----------------
SystemOptimizer.exe     [Range]      C:\Users\[User]\Downloads\SystemOptimizer.exe
OptimizationService.exe [Range]      C:\Windows\System32\OptimizationService.exe
```

---

### PREUVES TECHNIQUES

#### Captures d'Écran
1. **Volatility - Liste des processus** : [Lien vers capture]
2. **Autopsy - Timeline** : [Lien vers capture]
3. **Connexions réseau** : [Lien vers capture]
4. **Artefacts de persistance** : [Lien vers capture]

#### Fichiers Joints
- **Dump Volatility complet** : pslist-full.txt
- **Timeline Autopsy** : timeline-complete.csv
- **Export registre** : registry-malicious-keys.reg
- **Logs d'événements** : security-events-filtered.txt

---

### TECHNIQUES D'ATTAQUE IDENTIFIÉES (MITRE ATT&CK)

| Technique ID | Nom | Description | Preuve |
|--------------|-----|-------------|--------|
| T1566.001 | Spearphishing Attachment | Payload livré via fichier | SystemOptimizer.exe |
| T1055 | Process Injection | Injection dans explorer.exe | Analyse Volatility |
| T1547.001 | Registry Run Keys | Persistance via registre | Clé HKCU\Run |
| T1053.005 | Scheduled Task | Tâche programmée | "System Optimization" |
| T1543.003 | Windows Service | Service malveillant | OptimizationSvc |
| T1005 | Data from Local System | Collecte de fichiers locaux | collected_data.zip |
| T1041 | Exfiltration Over C2 Channel | Exfiltration via C2 | Trafic vers 192.168.56.10 |

---

### RECOMMANDATIONS

#### Mesures Immédiates (0-24h)
1. **Isolement des systèmes compromis**
2. **Révocation des accès compromis**
3. **Blocage des IOCs réseau** (IP, domaines)
4. **Scan des autres systèmes** avec les IOCs identifiés

#### Mesures à Court Terme (1-7 jours)
1. **Renforcement de la détection EDR/XDR**
2. **Mise à jour des signatures antivirus**
3. **Audit des mécanismes de persistance**
4. **Formation des équipes SOC**

#### Mesures à Long Terme (1-3 mois)
1. **Révision des politiques de sécurité**
2. **Amélioration du monitoring réseau**
3. **Tests de détection réguliers**
4. **Programme de sensibilisation utilisateurs**

---

### LEÇONS APPRISES

#### Points Positifs
- [Éléments qui ont bien fonctionné dans la détection]
- [Outils efficaces pour l'investigation]

#### Points d'Amélioration
- [Lacunes identifiées dans la détection]
- [Processus à optimiser]

#### Recommandations Techniques
- [Améliorations techniques spécifiques]
- [Nouveaux outils à déployer]

---

### CONCLUSION

[Synthèse de l'investigation, impact réel, efficacité des mesures de détection, recommandations principales]

---

### ANNEXES

#### Annexe A : Détails Techniques Volatility
[Sortie complète des commandes Volatility importantes]

#### Annexe B : Timeline Autopsy Complète  
[Événements détaillés de la timeline]

#### Annexe C : Analyse des Logs
[Extraits pertinents des logs système]

#### Annexe D : Preuves Numériques
[Hashes, métadonnées, certificats]

---

**Signature :**  
[Nom de l'investigateur]  
[Titre]  
[Date et signature numérique]  

---

**Distribution :**  
- RSSI
- Équipe SOC  
- Management IT
- [Autres parties prenantes]
```

---

## 📊 Template 2 : Résumé Exécutif

```markdown
# RÉSUMÉ EXÉCUTIF - INVESTIGATION FORENSIQUE
## Projet M1 : Simulation Silver C2

### 🎯 CONTEXTE

**Incident :** Simulation d'attaque post-exploitation avec framework Silver C2  
**Date :** [Date de l'investigation]  
**Durée de l'investigation :** [Heures/Jours]  
**Équipe :** [Noms des investigateurs]  

### 🔍 RÉSULTATS CLÉS

#### Confirmation de Compromission
✅ **Intrusion confirmée** - Présence d'implant Silver C2 détectée  
✅ **Persistance établie** - Mécanismes multiples identifiés  
✅ **Exfiltration de données** - 2.3 MB de données collectées  
✅ **Connexions C2 actives** - Communications vers 192.168.56.10  

#### Étendue de l'Attaque
- **1 système compromis** (VM Windows 10)
- **3 mécanismes de persistance** installés
- **Durée estimée :** 75 minutes d'activité malveillante
- **Aucune propagation latérale** détectée

### 📈 IMPACT BUSINESS

| Aspect | Évaluation | Détails |
|--------|------------|---------|
| **Confidentialité** | Élevé | Documents sensibles collectés |
| **Intégrité** | Moyen | Fichiers système modifiés |
| **Disponibilité** | Faible | Aucun impact service |
| **Réputation** | Faible | Incident de laboratoire |

### 🛡️ EFFICACITÉ DES CONTRÔLES

#### Détection
- ❌ **EDR/Antivirus** : N/A (désactivé pour simulation)
- ✅ **Analyse forensique** : 100% des artefacts détectés
- ✅ **Investigation manuelle** : Timeline complète reconstituée

#### Réponse
- ✅ **Collecte de preuves** : Complète et intègre
- ✅ **Analyse technique** : Approfondie
- ✅ **Documentation** : Détaillée et reproductible

### 💡 RECOMMANDATIONS PRIORITAIRES

1. **Déploiement EDR** - Solution de détection comportementale
2. **Monitoring réseau** - Surveillance des connexions sortantes
3. **Baseline de sécurité** - Durcissement des postes de travail
4. **Formation équipes** - Sensibilisation aux techniques C2

### 💰 COÛT ESTIMÉ DE REMÉDIATION

- **Déploiement EDR** : [Budget estimé]
- **Formation équipes** : [Budget estimé]
- **Amélioration monitoring** : [Budget estimé]
- **Total estimé** : [Budget total]

### 📅 PLAN D'ACTION

| Action | Responsable | Délai | Priorité |
|--------|-------------|-------|----------|
| Évaluation solutions EDR | RSSI | 2 semaines | Haute |
| Audit configuration réseau | IT | 1 semaine | Haute |
| Formation SOC | RH/RSSI | 1 mois | Moyenne |
| Tests de détection | SOC | Continu | Moyenne |

### 🎓 VALEUR PÉDAGOGIQUE

Cette simulation démontre :
- L'efficacité des techniques post-exploitation modernes
- L'importance d'une approche forensique méthodique
- La complémentarité des outils d'investigation
- La nécessité d'une détection comportementale

---

**Préparé par :** [Nom]  
**Validé par :** [RSSI]  
**Date :** [Date]
```

---

## 📋 Template 3 : Rapport d'Analyse Technique (Format Court)

```markdown
# ANALYSE TECHNIQUE - SILVER C2 FORENSICS

## 🔬 MÉTHODOLOGIE

**Infrastructure d'analyse :**
- VM1 (Kali Linux) - Serveur Silver C2
- VM2 (Windows 10) - Système compromis  
- VM3 (Ubuntu) - Station d'analyse forensique

**Outils déployés :**
- Volatility 3.x (analyse mémoire)
- Autopsy 4.20+ (investigation disque)
- Belkasoft RAM Capturer (collecte mémoire)
- The Sleuth Kit (analyse filesystem)

## 🎯 ARTEFACTS IDENTIFIÉS

### Processus Malveillants
```
Nom                     PID    PPID   Création
----------------------  -----  -----  ---------------------
SystemOptimizer.exe     1234   856    2024-08-27 14:32:15
OptimizationService.exe 5678   4      2024-08-27 14:35:22
```

### Persistance
```
Type                    Localisation
-----------------       ------------------------------------------
Registre                HKCU\Run\OptimizationService
Tâche programmée        "System Optimization"
Service Windows         OptimizationSvc
```

### Communications Réseau
```
Source              Destination         Protocole   Volume
-----------------   -----------------   ---------   --------
192.168.56.20:X     192.168.56.10:8080  HTTP       1.2 MB
192.168.56.20:Y     192.168.56.10:8443  HTTPS      850 KB
```

## 🔍 TECHNIQUES DÉTECTÉES

- **T1566.001** - Spearphishing Attachment (payload initial)
- **T1055** - Process Injection (migration vers explorer.exe)
- **T1547.001** - Registry Run Keys (persistance)
- **T1053.005** - Scheduled Task (persistance)
- **T1005** - Data from Local System (collecte)
- **T1041** - Exfiltration Over C2 Channel (exfiltration)

## 📊 TIMELINE CRITIQUE

```
14:32:00 - Exécution SystemOptimizer.exe
14:32:15 - Connexion C2 établie
14:35:22 - Installation service malveillant  
14:45:30 - Début collecte de données
14:58:45 - Exfiltration de collected_data.zip
15:12:10 - Nettoyage partiel des logs
```

## 🎯 INDICATEURS DE COMPROMISSION

**Hashes (MD5) :**
- SystemOptimizer.exe: `[hash]`
- OptimizationService.exe: `[hash]`

**Réseau :**
- IP C2: `192.168.56.10`
- Ports: `8080/tcp`, `8443/tcp`

**Registre :**
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\OptimizationService`

## ✅ RECOMMANDATIONS

1. **Détection comportementale** - Déployer EDR moderne
2. **Monitoring réseau** - Surveiller connexions sortantes
3. **Audit persistance** - Scanner mécanismes de démarrage  
4. **Formation équipes** - Sensibilisation techniques C2

---

*Analyse réalisée dans le cadre du Projet M1 - Cyber Forensics*
```

---

## 📋 Template 4 : Checklist de Validation du Rapport

```markdown
# CHECKLIST DE VALIDATION - RAPPORT FORENSIQUE

## ✅ COMPLÉTUDE DU RAPPORT

### Informations Générales
- [ ] Référence du cas unique
- [ ] Date et heure de l'investigation
- [ ] Nom(s) de l'investigateur/des investigateurs
- [ ] Classification de sécurité appropriée
- [ ] Statut du rapport (draft/final)

### Résumé Exécutif
- [ ] Contexte de l'incident clairement expliqué
- [ ] Conclusions principales résumées
- [ ] Impact business évalué
- [ ] Recommandations prioritaires listées

### Méthodologie
- [ ] Outils utilisés documentés (versions)
- [ ] Processus d'investigation décrit
- [ ] Chaîne de custody respectée
- [ ] Preuves collectées inventoriées

### Analyse Technique
- [ ] Timeline détaillée et cohérente
- [ ] Artefacts techniques documentés
- [ ] IOCs complets et utilisables
- [ ] Techniques d'attaque mappées (MITRE ATT&CK)

### Preuves et Annexes
- [ ] Captures d'écran pertinentes incluses
- [ ] Logs et outputs d'outils joints
- [ ] Hashes et métadonnées vérifiés
- [ ] Fichiers de preuve archivés

## ✅ QUALITÉ TECHNIQUE

### Exactitude
- [ ] Informations techniques vérifiées
- [ ] Hashes calculés et confirmés
- [ ] Timeline cross-référencée entre sources
- [ ] IOCs testés et validés

### Complétude
- [ ] Toutes les questions d'investigation adressées
- [ ] Lacunes identifiées et documentées
- [ ] Hypothèses alternatives considérées
- [ ] Limites de l'investigation mentionnées

### Reproductibilité
- [ ] Commandes documentées avec syntaxe exacte
- [ ] Paramètres d'outils spécifiés
- [ ] Environnement d'investigation décrit
- [ ] Procédures reproductibles

## ✅ PRÉSENTATION

### Structure
- [ ] Plan logique et cohérent
- [ ] Sections clairement délimitées
- [ ] Transitions fluides entre parties
- [ ] Annexes organisées

### Lisibilité
- [ ] Langage adapté à l'audience
- [ ] Termes techniques expliqués
- [ ] Mise en forme cohérente
- [ ] Tableaux et graphiques lisibles

### Professional
- [ ] Orthographe et grammaire correctes
- [ ] Ton professionnel maintenu
- [ ] Objectivité préservée
- [ ] Conclusions justifiées

## ✅ RECOMMANDATIONS

### Pertinence
- [ ] Recommandations liées aux découvertes
- [ ] Priorités clairement établies
- [ ] Faisabilité évaluée
- [ ] Coûts estimés (si applicable)

### Actionabilité
- [ ] Actions concrètes proposées
- [ ] Responsables identifiés
- [ ] Délais réalistes
- [ ] Métriques de succès définies

## ✅ CONFORMITÉ

### Standards
- [ ] Respect des standards forensiques (ISO 27037)
- [ ] Conformité aux procédures internes
- [ ] Respect de la réglementation applicable
- [ ] Bonnes pratiques industry suivies

### Archivage
- [ ] Rapport versionné et daté
- [ ] Preuves numériques archivées
- [ ] Chaîne de custody documentée
- [ ] Accès sécurisé aux archives

---

**Validé par :** [Nom, Titre]  
**Date de validation :** [Date]  
**Version du rapport :** [Version]
```

---

## 🎨 Template 5 : Présentation PowerPoint (Structure)

```markdown
# STRUCTURE PRÉSENTATION - INVESTIGATION SILVER C2

## Slide 1 : Page de Titre
- Titre : "Investigation Forensique - Silver C2"
- Sous-titre : "Projet M1 - Cyber Forensics"
- Date, Investigateur, Organisme

## Slide 2 : Agenda
1. Contexte et Objectifs
2. Méthodologie d'Investigation
3. Découvertes Principales
4. Analyse Technique
5. Impact et Recommandations
6. Questions & Discussion

## Slide 3 : Contexte de l'Investigation
- Simulation d'attaque post-exploitation
- Framework Silver C2 utilisé
- Infrastructure de laboratoire (3 VMs)
- Objectifs pédagogiques

## Slide 4 : Infrastructure d'Investigation
[Diagramme des 3 VMs : Kali (Attaquant), Windows (Victime), Ubuntu (Analyste)]

## Slide 5 : Outils Forensiques Déployés
- Volatility 3.x (Analyse mémoire)
- Autopsy 4.20+ (Investigation disque)
- Belkasoft RAM Capturer (Collecte mémoire)
- The Sleuth Kit (Analyse filesystem)

## Slide 6 : Timeline de l'Attaque
[Graphique temporel des événements principaux]

## Slide 7 : Processus Malveillants Identifiés
[Tableau des processus avec PID, noms, dates]

## Slide 8 : Mécanismes de Persistance
[Schéma des 3 types : Registre, Tâche, Service]

## Slide 9 : Communications C2
[Graphique réseau montrant les flux]

## Slide 10 : Données Exfiltrées
[Volume, type, méthode d'exfiltration]

## Slide 11 : Mapping MITRE ATT&CK
[Matrice des techniques détectées]

## Slide 12 : Indicateurs de Compromission
[Hashes, IPs, noms de fichiers, clés registre]

## Slide 13 : Efficacité de la Détection
[Graphique : Ce qui a été détecté vs manqué]

## Slide 14 : Impact Business
[Matrice Impact vs Probabilité]

## Slide 15 : Recommandations Prioritaires
1. Déploiement EDR
2. Monitoring réseau
3. Formation équipes
4. Tests réguliers

## Slide 16 : Plan d'Action
[Timeline des actions recommandées]

## Slide 17 : Leçons Apprises
- Points positifs de l'investigation
- Améliorations identifiées
- Valeur pédagogique du projet

## Slide 18 : Questions & Discussion
[Slide d'ouverture pour les questions]

## Slide 19 : Contacts et Ressources
- Contact investigateur
- Liens vers documentation
- Ressources additionnelles
```

---

**Prochaine étape :** Scripts d'automatisation pour l'ensemble du projet M1.

---

*Templates de Rapport pour Projet M1 - Cyber Forensics*