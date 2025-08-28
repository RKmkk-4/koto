#!/bin/bash

# Script d'installation automatique de Silver C2 sur Kali Linux
# Auteur: Assistant Scout
# Version: 1.0

set -e

# Couleurs pour les messages
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Fonctions utilitaires
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

# Vérifier si le script est exécuté en tant que root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        log_error "Ce script ne doit pas être exécuté en tant que root pour la sécurité"
        log_info "Exécutez: chmod +x install-silver-c2.sh && ./install-silver-c2.sh"
        exit 1
    fi
}

# Vérifier la distribution
check_distribution() {
    if ! grep -q "Kali" /etc/os-release; then
        log_warning "Ce script est optimisé pour Kali Linux"
        read -p "Voulez-vous continuer? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Mise à jour du système
update_system() {
    log_info "Mise à jour du système..."
    sudo apt update && sudo apt upgrade -y
    log_success "Système mis à jour"
}

# Installation des dépendances
install_dependencies() {
    log_info "Installation des dépendances..."
    sudo apt install -y curl wget git build-essential mingw-w64 binutils-mingw-w64 g++-mingw-w64
    log_success "Dépendances installées"
}

# Vérifier et installer Go si nécessaire
install_go() {
    local go_version="1.21.5"
    local go_installed=false
    
    if command -v go &> /dev/null; then
        local current_version=$(go version | awk '{print $3}' | sed 's/go//')
        log_info "Go version détectée: $current_version"
        
        # Vérifier si la version est suffisante (>=1.19)
        if [[ $(echo -e "1.19\n$current_version" | sort -V | head -n1) == "1.19" ]]; then
            go_installed=true
            log_success "Version de Go suffisante"
        fi
    fi
    
    if [[ $go_installed == false ]]; then
        log_info "Installation de Go $go_version..."
        
        # Télécharger Go
        wget -q https://go.dev/dl/go${go_version}.linux-amd64.tar.gz -O /tmp/go${go_version}.linux-amd64.tar.gz
        
        # Supprimer l'ancienne installation
        sudo rm -rf /usr/local/go
        
        # Installer Go
        sudo tar -C /usr/local -xzf /tmp/go${go_version}.linux-amd64.tar.gz
        
        # Ajouter Go au PATH
        if ! grep -q "/usr/local/go/bin" ~/.bashrc; then
            echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
        fi
        
        # Appliquer les changements
        export PATH=$PATH:/usr/local/go/bin
        
        # Nettoyer
        rm -f /tmp/go${go_version}.linux-amd64.tar.gz
        
        log_success "Go $go_version installé"
    fi
}

# Installer Silver C2
install_silver() {
    log_info "Installation de Silver C2..."
    
    # Méthode 1: Script d'installation officiel
    if curl -fsSL https://sliver.sh/install | sudo bash; then
        log_success "Silver C2 installé via le script officiel"
        return 0
    fi
    
    log_warning "Le script officiel a échoué, essai de compilation depuis les sources..."
    
    # Méthode 2: Compilation depuis les sources
    cd /tmp
    git clone https://github.com/BishopFox/sliver.git
    cd sliver
    
    if make; then
        sudo make install
        log_success "Silver C2 compilé et installé depuis les sources"
    else
        log_error "Échec de la compilation de Silver C2"
        exit 1
    fi
    
    cd ~
    rm -rf /tmp/sliver
}

# Vérifier l'installation
verify_installation() {
    log_info "Vérification de l'installation..."
    
    if command -v sliver-server &> /dev/null && command -v sliver-client &> /dev/null; then
        log_success "Silver C2 installé avec succès!"
        
        echo
        log_info "Versions installées:"
        sliver-server version
        sliver-client version
        
        return 0
    else
        log_error "L'installation a échoué"
        return 1
    fi
}

# Créer la structure de répertoires
create_directories() {
    log_info "Création de la structure de répertoires..."
    
    mkdir -p ~/silver-workspace/{payloads,logs,configs,scripts}
    
    log_success "Répertoires créés dans ~/silver-workspace/"
}

# Créer des scripts utilitaires
create_utility_scripts() {
    log_info "Création des scripts utilitaires..."
    
    # Script de démarrage du serveur
    cat > ~/silver-workspace/scripts/start-server.sh << 'EOF'
#!/bin/bash
echo "Démarrage du serveur Silver C2..."
sudo sliver-server daemon
EOF
    
    # Script de connexion client
    cat > ~/silver-workspace/scripts/connect-client.sh << 'EOF'
#!/bin/bash
echo "Connexion au serveur Silver C2..."
sliver-client
EOF
    
    # Script de génération d'implant Windows
    cat > ~/silver-workspace/scripts/generate-windows-implant.sh << 'EOF'
#!/bin/bash
read -p "IP du serveur C2: " server_ip
read -p "Port (défaut 8080): " server_port
server_port=${server_port:-8080}

echo "Génération de l'implant Windows..."
sliver-client -c "generate --http ${server_ip}:${server_port} --os windows --arch amd64 --format exe --save ~/silver-workspace/payloads/"
EOF
    
    # Rendre les scripts exécutables
    chmod +x ~/silver-workspace/scripts/*.sh
    
    log_success "Scripts utilitaires créés dans ~/silver-workspace/scripts/"
}

# Configuration de base
configure_silver() {
    log_info "Configuration de base de Silver..."
    
    # Créer le répertoire de configuration s'il n'existe pas
    mkdir -p ~/.sliver
    
    # Note: La configuration se fait principalement via l'interface
    log_info "La configuration détaillée se fera via l'interface Silver"
}

# Afficher les instructions post-installation
show_post_install_instructions() {
    echo
    log_success "Installation terminée avec succès!"
    echo
    echo -e "${BLUE}Instructions pour démarrer:${NC}"
    echo "1. Démarrer le serveur: sudo sliver-server daemon"
    echo "2. Se connecter: sliver-client"
    echo "3. Créer un listener: http --lhost 0.0.0.0 --lport 8080"
    echo "4. Générer un implant: generate --http <IP>:8080 --os windows --format exe"
    echo
    echo -e "${BLUE}Scripts utilitaires disponibles:${NC}"
    echo "- ~/silver-workspace/scripts/start-server.sh"
    echo "- ~/silver-workspace/scripts/connect-client.sh"
    echo "- ~/silver-workspace/scripts/generate-windows-implant.sh"
    echo
    echo -e "${BLUE}Documentation:${NC}"
    echo "- Guide local: ~/guide-silver-c2-kali.md"
    echo "- Wiki officiel: https://github.com/BishopFox/sliver/wiki"
    echo
    echo -e "${YELLOW}Note:${NC} Redémarrez votre terminal ou exécutez 'source ~/.bashrc' pour charger Go"
}

# Fonction principale
main() {
    echo -e "${BLUE}=== Installation de Silver C2 sur Kali Linux ===${NC}"
    echo
    
    check_root
    check_distribution
    
    update_system
    install_dependencies
    install_go
    install_silver
    
    if verify_installation; then
        create_directories
        create_utility_scripts
        configure_silver
        show_post_install_instructions
    else
        log_error "L'installation a échoué. Consultez les logs ci-dessus."
        exit 1
    fi
}

# Gestion des signaux
trap 'log_error "Installation interrompue"; exit 130' INT TERM

# Exécution du script principal
main "$@"