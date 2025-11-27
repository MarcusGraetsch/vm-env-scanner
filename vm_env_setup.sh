#!/usr/bin/env bash
###############################################################################
# VM Environment Setup Script v2.0.0
#
# Purpose: Automatically install and configure a complete DevOps development
#          environment based on the VM environment scan results.
#
# Usage: ./vm_env_setup.sh [OPTIONS]
#
# Options:
#   --scan-file FILE    Path to scan JSON (default: vm_env_scan_report.json)
#   --dry-run           Show what would be installed without installing
#   --skip-cloud        Skip cloud provider CLI installations
#   --skip-ide          Skip IDE installations
#   --skip-k8s          Skip Kubernetes tools
#   --skip-iac          Skip IaC tools
#   --help              Show this help message
#
# Requirements:
#   - Ubuntu/Debian-based system
#   - sudo access
#   - Internet connectivity
#   - jq (will be auto-installed if missing)
###############################################################################

set -euo pipefail

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
SCAN_FILE="vm_env_scan_report.json"
DRY_RUN=false
SKIP_CLOUD=false
SKIP_IDE=false
SKIP_K8S=false
SKIP_IAC=false
LOG_FILE="vm_env_setup_$(date +%Y%m%d_%H%M%S).log"

# Track installations
declare -a INSTALLED=()
declare -a FAILED=()
declare -a SKIPPED=()
declare -a WARNINGS=()

###############################################################################
# Utility Functions
###############################################################################

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $*" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" | tee -a "$LOG_FILE"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*" | tee -a "$LOG_FILE"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*" | tee -a "$LOG_FILE"
}

section() {
    echo ""
    echo -e "${MAGENTA}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${MAGENTA}  $*${NC}"
    echo -e "${MAGENTA}═══════════════════════════════════════════════════════════${NC}"
    echo ""
}

show_help() {
    sed -n '/^###/,/^###/p' "$0" | sed '1d;$d' | sed 's/^# //; s/^#//'
    exit 0
}

###############################################################################
# Parse Arguments
###############################################################################

while [[ $# -gt 0 ]]; do
    case $1 in
        --scan-file)
            SCAN_FILE="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --skip-cloud)
            SKIP_CLOUD=true
            shift
            ;;
        --skip-ide)
            SKIP_IDE=true
            shift
            ;;
        --skip-k8s)
            SKIP_K8S=true
            shift
            ;;
        --skip-iac)
            SKIP_IAC=true
            shift
            ;;
        --help)
            show_help
            ;;
        *)
            log_error "Unknown option: $1"
            show_help
            ;;
    esac
done

###############################################################################
# Check Prerequisites
###############################################################################

section "Checking Prerequisites"

if [[ ! -f "$SCAN_FILE" ]]; then
    log_error "Scan file not found: $SCAN_FILE"
    log_info "Please run vm_env_scanner_v2.sh first to generate the scan report"
    exit 1
fi

log "Found scan file: $SCAN_FILE"

# Install jq if not available
if ! command -v jq &> /dev/null; then
    log_warn "jq not found, installing..."
    if [[ "$DRY_RUN" == false ]]; then
        sudo apt-get update -qq
        sudo apt-get install -y jq
    fi
fi

# Check sudo access
if ! sudo -n true 2>/dev/null; then
    log_warn "This script requires sudo access. You may be prompted for your password."
fi

###############################################################################
# Parse Scan Results
###############################################################################

section "Analyzing Environment"

# Extract key information
OS_RELEASE=$(jq -r '.system.os_release' "$SCAN_FILE")
ARCH=$(jq -r '.system.arch' "$SCAN_FILE")
HAS_DOCKER=$(jq -r '.containers.docker_installed' "$SCAN_FILE")
DOCKER_RUNNING=$(jq -r '.containers.docker_running' "$SCAN_FILE")
IN_DOCKER_GROUP=$(jq -r '.user.in_docker_group' "$SCAN_FILE")
PASSWORDLESS_SUDO=$(jq -r '.user.passwordless_sudo' "$SCAN_FILE")
TLS_INTERCEPTION=$(jq -r '.tls.interception_detected' "$SCAN_FILE")
PEP668_ACTIVE=$(jq -r '.packages.pep668_active' "$SCAN_FILE")

log_info "OS: $OS_RELEASE ($ARCH)"
log_info "Docker: $HAS_DOCKER (Running: $DOCKER_RUNNING)"
log_info "Passwordless sudo: $PASSWORDLESS_SUDO"
log_info "TLS Interception: $TLS_INTERCEPTION"
log_info "PEP 668 Active: $PEP668_ACTIVE"

# Check for warnings in scan
SCAN_WARNINGS=$(jq -r '.warnings[]' "$SCAN_FILE" 2>/dev/null || echo "")
if [[ -n "$SCAN_WARNINGS" ]]; then
    log_warn "Scan warnings detected:"
    echo "$SCAN_WARNINGS" | while read -r warning; do
        log_warn "  - $warning"
    done
fi

###############################################################################
# TLS Certificate Handling
###############################################################################

section "Checking TLS/SSL Configuration"

if [[ "$TLS_INTERCEPTION" == "yes" ]]; then
    WARNINGS+=("TLS interception detected - Corporate firewall is intercepting HTTPS traffic")
    log_warn "Corporate TLS interception detected (issuer: fw-int.hisolutions.com)"
    log_warn "This may cause issues with:"
    log_warn "  - Package installations (npm, pip, snap, apt)"
    log_warn "  - Git operations over HTTPS"
    log_warn "  - Cloud provider CLI authentication"
    log_warn "  - Docker image pulls"
    echo ""
    log_info "Solutions:"
    log_info "  1. Export corporate CA certificate and install it system-wide"
    log_info "  2. Use HTTP mirrors where available"
    log_info "  3. Configure tools to accept the corporate certificate"
    log_info "  4. Contact IT for the corporate root CA certificate"
    echo ""

    # Check if we can find the corporate cert
    CORP_CERT_ISSUER="fw-int.hisolutions.com"
    log_info "Attempting to extract corporate certificate..."

    if [[ "$DRY_RUN" == false ]]; then
        # Try to get the certificate from github.com
        if openssl s_client -connect github.com:443 -showcerts </dev/null 2>/dev/null | \
           openssl x509 -outform PEM > /tmp/corporate_ca.pem 2>/dev/null; then
            log_success "Corporate certificate extracted to /tmp/corporate_ca.pem"
            log_info "To install it system-wide, run:"
            log_info "  sudo cp /tmp/corporate_ca.pem /usr/local/share/ca-certificates/corporate-ca.crt"
            log_info "  sudo update-ca-certificates"

            read -p "Install corporate certificate now? (y/N): " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                sudo cp /tmp/corporate_ca.pem /usr/local/share/ca-certificates/corporate-ca.crt
                sudo update-ca-certificates
                log_success "Corporate certificate installed"
            else
                SKIPPED+=("Corporate certificate installation (manual step required)")
            fi
        fi
    fi
else
    log_success "No TLS interception detected - Standard HTTPS should work fine"
fi

###############################################################################
# Update System
###############################################################################

section "Updating System Packages"

if [[ "$DRY_RUN" == false ]]; then
    log "Updating apt package lists..."
    sudo apt-get update -qq
    log "Upgrading installed packages..."
    sudo apt-get upgrade -y
    log_success "System packages updated"
else
    log_info "[DRY RUN] Would update and upgrade system packages"
fi

###############################################################################
# Install Base Development Tools
###############################################################################

section "Installing Base Development Tools"

BASE_PACKAGES=(
    "build-essential"
    "software-properties-common"
    "apt-transport-https"
    "ca-certificates"
    "gnupg"
    "lsb-release"
    "curl"
    "wget"
    "git"
    "jq"
    "yq"
    "unzip"
    "zip"
    "tree"
    "htop"
    "tmux"
    "vim"
    "nano"
)

for pkg in "${BASE_PACKAGES[@]}"; do
    if ! dpkg -l | grep -q "^ii  $pkg "; then
        log "Installing $pkg..."
        if [[ "$DRY_RUN" == false ]]; then
            if sudo apt-get install -y "$pkg" 2>&1 | tee -a "$LOG_FILE"; then
                INSTALLED+=("$pkg")
            else
                FAILED+=("$pkg")
            fi
        else
            log_info "[DRY RUN] Would install $pkg"
        fi
    else
        log_info "$pkg already installed"
    fi
done

###############################################################################
# Install Node.js and npm
###############################################################################

section "Installing Node.js and npm"

NODE_INSTALLED=$(jq -r '.dev_tools.node.installed' "$SCAN_FILE")

if [[ "$NODE_INSTALLED" != "true" ]]; then
    log "Installing Node.js LTS via NodeSource..."
    if [[ "$DRY_RUN" == false ]]; then
        # Install Node.js 20.x LTS
        curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
        sudo apt-get install -y nodejs

        if command -v node &> /dev/null; then
            NODE_VERSION=$(node --version)
            NPM_VERSION=$(npm --version)
            log_success "Node.js $NODE_VERSION and npm $NPM_VERSION installed"
            INSTALLED+=("node" "npm")
        else
            log_error "Node.js installation failed"
            FAILED+=("node" "npm")
        fi
    else
        log_info "[DRY RUN] Would install Node.js 20.x LTS"
    fi
else
    log_success "Node.js already installed"
fi

# Install yarn if needed
if ! command -v yarn &> /dev/null && [[ "$DRY_RUN" == false ]]; then
    log "Installing Yarn..."
    sudo npm install -g yarn
    INSTALLED+=("yarn")
fi

###############################################################################
# Install Python Development Tools
###############################################################################

section "Installing Python Development Tools"

if [[ "$PEP668_ACTIVE" == "yes" ]]; then
    log_warn "PEP 668 is active - using pipx for global Python tools"

    # Ensure pipx is installed
    if ! command -v pipx &> /dev/null; then
        log "Installing pipx..."
        if [[ "$DRY_RUN" == false ]]; then
            sudo apt-get install -y pipx
            pipx ensurepath
            INSTALLED+=("pipx")
        fi
    fi
else
    log_info "PEP 668 not active - pip install available"
fi

# Install Python development packages
PYTHON_PACKAGES=(
    "python3-dev"
    "python3-pip"
    "python3-venv"
    "python3-setuptools"
)

for pkg in "${PYTHON_PACKAGES[@]}"; do
    if ! dpkg -l | grep -q "^ii  $pkg "; then
        log "Installing $pkg..."
        if [[ "$DRY_RUN" == false ]]; then
            sudo apt-get install -y "$pkg"
            INSTALLED+=("$pkg")
        fi
    fi
done

###############################################################################
# Install Kubernetes Tools
###############################################################################

if [[ "$SKIP_K8S" == false ]]; then
    section "Installing Kubernetes Tools"

    # kubectl
    KUBECTL_INSTALLED=$(jq -r '.dev_tools.kubectl.installed' "$SCAN_FILE")
    if [[ "$KUBECTL_INSTALLED" != "true" ]]; then
        log "Installing kubectl..."
        if [[ "$DRY_RUN" == false ]]; then
            curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
            sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
            rm kubectl
            INSTALLED+=("kubectl")
            log_success "kubectl installed"
        else
            log_info "[DRY RUN] Would install kubectl"
        fi
    else
        log_success "kubectl already installed"
    fi

    # Helm
    HELM_INSTALLED=$(jq -r '.dev_tools.helm.installed' "$SCAN_FILE")
    if [[ "$HELM_INSTALLED" != "true" ]]; then
        log "Installing Helm..."
        if [[ "$DRY_RUN" == false ]]; then
            curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
            INSTALLED+=("helm")
            log_success "Helm installed"
        else
            log_info "[DRY RUN] Would install Helm"
        fi
    else
        log_success "Helm already installed"
    fi

    # k9s
    K9S_INSTALLED=$(jq -r '.dev_tools.k9s.installed' "$SCAN_FILE")
    if [[ "$K9S_INSTALLED" != "true" ]]; then
        log "Installing k9s..."
        if [[ "$DRY_RUN" == false ]]; then
            K9S_VERSION=$(curl -s https://api.github.com/repos/derailed/k9s/releases/latest | jq -r .tag_name)
            curl -sL "https://github.com/derailed/k9s/releases/download/${K9S_VERSION}/k9s_Linux_amd64.tar.gz" | sudo tar xzf - -C /usr/local/bin k9s
            INSTALLED+=("k9s")
            log_success "k9s installed"
        else
            log_info "[DRY RUN] Would install k9s"
        fi
    else
        log_success "k9s already installed"
    fi

    # Minikube
    MINIKUBE_INSTALLED=$(jq -r '.dev_tools.minikube.installed' "$SCAN_FILE")
    if [[ "$MINIKUBE_INSTALLED" != "true" ]]; then
        log "Installing Minikube..."
        if [[ "$DRY_RUN" == false ]]; then
            curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
            sudo install minikube-linux-amd64 /usr/local/bin/minikube
            rm minikube-linux-amd64
            INSTALLED+=("minikube")
            log_success "Minikube installed"
        else
            log_info "[DRY RUN] Would install Minikube"
        fi
    else
        log_success "Minikube already installed"
    fi

    # kind
    KIND_INSTALLED=$(jq -r '.dev_tools.kind.installed' "$SCAN_FILE")
    if [[ "$KIND_INSTALLED" != "true" ]]; then
        log "Installing kind..."
        if [[ "$DRY_RUN" == false ]]; then
            curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.20.0/kind-linux-amd64
            sudo install -o root -g root -m 0755 kind /usr/local/bin/kind
            rm kind
            INSTALLED+=("kind")
            log_success "kind installed"
        else
            log_info "[DRY RUN] Would install kind"
        fi
    else
        log_success "kind already installed"
    fi

    # k3d
    K3D_INSTALLED=$(jq -r '.dev_tools.k3d.installed' "$SCAN_FILE")
    if [[ "$K3D_INSTALLED" != "true" ]]; then
        log "Installing k3d..."
        if [[ "$DRY_RUN" == false ]]; then
            curl -s https://raw.githubusercontent.com/k3d-io/k3d/main/install.sh | bash
            INSTALLED+=("k3d")
            log_success "k3d installed"
        else
            log_info "[DRY RUN] Would install k3d"
        fi
    else
        log_success "k3d already installed"
    fi
else
    log_info "Skipping Kubernetes tools installation (--skip-k8s)"
fi

###############################################################################
# Install Infrastructure as Code Tools
###############################################################################

if [[ "$SKIP_IAC" == false ]]; then
    section "Installing IaC Tools"

    # Terraform
    TERRAFORM_INSTALLED=$(jq -r '.dev_tools.terraform.installed' "$SCAN_FILE")
    if [[ "$TERRAFORM_INSTALLED" != "true" ]]; then
        log "Installing Terraform..."
        if [[ "$DRY_RUN" == false ]]; then
            wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
            echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
            sudo apt-get update -qq
            sudo apt-get install -y terraform
            INSTALLED+=("terraform")
            log_success "Terraform installed"
        else
            log_info "[DRY RUN] Would install Terraform"
        fi
    else
        log_success "Terraform already installed"
    fi

    # OpenTofu
    TOFU_INSTALLED=$(jq -r '.dev_tools.tofu.installed' "$SCAN_FILE")
    if [[ "$TOFU_INSTALLED" != "true" ]]; then
        log "Installing OpenTofu..."
        if [[ "$DRY_RUN" == false ]]; then
            # Install via snap as it's the easiest method
            if command -v snap &> /dev/null; then
                sudo snap install --classic opentofu || log_warn "OpenTofu snap installation failed"
                INSTALLED+=("opentofu")
            else
                log_warn "Snap not available, skipping OpenTofu"
                SKIPPED+=("opentofu - snap required")
            fi
        else
            log_info "[DRY RUN] Would install OpenTofu"
        fi
    else
        log_success "OpenTofu already installed"
    fi

    # Pulumi
    PULUMI_INSTALLED=$(jq -r '.dev_tools.pulumi.installed' "$SCAN_FILE")
    if [[ "$PULUMI_INSTALLED" != "true" ]]; then
        log "Installing Pulumi..."
        if [[ "$DRY_RUN" == false ]]; then
            curl -fsSL https://get.pulumi.com | sh
            # Add to PATH for current session
            export PATH="$HOME/.pulumi/bin:$PATH"
            INSTALLED+=("pulumi")
            log_success "Pulumi installed"
            log_info "Add to your ~/.bashrc: export PATH=\"\$HOME/.pulumi/bin:\$PATH\""
        else
            log_info "[DRY RUN] Would install Pulumi"
        fi
    else
        log_success "Pulumi already installed"
    fi
else
    log_info "Skipping IaC tools installation (--skip-iac)"
fi

###############################################################################
# Install Cloud Provider CLIs
###############################################################################

if [[ "$SKIP_CLOUD" == false ]]; then
    section "Installing Cloud Provider CLIs"

    # AWS CLI
    AWS_INSTALLED=$(jq -r '.dev_tools.aws.installed' "$SCAN_FILE")
    if [[ "$AWS_INSTALLED" != "true" ]]; then
        log "Installing AWS CLI v2..."
        if [[ "$DRY_RUN" == false ]]; then
            curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
            unzip -q awscliv2.zip
            sudo ./aws/install
            rm -rf aws awscliv2.zip
            INSTALLED+=("aws")
            log_success "AWS CLI installed"
        else
            log_info "[DRY RUN] Would install AWS CLI"
        fi
    else
        log_success "AWS CLI already installed"
    fi

    # Azure CLI
    AZ_INSTALLED=$(jq -r '.dev_tools.az.installed' "$SCAN_FILE")
    if [[ "$AZ_INSTALLED" != "true" ]]; then
        log "Installing Azure CLI..."
        if [[ "$DRY_RUN" == false ]]; then
            curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
            INSTALLED+=("az")
            log_success "Azure CLI installed"
        else
            log_info "[DRY RUN] Would install Azure CLI"
        fi
    else
        log_success "Azure CLI already installed"
    fi

    # Google Cloud SDK
    GCLOUD_INSTALLED=$(jq -r '.dev_tools.gcloud.installed' "$SCAN_FILE")
    if [[ "$GCLOUD_INSTALLED" != "true" ]]; then
        log "Installing Google Cloud SDK..."
        if [[ "$DRY_RUN" == false ]]; then
            echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | sudo tee -a /etc/apt/sources.list.d/google-cloud-sdk.list
            curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg
            sudo apt-get update -qq
            sudo apt-get install -y google-cloud-cli google-cloud-cli-gke-gcloud-auth-plugin
            INSTALLED+=("gcloud")
            log_success "Google Cloud SDK installed"
        else
            log_info "[DRY RUN] Would install Google Cloud SDK"
        fi
    else
        log_success "Google Cloud SDK already installed"
    fi

    # Oracle Cloud CLI
    OCI_INSTALLED=$(jq -r '.dev_tools.oci.installed' "$SCAN_FILE")
    if [[ "$OCI_INSTALLED" != "true" ]]; then
        log "Installing Oracle Cloud CLI..."
        if [[ "$DRY_RUN" == false ]]; then
            bash -c "$(curl -L https://raw.githubusercontent.com/oracle/oci-cli/master/scripts/install/install.sh)" -- --accept-all-defaults
            INSTALLED+=("oci")
            log_success "Oracle Cloud CLI installed"
            log_info "Add to your ~/.bashrc: source ~/lib/oracle-cli/lib/python3.*/site-packages/oci_cli/bin/oci_autocomplete.sh"
        else
            log_info "[DRY RUN] Would install Oracle Cloud CLI"
        fi
    else
        log_success "Oracle Cloud CLI already installed"
    fi

    # Alibaba Cloud CLI
    ALIYUN_INSTALLED=$(jq -r '.dev_tools.aliyun.installed' "$SCAN_FILE")
    if [[ "$ALIYUN_INSTALLED" != "true" ]]; then
        log "Installing Alibaba Cloud CLI..."
        if [[ "$DRY_RUN" == false ]]; then
            # Download and install via GitHub releases
            ALIYUN_VERSION=$(curl -s https://api.github.com/repos/aliyun/aliyun-cli/releases/latest | jq -r .tag_name | sed 's/v//')
            curl -LO "https://github.com/aliyun/aliyun-cli/releases/download/v${ALIYUN_VERSION}/aliyun-cli-linux-${ALIYUN_VERSION}-amd64.tgz"
            tar -xzf "aliyun-cli-linux-${ALIYUN_VERSION}-amd64.tgz"
            sudo mv aliyun /usr/local/bin/
            rm "aliyun-cli-linux-${ALIYUN_VERSION}-amd64.tgz"
            INSTALLED+=("aliyun")
            log_success "Alibaba Cloud CLI installed"
        else
            log_info "[DRY RUN] Would install Alibaba Cloud CLI"
        fi
    else
        log_success "Alibaba Cloud CLI already installed"
    fi

    # IONOS Cloud CLI
    IONOSCTL_INSTALLED=$(jq -r '.dev_tools.ionosctl.installed' "$SCAN_FILE")
    if [[ "$IONOSCTL_INSTALLED" != "true" ]]; then
        log "Installing IONOS Cloud CLI..."
        if [[ "$DRY_RUN" == false ]]; then
            IONOS_VERSION=$(curl -s https://api.github.com/repos/ionos-cloud/ionosctl/releases/latest | jq -r .tag_name | sed 's/v//')
            curl -LO "https://github.com/ionos-cloud/ionosctl/releases/download/v${IONOS_VERSION}/ionosctl-${IONOS_VERSION}-linux-amd64.tar.gz"
            tar -xzf "ionosctl-${IONOS_VERSION}-linux-amd64.tar.gz"
            sudo mv ionosctl /usr/local/bin/
            rm "ionosctl-${IONOS_VERSION}-linux-amd64.tar.gz"
            INSTALLED+=("ionosctl")
            log_success "IONOS Cloud CLI installed"
        else
            log_info "[DRY RUN] Would install IONOS Cloud CLI"
        fi
    else
        log_success "IONOS Cloud CLI already installed"
    fi

    # STACKIT CLI
    log "Installing STACKIT CLI..."
    if [[ "$DRY_RUN" == false ]]; then
        if ! command -v stackit &> /dev/null; then
            curl -sL https://github.com/stackitcloud/stackit-cli/releases/latest/download/stackit-linux-amd64.tar.gz | tar xz
            sudo mv stackit /usr/local/bin/
            INSTALLED+=("stackit")
            log_success "STACKIT CLI installed"
        else
            log_success "STACKIT CLI already installed"
        fi
    else
        log_info "[DRY RUN] Would install STACKIT CLI"
    fi

    # Delos Cloud - Note: Manual configuration typically required
    log_info "Delos Cloud CLI - Typically requires manual setup from provider"
    log_info "Visit: https://www.delos-cloud.com/ for CLI documentation"
    WARNINGS+=("Delos Cloud CLI requires manual installation from provider")

else
    log_info "Skipping cloud provider CLIs installation (--skip-cloud)"
fi

###############################################################################
# Install IDEs and Editors
###############################################################################

if [[ "$SKIP_IDE" == false ]]; then
    section "Installing IDEs and Editors"

    # VS Code
    CODE_INSTALLED=$(jq -r '.dev_tools.code.installed' "$SCAN_FILE")
    if [[ "$CODE_INSTALLED" != "true" ]]; then
        log "Installing Visual Studio Code..."
        if [[ "$DRY_RUN" == false ]]; then
            wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > packages.microsoft.gpg
            sudo install -o root -g root -m 644 packages.microsoft.gpg /etc/apt/trusted.gpg.d/
            sudo sh -c 'echo "deb [arch=amd64] https://packages.microsoft.com/repos/code stable main" > /etc/apt/sources.list.d/vscode.list'
            rm -f packages.microsoft.gpg
            sudo apt-get update -qq
            sudo apt-get install -y code
            INSTALLED+=("code")
            log_success "VS Code installed"
        else
            log_info "[DRY RUN] Would install VS Code"
        fi
    else
        log_success "VS Code already installed"
    fi

    # Cursor (VS Code fork with AI features)
    CURSOR_INSTALLED=$(jq -r '.dev_tools.cursor.installed' "$SCAN_FILE")
    if [[ "$CURSOR_INSTALLED" != "true" ]]; then
        log "Installing Cursor..."
        if [[ "$DRY_RUN" == false ]]; then
            # Cursor is distributed as AppImage
            log_info "Downloading Cursor AppImage..."
            CURSOR_URL="https://downloader.cursor.sh/linux/appImage/x64"
            wget -O "$HOME/Cursor.AppImage" "$CURSOR_URL"
            chmod +x "$HOME/Cursor.AppImage"

            # Create desktop entry
            mkdir -p "$HOME/.local/share/applications"
            cat > "$HOME/.local/share/applications/cursor.desktop" <<EOF
[Desktop Entry]
Name=Cursor
Exec=$HOME/Cursor.AppImage
Icon=cursor
Type=Application
Categories=Development;IDE;
EOF

            INSTALLED+=("cursor")
            log_success "Cursor installed to $HOME/Cursor.AppImage"
        else
            log_info "[DRY RUN] Would install Cursor"
        fi
    else
        log_success "Cursor already installed"
    fi

    # Neovim
    NVIM_INSTALLED=$(jq -r '.dev_tools.nvim.installed' "$SCAN_FILE")
    if [[ "$NVIM_INSTALLED" != "true" ]]; then
        log "Installing Neovim..."
        if [[ "$DRY_RUN" == false ]]; then
            sudo apt-get install -y neovim
            INSTALLED+=("nvim")
            log_success "Neovim installed"
        else
            log_info "[DRY RUN] Would install Neovim"
        fi
    else
        log_success "Neovim already installed"
    fi
else
    log_info "Skipping IDE installation (--skip-ide)"
fi

###############################################################################
# Install AI Coding Assistants
###############################################################################

section "Installing AI Coding Assistants"

# GitHub CLI (for Copilot)
GH_INSTALLED=$(jq -r '.dev_tools.gh.installed' "$SCAN_FILE")
if [[ "$GH_INSTALLED" != "true" ]]; then
    log "Installing GitHub CLI..."
    if [[ "$DRY_RUN" == false ]]; then
        curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
        sudo chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null
        sudo apt-get update -qq
        sudo apt-get install -y gh
        INSTALLED+=("gh")
        log_success "GitHub CLI installed"
        log_info "To use GitHub Copilot, run: gh auth login"
    else
        log_info "[DRY RUN] Would install GitHub CLI"
    fi
else
    log_success "GitHub CLI already installed"
fi

# Claude Code CLI
CLAUDE_INSTALLED=$(jq -r '.dev_tools.claude.installed' "$SCAN_FILE")
if [[ "$CLAUDE_INSTALLED" != "true" ]]; then
    log "Installing Claude Code CLI..."
    if [[ "$DRY_RUN" == false ]]; then
        if command -v npm &> /dev/null; then
            sudo npm install -g @anthropic-ai/claude-code
            INSTALLED+=("claude")
            log_success "Claude Code CLI installed"
            log_info "To authenticate, run: claude-code auth"
        else
            log_error "npm not available, cannot install Claude Code CLI"
            FAILED+=("claude - npm required")
        fi
    else
        log_info "[DRY RUN] Would install Claude Code CLI"
    fi
else
    log_success "Claude Code CLI already installed"
fi

###############################################################################
# Install Additional Languages and Runtimes
###############################################################################

section "Installing Additional Languages"

# Go
GO_INSTALLED=$(jq -r '.dev_tools.go.installed' "$SCAN_FILE")
if [[ "$GO_INSTALLED" != "true" ]]; then
    log "Installing Go..."
    if [[ "$DRY_RUN" == false ]]; then
        GO_VERSION="1.21.5"
        wget "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
        sudo rm -rf /usr/local/go
        sudo tar -C /usr/local -xzf "go${GO_VERSION}.linux-amd64.tar.gz"
        rm "go${GO_VERSION}.linux-amd64.tar.gz"
        INSTALLED+=("go")
        log_success "Go installed"
        log_info "Add to your ~/.bashrc: export PATH=\"\$PATH:/usr/local/go/bin:\$HOME/go/bin\""
    else
        log_info "[DRY RUN] Would install Go"
    fi
else
    log_success "Go already installed"
fi

# Rust
RUSTC_INSTALLED=$(jq -r '.dev_tools.rustc.installed' "$SCAN_FILE")
if [[ "$RUSTC_INSTALLED" != "true" ]]; then
    log "Installing Rust..."
    if [[ "$DRY_RUN" == false ]]; then
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source "$HOME/.cargo/env"
        INSTALLED+=("rustc" "cargo")
        log_success "Rust installed"
        log_info "Rust toolchain installed via rustup"
    else
        log_info "[DRY RUN] Would install Rust"
    fi
else
    log_success "Rust already installed"
fi

###############################################################################
# Docker Configuration
###############################################################################

section "Configuring Docker"

if [[ "$HAS_DOCKER" == "yes" ]]; then
    log_success "Docker is installed"

    if [[ "$IN_DOCKER_GROUP" == "yes" ]]; then
        log_success "User is in docker group"
    else
        log_warn "User is not in docker group"
        if [[ "$DRY_RUN" == false ]]; then
            read -p "Add current user to docker group? (y/N): " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                sudo usermod -aG docker "$USER"
                log_success "Added to docker group. Log out and back in for changes to take effect."
            fi
        fi
    fi

    if [[ "$DOCKER_RUNNING" == "yes (user can access)" ]]; then
        log_success "Docker is running and accessible"
    else
        log_warn "Docker daemon may not be running or accessible"
    fi
else
    log_warn "Docker is not installed. Install it for container development."
    if [[ "$DRY_RUN" == false ]]; then
        read -p "Install Docker now? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            log "Installing Docker..."
            curl -fsSL https://get.docker.com -o get-docker.sh
            sudo sh get-docker.sh
            rm get-docker.sh
            sudo usermod -aG docker "$USER"
            INSTALLED+=("docker")
            log_success "Docker installed. Log out and back in for group changes to take effect."
        fi
    fi
fi

###############################################################################
# Generate Summary Report
###############################################################################

section "Installation Summary"

echo ""
echo -e "${GREEN}Successfully Installed (${#INSTALLED[@]}):${NC}"
if [[ ${#INSTALLED[@]} -gt 0 ]]; then
    printf '%s\n' "${INSTALLED[@]}" | sort | uniq | while read -r item; do
        echo "  ✓ $item"
    done
else
    echo "  (none)"
fi

echo ""
echo -e "${RED}Failed Installations (${#FAILED[@]}):${NC}"
if [[ ${#FAILED[@]} -gt 0 ]]; then
    printf '%s\n' "${FAILED[@]}" | sort | uniq | while read -r item; do
        echo "  ✗ $item"
    done
else
    echo "  (none)"
fi

echo ""
echo -e "${YELLOW}Skipped/Manual Steps (${#SKIPPED[@]}):${NC}"
if [[ ${#SKIPPED[@]} -gt 0 ]]; then
    printf '%s\n' "${SKIPPED[@]}" | while read -r item; do
        echo "  ⊘ $item"
    done
else
    echo "  (none)"
fi

echo ""
echo -e "${YELLOW}Warnings (${#WARNINGS[@]}):${NC}"
if [[ ${#WARNINGS[@]} -gt 0 ]]; then
    printf '%s\n' "${WARNINGS[@]}" | while read -r item; do
        echo "  ⚠ $item"
    done
else
    echo "  (none)"
fi

###############################################################################
# Post-Installation Configuration
###############################################################################

section "Post-Installation Steps"

echo "To complete your DevOps environment setup:"
echo ""
echo "1. Shell Configuration:"
echo "   Add the following to your ~/.bashrc or ~/.zshrc:"
echo ""
cat <<'EOF'
   # Go
   export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin"

   # Rust
   source "$HOME/.cargo/env"

   # Pulumi
   export PATH="$HOME/.pulumi/bin:$PATH"

   # Node global packages
   export PATH="$HOME/.npm-global/bin:$PATH"
EOF

echo ""
echo "2. Reload shell configuration:"
echo "   source ~/.bashrc"
echo ""
echo "3. Cloud Provider Authentication:"
echo "   - AWS:     aws configure"
echo "   - Azure:   az login"
echo "   - GCP:     gcloud auth login && gcloud init"
echo "   - Oracle:  oci setup config"
echo "   - Alibaba: aliyun configure"
echo "   - IONOS:   ionosctl login"
echo "   - STACKIT: stackit auth login"
echo ""
echo "4. AI Assistant Setup:"
echo "   - GitHub Copilot: gh auth login"
echo "   - Claude Code:    claude-code auth"
echo ""
echo "5. Docker (if user group changed):"
echo "   Log out and log back in for docker group membership to take effect"
echo ""
echo "6. TLS Certificate (if corporate firewall detected):"
echo "   Contact IT for the corporate root CA certificate and install it:"
echo "   sudo cp corporate-ca.crt /usr/local/share/ca-certificates/"
echo "   sudo update-ca-certificates"
echo ""
echo "7. Kubernetes Context:"
echo "   Configure kubectl with your cluster:"
echo "   kubectl config set-context <context-name>"
echo ""

###############################################################################
# Write Completion Marker
###############################################################################

COMPLETION_FILE="vm_env_setup_complete_$(date +%Y%m%d_%H%M%S).json"

cat > "$COMPLETION_FILE" <<EOF
{
  "setup_version": "2.0.0",
  "completed_at": "$(date -Iseconds)",
  "scan_file": "$SCAN_FILE",
  "dry_run": $DRY_RUN,
  "installed": $(printf '%s\n' "${INSTALLED[@]}" | jq -R . | jq -s .),
  "failed": $(printf '%s\n' "${FAILED[@]}" | jq -R . | jq -s .),
  "skipped": $(printf '%s\n' "${SKIPPED[@]}" | jq -R . | jq -s .),
  "warnings": $(printf '%s\n' "${WARNINGS[@]}" | jq -R . | jq -s .)
}
EOF

log_success "Setup complete! Summary saved to: $COMPLETION_FILE"
log_info "Full log available at: $LOG_FILE"

if [[ "$DRY_RUN" == true ]]; then
    echo ""
    log_info "This was a DRY RUN. No actual installations were performed."
    log_info "Run without --dry-run to perform actual installations."
fi

echo ""
log_success "Your DevOps environment is ready! 🚀"
