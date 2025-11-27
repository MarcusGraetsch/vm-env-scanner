#!/usr/bin/env bash
###############################################################################
# TLS Certificate Fixer for Corporate Environments
#
# Purpose: Extract and install corporate TLS certificates to fix package
#          installation and HTTPS connectivity issues caused by TLS interception
#
# Usage: ./fix_tls_certificates.sh [OPTIONS]
#
# Options:
#   --test-domain DOMAIN    Domain to extract certificate from (default: github.com)
#   --auto-install          Automatically install without prompting
#   --help                  Show this help message
###############################################################################

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
TEST_DOMAIN="github.com"
AUTO_INSTALL=false

log() {
    echo -e "${GREEN}[$(date +'%H:%M:%S')]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

show_help() {
    sed -n '/^###/,/^###/p' "$0" | sed '1d;$d' | sed 's/^# //; s/^#//'
    exit 0
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --test-domain)
            TEST_DOMAIN="$2"
            shift 2
            ;;
        --auto-install)
            AUTO_INSTALL=true
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

log "TLS Certificate Fixer for Corporate Environments"
echo ""

# Check if we're behind a corporate firewall
log "Testing connection to $TEST_DOMAIN..."

CERT_INFO=$(echo | openssl s_client -connect "${TEST_DOMAIN}:443" -showcerts 2>/dev/null | openssl x509 -noout -issuer -subject 2>/dev/null || echo "")

if [[ -z "$CERT_INFO" ]]; then
    log_error "Could not connect to $TEST_DOMAIN"
    log_error "Check your internet connection"
    exit 1
fi

log_info "Certificate information:"
echo "$CERT_INFO"
echo ""

# Check if this is a corporate certificate
ISSUER=$(echo "$CERT_INFO" | grep "issuer" | sed 's/.*CN = //' | sed 's/,.*//')

if [[ "$ISSUER" =~ "hisolutions" ]] || [[ "$ISSUER" =~ "fw-int" ]] || [[ "$ISSUER" =~ "corp" ]] || [[ "$ISSUER" =~ "internal" ]]; then
    log_warn "Corporate TLS interception detected!"
    log_warn "Certificate issuer: $ISSUER"
    echo ""
    log_info "This means your company's firewall is intercepting HTTPS traffic."
    log_info "To fix package installation issues, we need to install the corporate certificate."
    echo ""
else
    log "No corporate TLS interception detected"
    log "Certificate appears to be from a standard CA"
    exit 0
fi

# Extract the full certificate chain
log "Extracting certificate chain from $TEST_DOMAIN..."

TEMP_CERT="/tmp/corporate_cert_chain.pem"
echo | openssl s_client -connect "${TEST_DOMAIN}:443" -showcerts 2>/dev/null | \
    sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' > "$TEMP_CERT"

CERT_COUNT=$(grep -c "BEGIN CERTIFICATE" "$TEMP_CERT")
log_info "Extracted $CERT_COUNT certificate(s)"

if [[ $CERT_COUNT -eq 0 ]]; then
    log_error "Failed to extract certificates"
    exit 1
fi

# Display certificate details
log_info "Certificate details:"
openssl x509 -in "$TEMP_CERT" -noout -text | grep -E "(Issuer:|Subject:|Not Before|Not After)" || true
echo ""

# Ask for confirmation unless auto-install is enabled
if [[ "$AUTO_INSTALL" == false ]]; then
    read -p "Do you want to install this certificate system-wide? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log "Installation cancelled"
        log_info "Certificate saved to: $TEMP_CERT"
        exit 0
    fi
fi

# Install the certificate
log "Installing corporate certificate system-wide..."

CERT_NAME="corporate-ca-$(echo "$ISSUER" | tr ' ' '-' | tr '[:upper:]' '[:lower:]').crt"
sudo cp "$TEMP_CERT" "/usr/local/share/ca-certificates/$CERT_NAME"
sudo update-ca-certificates

if [[ $? -eq 0 ]]; then
    log "✓ Certificate installed successfully"
else
    log_error "Failed to install certificate"
    exit 1
fi

# Configure various tools to use the system certificates
log "Configuring tools to use system certificates..."

# Git
if command -v git &> /dev/null; then
    git config --global http.sslCAInfo /etc/ssl/certs/ca-certificates.crt
    log_info "✓ Configured git"
fi

# npm
if command -v npm &> /dev/null; then
    npm config set cafile /etc/ssl/certs/ca-certificates.crt
    log_info "✓ Configured npm"
fi

# pip
if command -v pip &> /dev/null; then
    PIP_CONF_DIR="$HOME/.config/pip"
    mkdir -p "$PIP_CONF_DIR"
    if ! grep -q "cert" "$PIP_CONF_DIR/pip.conf" 2>/dev/null; then
        cat >> "$PIP_CONF_DIR/pip.conf" <<EOF

[global]
cert = /etc/ssl/certs/ca-certificates.crt
EOF
        log_info "✓ Configured pip"
    fi
fi

# curl
if command -v curl &> /dev/null; then
    CURL_RC="$HOME/.curlrc"
    if ! grep -q "cacert" "$CURL_RC" 2>/dev/null; then
        echo "cacert = /etc/ssl/certs/ca-certificates.crt" >> "$CURL_RC"
        log_info "✓ Configured curl"
    fi
fi

# wget
if command -v wget &> /dev/null; then
    WGET_RC="$HOME/.wgetrc"
    if ! grep -q "ca_certificate" "$WGET_RC" 2>/dev/null; then
        echo "ca_certificate = /etc/ssl/certs/ca-certificates.crt" >> "$WGET_RC"
        log_info "✓ Configured wget"
    fi
fi

# Docker (if running)
if command -v docker &> /dev/null && docker info &>/dev/null; then
    DOCKER_CERT_DIR="/etc/docker/certs.d"
    sudo mkdir -p "$DOCKER_CERT_DIR"
    sudo cp "/usr/local/share/ca-certificates/$CERT_NAME" "$DOCKER_CERT_DIR/ca.crt"
    log_info "✓ Configured docker"
fi

# Node.js
if command -v node &> /dev/null; then
    NPM_RC="$HOME/.npmrc"
    if ! grep -q "cafile" "$NPM_RC" 2>/dev/null; then
        echo "cafile=/etc/ssl/certs/ca-certificates.crt" >> "$NPM_RC"
        log_info "✓ Configured Node.js/npm"
    fi
fi

echo ""
log "Certificate installation complete!"
echo ""
log_info "The following tools have been configured:"
log_info "  - System-wide CA certificates"
log_info "  - Git"
log_info "  - npm/Node.js"
log_info "  - pip/Python"
log_info "  - curl"
log_info "  - wget"
log_info "  - Docker"
echo ""
log_info "You may need to restart your terminal or log out/in for all changes to take effect"
echo ""

# Test the configuration
log "Testing HTTPS connectivity..."

TEST_URLS=(
    "https://github.com"
    "https://pypi.org"
    "https://registry.npmjs.org"
)

SUCCESS_COUNT=0
for url in "${TEST_URLS[@]}"; do
    if curl -s -o /dev/null -w "%{http_code}" "$url" | grep -q "200\|301\|302"; then
        log "✓ $url - OK"
        ((SUCCESS_COUNT++))
    else
        log_warn "✗ $url - Failed"
    fi
done

echo ""
if [[ $SUCCESS_COUNT -eq ${#TEST_URLS[@]} ]]; then
    log "All connectivity tests passed! 🎉"
else
    log_warn "Some connectivity tests failed"
    log_warn "You may need to:"
    log_warn "  1. Contact IT for the correct corporate CA certificate"
    log_warn "  2. Check proxy settings"
    log_warn "  3. Verify firewall rules"
fi

echo ""
log "Certificate file saved to: /usr/local/share/ca-certificates/$CERT_NAME"
log "Temporary file: $TEMP_CERT"
