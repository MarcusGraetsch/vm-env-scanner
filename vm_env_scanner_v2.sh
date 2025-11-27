#!/usr/bin/env bash
#===============================================================================
# vm_env_scanner_v2.sh
# Purpose: Comprehensive environment scan for an Ubuntu VM to identify
#          restrictions affecting DevOps/cloud development workflows
#
# Usage:
#   chmod +x vm_env_scanner_v2.sh
#   ./vm_env_scanner_v2.sh [OPTIONS]
#
# Options:
#   --dry-run       Show what sudo commands would run without executing
#   --section NAME  Run only specific section (system|virt|user|disk|packages|
#                   network|firewall|tls|snap|docker|security|tools|storage|
#                   devops|summary)
#   --json-only     Output only JSON (suppress human-readable report)
#   --help          Show this help
#
# Outputs:
#   ~/vm_env_scan_report.txt   (human-readable summary)
#   ~/vm_env_scan_report.json  (machine-readable, complete data)
#
# NOTE: This script OBSERVES and REPORTS only. It does NOT attempt to
#       circumvent any security controls or modify system configuration.
#===============================================================================

set -euo pipefail
export LANG=C

#-------------------------------------------------------------------------------
# Configuration
#-------------------------------------------------------------------------------
readonly VERSION="2.0.0"
readonly OUT_TXT="${HOME}/vm_env_scan_report.txt"
readonly OUT_JSON="${HOME}/vm_env_scan_report.json"
readonly NOW="$(date --iso-8601=seconds)"
readonly HOSTNAME_VAL="$(hostname)"
readonly CURRENT_USER="$(whoami)"

# Domains to test for TLS interception and connectivity
readonly DOMAIN_TESTS=(
    "github.com"
    "pypi.org"
    "registry.npmjs.org"
    "download.docker.com"
    "apt.releases.hashicorp.com"
    "api.snapcraft.io"
    "registry.terraform.io"
    "helm.sh"
)

# Cloud provider endpoints to test
readonly CLOUD_ENDPOINTS=(
    "console.aws.amazon.com"
    "portal.azure.com"
    "console.cloud.google.com"
    "cloud.ionos.de"
    "portal.stackit.cloud"
    "my.delos-cloud.com"
    "intl.aliyun.com" # Added Alibaba Cloud
    "oraclecloud.com" # Added Oracle Cloud Infrastructure
)

# Network timeout for TLS/connectivity tests (seconds)
readonly NET_TIMEOUT=10

# Runtime flags
DRY_RUN=false
JSON_ONLY=false
SECTION_FILTER=""

# Temporary directory for intermediate data
TMPDIR=""

# Associative array for JSON data collection
declare -A JSON_DATA

# Array to track scan warnings/errors
declare -a SCAN_WARNINGS=()
declare -a SCAN_ERRORS=()

#-------------------------------------------------------------------------------
# Utility Functions
#-------------------------------------------------------------------------------

show_help() {
    sed -n '2,/^#====/p' "$0" | grep '^#' | sed 's/^# \?//'
    exit 0
}

log_info() {
    [[ "$JSON_ONLY" == "true" ]] && return
    printf "%s\n" "$*"
}

log_section() {
    [[ "$JSON_ONLY" == "true" ]] && return
    printf "\n%s\n" "=== $* ==="
}

log_warn() {
    SCAN_WARNINGS+=("$*")
    [[ "$JSON_ONLY" == "true" ]] && return
    printf "[WARN] %s\n" "$*" >&2
}

log_error() {
    SCAN_ERRORS+=("$*")
    [[ "$JSON_ONLY" == "true" ]] && return
    printf "[ERROR] %s\n" "$*" >&2
}

# Run command with timeout, capture output and exit status
run_cmd() {
    local timeout_sec="${1:-10}"
    shift
    local outfile
    outfile="$(mktemp)"
    local exit_code=0
    
    if timeout "$timeout_sec" "$@" > "$outfile" 2>&1; then
        exit_code=0
    else
        exit_code=$?
    fi
    
    cat "$outfile"
    rm -f "$outfile"
    return $exit_code
}

# Run sudo command (respects --dry-run)
run_sudo() {
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] Would execute: sudo $*"
        return 0
    fi
    sudo "$@" 2>&1 || true
}

# Store data for JSON output
json_set() {
    local key="$1"
    local value="$2"
    JSON_DATA["$key"]="$value"
}

# Escape string for JSON
json_escape() {
    local str="$1"
    str="${str//\\/\\\\}"      # backslash
    str="${str//\"/\\\"}"      # double quote
    str="${str//$'\\n'/\\\\n}"    # newline
    str="${str//$'\\r'/\\\\r}"    # carriage return
    str="${str//$'\\t'/\\\\t}"    # tab
    printf '%s' "$str"
}

# Check if command exists
cmd_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check for critical dependencies
check_dependencies() {
    log_info "--- Checking Essential Dependencies ---"
    if ! cmd_exists jq; then
        log_error "Essential tool 'jq' is not installed. JSON output quality will be severely degraded (e.g., version parsing will fail). Please install 'jq' (e.g., sudo apt install jq)."
    else
        log_info "Dependency 'jq' found."
    fi
    log_info "--- End Dependency Check ---"
}

# Write to report file
report() {
    [[ "$JSON_ONLY" == "true" ]] && return
    printf "%s\n" "$*" >> "$OUT_TXT"
}

report_section() {
    [[ "$JSON_ONLY" == "true" ]] && return
    printf "\n%s\n" "=== $* ===" >> "$OUT_TXT"
}

#-------------------------------------------------------------------------------
# Scan Functions (Modular)
#-------------------------------------------------------------------------------

scan_system_basics() {
    log_section "System Basics"
    report_section "System Basics"
    
    local os_release kernel arch
    os_release="$(lsb_release -ds 2>/dev/null || grep -m1 'PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || echo 'unknown')"
    kernel="$(uname -r)"
    arch="$(uname -m)"
    
    # Detect VM environment
    local vm_type="unknown"
    if [[ -f /sys/class/dmi/id/product_name ]]; then
        vm_type="$(cat /sys/class/dmi/id/product_name 2>/dev/null || echo 'unknown')"
    fi
    
    # VMware tools check
    local vmware_tools="no"
    if pgrep -f 'vmtoolsd|vmware' >/dev/null 2>&1; then
        vmware_tools="yes"
    fi
    
    # Check for other guest agents
    local guest_agents=""
    pgrep -f 'qemu-ga' >/dev/null 2>&1 && guest_agents+="qemu-guest-agent "
    pgrep -f 'VBoxService' >/dev/null 2>&1 && guest_agents+="virtualbox-guest "
    pgrep -f 'waagent' >/dev/null 2>&1 && guest_agents+="azure-linux-agent "
    [[ -z "$guest_agents" ]] && guest_agents="none detected"
    
    log_info "OS: $os_release"
    log_info "Kernel: $kernel ($arch)"
    log_info "VM Product: $vm_type"
    log_info "VMware Tools: $vmware_tools"
    log_info "Guest Agents: $guest_agents"
    
    report "OS: $os_release"
    report "Kernel: $kernel ($arch)"
    report "VM Product: $vm_type"
    report "VMware Tools: $vmware_tools"
    report "Guest Agents: $guest_agents"
    
    json_set "os_release" "\"$(json_escape "$os_release")\""
    json_set "kernel" "\"$kernel\""
    json_set "arch" "\"$arch\""
    json_set "vm_product" "\"$(json_escape "$vm_type")\""
    json_set "vmware_tools" "\"$vmware_tools\""
    json_set "guest_agents" "\"$(json_escape "$guest_agents")\""
}

scan_virtualization() {
    log_section "Virtualization & Container Capabilities"
    report_section "Virtualization & Container Capabilities"
    
    # systemd-detect-virt
    local virt_type
    virt_type="$(systemd-detect-virt 2>/dev/null || echo 'detection failed')"
    
    # KVM modules
    local kvm_modules
    kvm_modules="$(lsmod 2>/dev/null | awk '/^kvm/ {print $1}' | tr '\n' ' ' || echo 'none')"
    [[ -z "$kvm_modules" ]] && kvm_modules="none"
    
    # Nested virtualization check
    local nested_virt="unknown"
    if [[ -f /sys/module/kvm_intel/parameters/nested ]]; then
        nested_virt="$(cat /sys/module/kvm_intel/parameters/nested 2>/dev/null)"
    elif [[ -f /sys/module/kvm_amd/parameters/nested ]]; then
        nested_virt="$(cat /sys/module/kvm_amd/parameters/nested 2>/dev/null)"
    fi
    
    # cgroups version (critical for containers)
    local cgroup_version="unknown"
    if [[ -f /sys/fs/cgroup/cgroup.controllers ]]; then
        cgroup_version="v2 (unified)"
    elif [[ -d /sys/fs/cgroup/cpu ]]; then
        cgroup_version="v1 (legacy)"
    fi
    
    # User namespaces (for rootless containers)
    local user_ns="disabled"
    if [[ -f /proc/sys/kernel/unprivileged_userns_clone ]]; then
        local ns_val
        ns_val="$(cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null)"
        [[ "$ns_val" == "1" ]] && user_ns="enabled"
    else
        # If file doesn't exist, check if user_namespaces is compiled in
        if [[ -f /proc/sys/user/max_user_namespaces ]]; then
            local max_ns
            max_ns="$(cat /proc/sys/user/max_user_namespaces 2>/dev/null)"
            [[ "$max_ns" -gt 0 ]] && user_ns="enabled (max: $max_ns)"
        fi
    fi
    
    # Seccomp availability
    local seccomp="unavailable"
    if grep -q 'CONFIG_SECCOMP=y' /boot/config-"$(uname -r)" 2>/dev/null; then
        seccomp="available"
    elif [[ -f /proc/sys/kernel/seccomp/actions_avail ]]; then
        seccomp="available"
    fi
    
    log_info "Virtualization type: $virt_type"
    log_info "KVM modules: $kvm_modules"
    log_info "Nested virtualization: $nested_virt"
    log_info "Cgroups version: $cgroup_version"
    log_info "User namespaces: $user_ns"
    log_info "Seccomp: $seccomp"
    
    report "Virtualization type: $virt_type"
    report "KVM modules: $kvm_modules"
    report "Nested virtualization: $nested_virt"
    report "Cgroups version: $cgroup_version"
    report "User namespaces: $user_ns"
    report "Seccomp: $seccomp"
    
    # Implications
    if [[ "$cgroup_version" == "v1 (legacy)" ]]; then
        log_warn "cgroups v1 detected - some newer container features may not work"
        report "  [!] cgroups v1 may limit container functionality"
    fi
    
    if [[ "$user_ns" == "disabled" ]]; then
        log_warn "User namespaces disabled - rootless containers won't work"
        report "  [!] Rootless containers (Podman rootless, Docker rootless) unavailable"
    fi
    
    json_set "virtualization_type" "\"$virt_type\""
    json_set "kvm_modules" "\"$(json_escape "$kvm_modules")\""
    json_set "nested_virtualization" "\"$nested_virt\""
    json_set "cgroup_version" "\"$cgroup_version\""
    json_set "user_namespaces" "\"$user_ns\""
    json_set "seccomp" "\"$seccomp\""
}

scan_user_permissions() {
    log_section "User, Groups & Privileges"
    report_section "User, Groups & Privileges"
    
    local groups_list
    groups_list="$(id -nG 2>/dev/null || echo 'unknown')"
    
    # Check for specific important groups
    local in_docker_group="no"
    local in_sudo_group="no"
    local in_wheel_group="no"
    local in_kvm_group="no"
    
    id -nG 2>/dev/null | grep -qw docker && in_docker_group="yes"
    id -nG 2>/dev/null | grep -qw sudo && in_sudo_group="yes"
    id -nG 2>/dev/null | grep -qw wheel && in_wheel_group="yes"
    id -nG 2>/dev/null | grep -qw kvm && in_kvm_group="yes"
    
    # Passwordless sudo check
    local passwordless_sudo="no"
    if sudo -n true 2>/dev/null; then
        passwordless_sudo="yes"
    fi
    
    # Check sudoers restrictions (if readable)
    local sudo_restrictions="unknown"
    if [[ "$DRY_RUN" != "true" ]] && sudo -l 2>/dev/null | grep -q 'NOPASSWD'; then
        sudo_restrictions="$(sudo -l 2>/dev/null | head -20)"
    fi
    
    # UID/GID
    local uid gid
    uid="$(id -u)"
    gid="$(id -g)"
    
    log_info "User: $CURRENT_USER (UID: $uid, GID: $gid)"
    log_info "Groups: $groups_list"
    log_info "In docker group: $in_docker_group"
    log_info "In sudo group: $in_sudo_group"
    log_info "In kvm group: $in_kvm_group"
    log_info "Passwordless sudo: $passwordless_sudo"
    
    report "User: $CURRENT_USER (UID: $uid, GID: $gid)"
    report "Groups: $groups_list"
    report "In docker group: $in_docker_group"
    report "In sudo group: $in_sudo_group"
    report "In kvm group: $in_kvm_group"
    report "Passwordless sudo: $passwordless_sudo"
    
    if [[ "$in_docker_group" == "no" ]]; then
        log_warn "User not in docker group - will need sudo for docker commands"
        report "  [!] Add user to docker group: sudo usermod -aG docker $CURRENT_USER"
    fi
    
    json_set "user" "\"$CURRENT_USER\""
    json_set "uid" "$uid"
    json_set "gid" "$gid"
    json_set "groups" "\"$(json_escape "$groups_list")\""
    json_set "in_docker_group" "\"$in_docker_group\""
    json_set "in_sudo_group" "\"$in_sudo_group\""
    json_set "in_kvm_group" "\"$in_kvm_group\""
    json_set "passwordless_sudo" "\"$passwordless_sudo\""
}

scan_disk_storage() {
    log_section "Disk, Mounts & Filesystem"
    report_section "Disk, Mounts & Filesystem"
    
    # Disk usage
    local disk_info
    disk_info="$(df -hT / /home /tmp 2>/dev/null | tail -n +2 || echo 'unknown')"
    
    log_info "Disk usage:"
    log_info "$disk_info"
    report "Disk usage:"
    report "$disk_info"
    
    # Root filesystem info
    local root_fs_type root_fs_size root_fs_avail root_fs_use
    read -r _ root_fs_type root_fs_size _ root_fs_avail root_fs_use _ < <(df -hT / 2>/dev/null | tail -1)
    
    # Check for read-only mounts
    local ro_mounts
    ro_mounts="$(mount 2>/dev/null | grep '\bro\b' | grep -v 'snap\|squashfs' || echo 'none')"
    
    log_info "Read-only mounts (excluding snaps): ${ro_mounts:-none}"
    report "Read-only mounts: ${ro_mounts:-none}"
    
    # Check for noexec mounts (affects scripts/binaries)
    local noexec_mounts
    noexec_mounts="$(mount 2>/dev/null | grep 'noexec' || echo 'none')"
    
    if [[ "$noexec_mounts" != "none" ]]; then
        log_warn "noexec mounts detected - may affect script execution"
        log_info "$noexec_mounts"
        report "noexec mounts detected:"
        report "$noexec_mounts"
    fi
    
    # /tmp writability
    local tmp_writable="no"
    if touch /tmp/.scan_test_$$ 2>/dev/null; then
        tmp_writable="yes"
        rm -f /tmp/.scan_test_$$
    fi
    
    # Home directory writability and space
    local home_writable="no"
    if touch "$HOME/.scan_test_$$" 2>/dev/null; then
        home_writable="yes"
        rm -f "$HOME/.scan_test_$$"
    fi
    
    log_info "/tmp writable: $tmp_writable"
    log_info "Home writable: $home_writable"
    report "/tmp writable: $tmp_writable"
    report "Home writable: $home_writable"
    
    json_set "root_fs_type" "\"${root_fs_type:-unknown}\""
    json_set "root_fs_size" "\"${root_fs_size:-unknown}\""
    json_set "root_fs_available" "\"${root_fs_avail:-unknown}\""
    json_set "root_fs_use_percent" "\"${root_fs_use:-unknown}\""
    json_set "tmp_writable" "\"$tmp_writable\""
    json_set "home_writable" "\"$home_writable\""
    json_set "readonly_mounts" "\"$(json_escape "$ro_mounts")\""
}

scan_package_managers() {
    log_section "Package Managers & Sources"
    report_section "Package Managers & Sources"
    
    # APT configuration
    log_info "--- APT ---"
    report "--- APT ---"
    
    # Sources list
    local apt_sources_count=0
    if [[ -f /etc/apt/sources.list ]]; then
        apt_sources_count="$(grep -c '^deb ' /etc/apt/sources.list 2>/dev/null || echo 0)"
    fi
    local apt_sources_d_count=0
    if [[ -d /etc/apt/sources.list.d ]]; then
        apt_sources_d_count="$(find /etc/apt/sources.list.d -name '*.list' -o -name '*.sources' 2>/dev/null | wc -l)"
    fi
    
    log_info "APT sources in sources.list: $apt_sources_count"
    log_info "Additional source files: $apt_sources_d_count"
    report "APT sources in sources.list: $apt_sources_count"
    report "Additional source files: $apt_sources_d_count"
    
    # List additional repos
    if [[ -d /etc/apt/sources.list.d ]]; then
        local extra_repos
        extra_repos="$(ls -1 /etc/apt/sources.list.d/ 2>/dev/null || echo 'none')"
        log_info "Extra repo files: $extra_repos"
        report "Extra repo files:"
        report "$extra_repos"
    fi
    
    # APT proxy configuration
    local apt_proxy=""
    apt_proxy="$(grep -rh 'Acquire::http::Proxy\|Acquire::https::Proxy' /etc/apt/ 2>/dev/null | head -5 || echo 'none configured')"
    log_info "APT proxy: $apt_proxy"
    report "APT proxy: $apt_proxy"
    
    # Check if apt is locked
    local apt_locked="no"
    if fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || \
       fuser /var/lib/apt/lists/lock >/dev/null 2>&1; then
        apt_locked="yes"
        log_warn "APT is currently locked by another process"
    fi
    
    # Snap
    log_info "--- Snap ---"
    report "--- Snap ---"
    
    local snap_installed="no"
    local snap_version=""
    if cmd_exists snap; then
        snap_installed="yes"
        snap_version="$(snap version 2>/dev/null | head -1 || echo 'unknown')"
    fi
    log_info "Snap installed: $snap_installed"
    [[ -n "$snap_version" ]] && log_info "Snap version: $snap_version"
    report "Snap installed: $snap_installed"
    
    # Flatpak
    log_info "--- Flatpak ---"
    report "--- Flatpak ---"
    
    local flatpak_installed="no"
    if cmd_exists flatpak; then
        flatpak_installed="yes"
    fi
    log_info "Flatpak installed: $flatpak_installed"
    report "Flatpak installed: $flatpak_installed"
    
    # Python / pip / pipx
    log_info "--- Python & pip ---"
    report "--- Python & pip ---"
    
    local python_version pip_version pipx_installed pep668_active
    python_version="$(python3 --version 2>/dev/null || echo 'not installed')"
    pip_version="$(python3 -m pip --version 2>/dev/null || echo 'not available')"
    pipx_installed="no"
    cmd_exists pipx && pipx_installed="yes"
    
    # PEP 668 detection (externally managed environment)
    pep668_active="no"
    local python_stdlib_path
    python_stdlib_path="$(python3 -c 'import sysconfig; print(sysconfig.get_path("stdlib"))' 2>/dev/null || echo '')"
    if [[ -n "$python_stdlib_path" ]] && [[ -f "${python_stdlib_path}/EXTERNALLY-MANAGED" ]]; then
        pep668_active="yes"
    fi
    # Also check site-packages
    local site_packages_path
    site_packages_path="$(python3 -c 'import site; print(site.getsitepackages()[0] if site.getsitepackages() else "")' 2>/dev/null || echo '')"
    if [[ -n "$site_packages_path" ]] && [[ -f "${site_packages_path}/../EXTERNALLY-MANAGED" ]]; then
        pep668_active="yes"
    fi
    
    log_info "Python: $python_version"
    log_info "pip: $pip_version"
    log_info "pipx installed: $pipx_installed"
    log_info "PEP 668 (externally managed): $pep668_active"
    
    report "Python: $python_version"
    report "pip: $pip_version"
    report "pipx installed: $pipx_installed"
    report "PEP 668 (externally managed): $pep668_active"
    
    if [[ "$pep668_active" == "yes" ]]; then
        log_warn "PEP 668 active - use 'pip install --user' or pipx/venv for packages"
        report "  [!] System Python is externally managed. Use virtual environments or pipx."
    fi
    
    # Node.js / npm
    log_info "--- Node.js & npm ---"
    report "--- Node.js & npm ---"
    
    local node_version npm_version
    node_version="$(node --version 2>/dev/null || echo 'not installed')"
    npm_version="$(npm --version 2>/dev/null || echo 'not installed')"
    
    log_info "Node.js: $node_version"
    log_info "npm: $npm_version"
    report "Node.js: $node_version"
    report "npm: $npm_version"
    
    # Check for npm proxy config
    local npm_proxy=""
    if [[ -f "$HOME/.npmrc" ]]; then
        npm_proxy="$(grep -i proxy "$HOME/.npmrc" 2>/dev/null || echo 'none')"
    fi
    
    json_set "apt_sources_count" "$apt_sources_count"
    json_set "apt_locked" "\"$apt_locked\""
    json_set "apt_proxy" "\"$(json_escape "$apt_proxy")\""
    json_set "snap_installed" "\"$snap_installed\""
    json_set "flatpak_installed" "\"$flatpak_installed\""
    json_set "python_version" "\"$(json_escape "$python_version")\""
    json_set "pip_version" "\"$(json_escape "$pip_version")\""
    json_set "pipx_installed" "\"$pipx_installed\""
    json_set "pep668_active" "\"$pep668_active\""
    json_set "node_version" "\"$node_version\""
    json_set "npm_version" "\"$npm_version\""
}

scan_network() {
    log_section "Network Configuration"
    report_section "Network Configuration"
    
    # Interfaces
    log_info "--- Network Interfaces ---"
    report "--- Network Interfaces ---"
    
    local interfaces
    interfaces="$(ip -4 -o addr show 2>/dev/null | awk '{print $2": "$4}' || echo 'unknown')"
    log_info "$interfaces"
    report "$interfaces"
    
    # Default gateway
    local default_gw
    default_gw="$(ip route show default 2>/dev/null | awk '/default/ {print $3}' | head -1 || echo 'none')"
    log_info "Default gateway: $default_gw"
    report "Default gateway: $default_gw"
    
    # DNS configuration
    log_info "--- DNS Configuration ---"
    report "--- DNS Configuration ---"
    
    # Check if systemd-resolved is in use
    local dns_method="traditional"
    if systemctl is-active systemd-resolved >/dev/null 2>&1; then
        dns_method="systemd-resolved"
        log_info "DNS managed by: systemd-resolved"
        report "DNS managed by: systemd-resolved"
        
        # Show resolved status
        local resolved_status
        resolved_status="$(resolvectl status 2>/dev/null | head -20 || echo 'unable to query')"
        log_info "$resolved_status"
        report "$resolved_status"
    else
        log_info "DNS managed by: traditional /etc/resolv.conf"
        report "DNS managed by: traditional /etc/resolv.conf"
    fi
    
    # Show resolv.conf
    local resolv_conf
    resolv_conf="$(cat /etc/resolv.conf 2>/dev/null | grep -v '^#' | head -10 || echo 'not readable')"
    log_info "resolv.conf:"
    log_info "$resolv_conf"
    report "resolv.conf:"
    report "$resolv_conf"
    
    # Proxy environment variables
    log_info "--- Proxy Environment ---"
    report "--- Proxy Environment ---"
    
    local http_proxy_val="${http_proxy:-${HTTP_PROXY:-}}"
    local https_proxy_val="${https_proxy:-${HTTPS_PROXY:-}}"
    local no_proxy_val="${no_proxy:-${NO_PROXY:-}}"
    local all_proxy_val="${all_proxy:-${ALL_PROXY:-}}"
    
    log_info "http_proxy: ${http_proxy_val:-not set}"
    log_info "https_proxy: ${https_proxy_val:-not set}"
    log_info "no_proxy: ${no_proxy_val:-not set}"
    log_info "all_proxy: ${all_proxy_val:-not set}"
    
    report "http_proxy: ${http_proxy_val:-not set}"
    report "https_proxy: ${https_proxy_val:-not set}"
    report "no_proxy: ${no_proxy_val:-not set}"
    
    # Check for system-wide proxy configs
    local system_proxy_files=""
    [[ -f /etc/environment ]] && grep -qi proxy /etc/environment 2>/dev/null && system_proxy_files+="/etc/environment "
    [[ -f /etc/profile.d/proxy.sh ]] && system_proxy_files+="/etc/profile.d/proxy.sh "
    
    if [[ -n "$system_proxy_files" ]]; then
        log_info "System proxy config files: $system_proxy_files"
        report "System proxy config files: $system_proxy_files"
    fi
    
    # Git proxy config
    local git_proxy=""
    if cmd_exists git; then
        git_proxy="$(git config --global --get http.proxy 2>/dev/null || echo 'not set')"
    fi
    log_info "Git http.proxy: $git_proxy"
    report "Git http.proxy: $git_proxy"
    
    json_set "default_gateway" "\"$default_gw\""
    json_set "dns_method" "\"$dns_method\""
    json_set "http_proxy" "\"$(json_escape "$http_proxy_val")\""
    json_set "https_proxy" "\"$(json_escape "$https_proxy_val")\""
    json_set "no_proxy" "\"$(json_escape "$no_proxy_val")\""
    json_set "git_proxy" "\"$git_proxy\""
}

scan_firewall() {
    log_section "Firewall & Packet Filters"
    report_section "Firewall & Packet Filters"
    
    # UFW
    local ufw_status="not installed"
    if cmd_exists ufw; then
        if [[ "$DRY_RUN" == "true" ]]; then
            ufw_status="[DRY-RUN: would run 'sudo ufw status']"
        else
            ufw_status="$(run_sudo ufw status verbose 2>/dev/null | head -20 || echo 'unable to query')"
        fi
    fi
    log_info "UFW status: $ufw_status"
    report "UFW status:"
    report "$ufw_status"
    
    # iptables
    local iptables_rules="not available"
    if cmd_exists iptables; then
        if [[ "$DRY_RUN" == "true" ]]; then
            iptables_rules="[DRY-RUN: would run 'sudo iptables -L -n']"
        else
            iptables_rules="$(run_sudo iptables -L -n 2>/dev/null | head -30 || echo 'unable to query')"
        fi
    fi
    log_info "iptables rules (first 30 lines):"
    log_info "$iptables_rules"
    report "iptables rules (first 30 lines):"
    report "$iptables_rules"
    
    # nftables
    local nft_rules="not available"
    if cmd_exists nft; then
        if [[ "$DRY_RUN" == "true" ]]; then
            nft_rules="[DRY-RUN: would run 'sudo nft list ruleset']"
        else
            nft_rules="$(run_sudo nft list ruleset 2>/dev/null | head -30 || echo 'unable to query')"
        fi
    fi
    log_info "nftables rules (first 30 lines):"
    log_info "$nft_rules"
    report "nftables rules (first 30 lines):"
    report "$nft_rules"
    
    json_set "ufw_active" "\"$(echo "$ufw_status" | grep -q 'Status: active' && echo yes || echo no)\""
}

scan_tls_interception() {
    log_section "TLS & Certificate Analysis"
    report_section "TLS & Certificate Analysis"
    
    # Check for corporate/custom CA certificates
    log_info "--- Custom CA Certificates ---"
    report "--- Custom CA Certificates ---"
    
    local custom_cas=""
    if [[ -d /usr/local/share/ca-certificates ]]; then
        custom_cas="$(find /usr/local/share/ca-certificates -name '*.crt' 2>/dev/null | head -10 || echo '')"
    fi
    
    if [[ -n "$custom_cas" ]]; then
        log_info "Custom CAs found in /usr/local/share/ca-certificates:"
        log_info "$custom_cas"
        report "Custom CAs found:"
        report "$custom_cas"
    else
        log_info "No custom CA certificates found in /usr/local/share/ca-certificates"
        report "No custom CA certificates found in /usr/local/share/ca-certificates"
    fi
    
    # TLS interception test for each domain
    log_info "--- TLS Interception Tests ---"
    report "--- TLS Interception Tests ---"
    
    local tls_results=()
    local interception_detected="no"
    
    for domain in "${DOMAIN_TESTS[@]}"; do
        log_info "Testing: $domain"
        report "Testing: $domain"
        
        local cert_file="$TMPDIR/${domain}.pem"
        local connect_result="failed"
        local issuer_cn=""
        local issuer_org=""
        local cert_chain_length=0
        
        # Attempt TLS connection with timeout
        if timeout "$NET_TIMEOUT" openssl s_client -showcerts -servername "$domain" \
            -connect "${domain}:443" </dev/null 2>/dev/null | \
            sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' > "$cert_file" 2>/dev/null; then
            
            if [[ -s "$cert_file" ]]; then
                connect_result="success"
                cert_chain_length="$(grep -c 'BEGIN CERTIFICATE' "$cert_file" || echo 0)"
                
                # Extract issuer info from the leaf certificate
                issuer_cn="$(openssl x509 -in "$cert_file" -noout -issuer 2>/dev/null | sed -n 's/.*CN *= *\([^,]*\).*/\1/p' | head -1 || echo '')"
                issuer_org="$(openssl x509 -in "$cert_file" -noout -issuer 2>/dev/null | sed -n 's/.*O *= *\([^,]*\).*/\1/p' | head -1 || echo '')"
                
                log_info "  Chain length: $cert_chain_length"
                log_info "  Issuer CN: ${issuer_cn:-unknown}"
                log_info "  Issuer Org: ${issuer_org:-unknown}"
                
                report "  Chain length: $cert_chain_length"
                report "  Issuer CN: ${issuer_cn:-unknown}"
                report "  Issuer Org: ${issuer_org:-unknown}"
                
                # Check for known TLS interception indicators
                local known_interceptors="ZScaler|Palo Alto|Fortinet|Blue Coat|Symantec|McAfee|Sophos|Barracuda|F5|Cisco|Check Point|Trend Micro|WatchGuard|Corporate|Internal|Enterprise"
                if echo "$issuer_org $issuer_cn" | grep -qiE "$known_interceptors"; then
                    interception_detected="yes"
                    log_warn "  -> Possible TLS interception detected: $issuer_org / $issuer_cn"
                    report "  [!] POSSIBLE TLS INTERCEPTION: $issuer_org / $issuer_cn"
                fi
                
                # Check if issuer is in system CA store
                local issuer_in_store="unknown"
                if [[ -n "$issuer_cn" ]]; then
                    if grep -rq "$issuer_cn" /etc/ssl/certs/ 2>/dev/null; then
                        issuer_in_store="yes"
                    else
                        issuer_in_store="no"
                        log_warn "  -> Issuer '$issuer_cn' NOT in system CA store"
                        report "  [!] Issuer not in system CA store"
                    fi
                fi
            fi
        else
            connect_result="connection failed"
            log_warn "  -> Could not connect to $domain (timeout or blocked)"
            report "  [!] Connection failed (timeout/blocked/DNS)"
        fi
        
        tls_results+=("{\"domain\":\"$domain\",\"status\":\"$connect_result\",\"issuer_cn\":\"$(json_escape "$issuer_cn")\",\"issuer_org\":\"$(json_escape "$issuer_org")\",\"chain_length\":$cert_chain_length}")
    done
    
    # Cloud provider connectivity tests
    log_info "--- Cloud Provider Endpoint Tests ---"
    report "--- Cloud Provider Endpoint Tests ---"
    
    local cloud_results=()
    for endpoint in "${CLOUD_ENDPOINTS[@]}"; do
        log_info "Testing: $endpoint"
        report "Testing: $endpoint"
        
        local connect_status="failed"
        if timeout "$NET_TIMEOUT" bash -c "echo >/dev/tcp/$endpoint/443" 2>/dev/null; then
            connect_status="reachable"
            log_info "  -> Reachable"
            report "  -> Reachable"
        else
            log_warn "  -> Connection failed"
            report "  [!] Connection failed"
        fi
        cloud_results+=("{\"endpoint\":\"$endpoint\",\"status\":\"$connect_status\"}")
    done
    
    json_set "tls_interception_detected" "\"$interception_detected\""
    json_set "tls_tests" "[$(IFS=,; echo "${tls_results[*]}")]"
    json_set "cloud_connectivity" "[$(IFS=,; echo "${cloud_results[*]}")]"
}

scan_snap_connectivity() {
    log_section "Snap Store Connectivity"
    report_section "Snap Store Connectivity"
    
    if ! cmd_exists snap; then
        log_info "Snap is not installed"
        report "Snap is not installed"
        json_set "snap_connectivity" "\"not_installed\""
        return
    fi
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] Would run: sudo snap debug connectivity"
        report "[DRY-RUN] Would run: sudo snap debug connectivity"
        json_set "snap_connectivity" "\"dry_run\""
        return
    fi
    
    local snap_debug
    snap_debug="$(run_sudo snap debug connectivity 2>&1 || echo 'failed')"
    
    log_info "$snap_debug"
    report "$snap_debug"
    
    if echo "$snap_debug" | grep -qi "certificate"; then
        log_warn "Snap connectivity has TLS/certificate issues"
        report "  [!] Snap likely blocked by TLS interception"
    fi
    
    json_set "snap_connectivity" "\"$(json_escape "$(echo "$snap_debug" | head -c 500)")\""
}

scan_docker() {
    log_section "Docker & Container Runtime"
    report_section "Docker & Container Runtime"
    
    # Docker
    if cmd_exists docker; then
        log_info "Docker binary: $(which docker)"
        report "Docker binary: $(which docker)"
        
        local docker_version
        docker_version="$(docker --version 2>/dev/null || echo 'unknown')"
        log_info "Docker version: $docker_version"
        report "Docker version: $docker_version"
        
        # Check if docker daemon is running
        local docker_running="no"
        if docker info >/dev/null 2>&1; then
            docker_running="yes (user can access)"
        elif run_sudo docker info >/dev/null 2>&1; then
            docker_running="yes (requires sudo)"
        fi
        
        log_info "Docker daemon: $docker_running"
        report "Docker daemon: $docker_running"
        
        if [[ "$docker_running" == *"sudo"* ]]; then
            log_warn "Docker requires sudo - add user to docker group for convenience"
            report "  [!] Consider: sudo usermod -aG docker $CURRENT_USER"
        fi
        
        # Docker storage driver and info
        if [[ "$DRY_RUN" != "true" ]] && [[ "$docker_running" != "no" ]]; then
            local docker_info
            docker_info="$(docker info 2>/dev/null || run_sudo docker info 2>/dev/null || echo '')"
            if [[ -n "$docker_info" ]]; then
                local storage_driver
                storage_driver="$(echo "$docker_info" | grep 'Storage Driver' | head -1 || echo 'unknown')"
                log_info "$storage_driver"
                report "$storage_driver"
            fi
        fi
        
        json_set "docker_installed" "\"yes\""
        json_set "docker_version" "\"$(json_escape "$docker_version")\""
        json_set "docker_running" "\"$docker_running\""
    else
        log_info "Docker is not installed"
        report "Docker is not installed"
        json_set "docker_installed" "\"no\""
    fi
    
    # Podman (alternative)
    if cmd_exists podman; then
        local podman_version
        podman_version="$(podman --version 2>/dev/null || echo 'unknown')"
        log_info "Podman: $podman_version"
        report "Podman: $podman_version"
        json_set "podman_installed" "\"yes\""
        json_set "podman_version" "\"$(json_escape "$podman_version")\""
    else
        json_set "podman_installed" "\"no\""
    fi
    
    # containerd
    if cmd_exists ctr; then
        log_info "containerd (ctr): installed"
        report "containerd: installed"
        json_set "containerd_installed" "\"yes\""
    else
        json_set "containerd_installed" "\"no\""
    fi
}

scan_security_frameworks() {
    log_section "Security Frameworks (AppArmor, SELinux)"
    report_section "Security Frameworks"
    
    # AppArmor
    local apparmor_status="not active"
    if cmd_exists aa-status; then
        if [[ "$DRY_RUN" == "true" ]]; then
            apparmor_status="[DRY-RUN: would run aa-status]"
        else
            local aa_out
            aa_out="$(run_sudo aa-status 2>&1 || echo 'unable to query')"
            if echo "$aa_out" | grep -q "profiles are loaded"; then
                apparmor_status="active"
                local aa_profiles
                aa_profiles="$(echo "$aa_out" | grep 'profiles are' | head -5)"
                log_info "AppArmor: $aa_profiles"
                report "AppArmor: $aa_profiles"
            else
                apparmor_status="installed but not active"
            fi
        fi
    fi
    log_info "AppArmor: $apparmor_status"
    report "AppArmor: $apparmor_status"
    
    # SELinux
    local selinux_status="not available"
    if cmd_exists sestatus; then
        selinux_status="$(sestatus 2>/dev/null | head -5 || echo 'unable to query')"
    elif cmd_exists getenforce; then
        selinux_status="$(getenforce 2>/dev/null || echo 'unable to query')"
    fi
    log_info "SELinux: $selinux_status"
    report "SELinux: $selinux_status"
    
    json_set "apparmor_status" "\"$(json_escape "$apparmor_status")\""
    json_set "selinux_status" "\"$(json_escape "$selinux_status")\""
}

scan_dev_tools() {
    log_section "Developer Tools Inventory"
    report_section "Developer Tools Inventory"
    
    # Define tools to check with categories
    declare -A tool_categories=(
        # Version Control
        ["git"]="vcs"
        ["gh"]="vcs"
        
        # Editors/IDEs
        ["code"]="editor"
        ["cursor"]="editor"
        ["vim"]="editor"
        ["nvim"]="editor"
        ["nano"]="editor"
        
        # Container & Kubernetes
        ["docker"]="container"
        ["podman"]="container"
        ["kubectl"]="k8s"
        ["helm"]="k8s"
        ["kind"]="k8s"
        ["minikube"]="k8s"
        ["k3d"]="k8s"
        ["k9s"]="k8s"
        
        # IaC & Config Management
        ["terraform"]="iac"
        ["tofu"]="iac"
        ["ansible"]="iac"
        ["ansible-playbook"]="iac"
        ["pulumi"]="iac"
        
        # Cloud CLIs
        ["aws"]="cloud"
        ["az"]="cloud"
        ["gcloud"]="cloud"
        ["ionosctl"]="cloud"
        ["aliyun"]="cloud" # Alibaba Cloud CLI
        ["oci"]="cloud"    # Oracle Cloud CLI
        
        # Languages & Package Managers
        ["python3"]="lang"
        ["pip"]="lang"
        ["pipx"]="lang"
        ["node"]="lang"
        ["npm"]="lang"
        ["yarn"]="lang"
        ["go"]="lang"
        ["cargo"]="lang"
        ["rustc"]="lang"
        
        # Utilities
        ["jq"]="util"
        ["yq"]="util"
        ["curl"]="util"
        ["wget"]="util"
        ["htop"]="util"
        ["tmux"]="util"
        ["make"]="util"
        
        # AI/Dev tools
        ["claude"]="ai"
    )
    
    local tools_found=""
    local tools_missing=""
    local tools_json="{"
    
    for tool in "${!tool_categories[@]}"; do
        local category="${tool_categories[$tool]}"
        if cmd_exists "$tool"; then
            local version=""
            case "$tool" in
                git) version="$(git --version 2>/dev/null | awk '{print $3}')" ;;
                docker) version="$(docker --version 2>/dev/null | awk '{print $3}' | tr -d ',')" ;;
                kubectl) version="$(kubectl version --client -o json 2>/dev/null | jq -r '.clientVersion.gitVersion' 2>/dev/null || echo 'unknown')" ;;
                terraform) version="$(terraform version -json 2>/dev/null | jq -r '.terraform_version' 2>/dev/null || echo 'unknown')" ;;
                aws) version="$(aws --version 2>/dev/null | awk '{print $1}' | cut -d/ -f2)" ;;
                az) version="$(az version -o tsv 2>/dev/null | head -1 || echo 'unknown')" ;;
                gcloud) version="$(gcloud version 2>/dev/null | head -1 | awk '{print $4}')" ;;
                helm) version="$(helm version --short 2>/dev/null || echo 'unknown')" ;;
                *) version="installed" ;;
            esac
            log_info "  [✓] $tool ($category): $version"
            report "  [✓] $tool ($category): $version"
            tools_found+="$tool "
            tools_json+="\"$tool\":{\"installed\":true,\"category\":\"$category\",\"version\":\"$(json_escape "$version")\"},"
        else
            tools_missing+="$tool "
            tools_json+="\"$tool\":{\"installed\":false,\"category\":\"$category\"},"
        fi
    done
    
    tools_json="${tools_json%,}}"
    
    log_info ""
    log_info "Missing tools: ${tools_missing:-none}"
    report ""
    report "Missing tools: ${tools_missing:-none}"
    
    json_set "dev_tools" "$tools_json"
}

scan_devops_specific() {
    log_section "DevOps Workflow Checks"
    report_section "DevOps Workflow Checks"
    
    # Git configuration
    log_info "--- Git Configuration ---"
    report "--- Git Configuration ---"
    
    if cmd_exists git; then
        local git_user git_email
        git_user="$(git config --global user.name 2>/dev/null || echo 'not set')"
        git_email="$(git config --global user.email 2>/dev/null || echo 'not set')"
        
        log_info "Git user.name: $git_user"
        log_info "Git user.email: $git_email"
        report "Git user.name: $git_user"
        report "Git user.email: $git_email"
        
        # SSH key check
        local ssh_keys_exist="no"
        if [[ -f "$HOME/.ssh/id_rsa" ]] || [[ -f "$HOME/.ssh/id_ed25519" ]] || [[ -f "$HOME/.ssh/id_ecdsa" ]]; then
            ssh_keys_exist="yes"
        fi
        log_info "SSH keys present: $ssh_keys_exist"
        report "SSH keys present: $ssh_keys_exist"
        
        # Git credential helper
        local git_cred_helper
        git_cred_helper="$(git config --global credential.helper 2>/dev/null || echo 'not configured')"
        log_info "Git credential helper: $git_cred_helper"
        report "Git credential helper: $git_cred_helper"
        
        json_set "git_user" "\"$(json_escape "$git_user")\""
        json_set "git_email" "\"$(json_escape "$git_email")\""
        json_set "ssh_keys_present" "\"$ssh_keys_exist\""
    fi
    
    # Kubernetes configs
    log_info "--- Kubernetes Configuration ---"
    report "--- Kubernetes Configuration ---"
    
    local kubeconfig_exists="no"
    local kubeconfig_path="${KUBECONFIG:-$HOME/.kube/config}"
    if [[ -f "$kubeconfig_path" ]]; then
        kubeconfig_exists="yes"
        local contexts
        contexts="$(kubectl config get-contexts -o name 2>/dev/null | head -10 || echo 'unable to read')"
        log_info "KUBECONFIG exists: $kubeconfig_path"
        log_info "Available contexts: $contexts"
        report "KUBECONFIG: $kubeconfig_path"
        report "Contexts: $contexts"
    else
        log_info "KUBECONFIG: not found"
        report "KUBECONFIG: not found at $kubeconfig_path"
    fi
    json_set "kubeconfig_exists" "\"$kubeconfig_exists\""
    
    # Cloud credentials check (existence only, not contents)
    log_info "--- Cloud Credentials (existence check) ---"
    report "--- Cloud Credentials (existence check) ---"
    
    local aws_creds="no"
    [[ -f "$HOME/.aws/credentials" ]] || [[ -n "${AWS_ACCESS_KEY_ID:-}" ]] && aws_creds="yes"
    
    local azure_creds="no"
    [[ -d "$HOME/.azure" ]] && azure_creds="yes"
    
    local gcloud_creds="no"
    [[ -d "$HOME/.config/gcloud" ]] && gcloud_creds="yes"
    
    local alibaba_creds="no"
    [[ -d "$HOME/.aliyun" ]] && alibaba_creds="yes"
    
    local oracle_creds="no"
    [[ -d "$HOME/.oci" ]] && oracle_creds="yes"
    
    log_info "AWS credentials: $aws_creds"
    log_info "Azure credentials: $azure_creds"
    log_info "GCloud credentials: $gcloud_creds"
    log_info "Alibaba credentials: $alibaba_creds"
    log_info "Oracle credentials: $oracle_creds"
    
    report "AWS credentials present: $aws_creds"
    report "Azure credentials present: $azure_creds"
    report "GCloud credentials present: $gcloud_creds"
    report "Alibaba credentials present: $alibaba_creds"
    report "Oracle credentials present: $oracle_creds"
    
    json_set "aws_credentials_exist" "\"$aws_creds\""
    json_set "azure_credentials_exist" "\"$azure_creds\""
    json_set "gcloud_credentials_exist" "\"$gcloud_creds\""
    json_set "alibaba_credentials_exist" "\"$alibaba_creds\""
    json_set "oracle_credentials_exist" "\"$oracle_creds\""
    
    # IDE/Editor extensions directory check
    log_info "--- IDE Configuration ---"
    report "--- IDE Configuration ---"
    
    if [[ -d "$HOME/.vscode" ]] || [[ -d "$HOME/.config/Code" ]]; then
        log_info "VS Code config: present"
        report "VS Code config: present"
    fi
    
    if [[ -d "$HOME/.cursor" ]] || [[ -d "$HOME/.config/Cursor" ]]; then
        log_info "Cursor config: present"
        report "Cursor config: present"
    fi
}

scan_storage_io() {
    log_section "Storage I/O & Performance"
    report_section "Storage I/O & Performance"
    
    # Quick I/O test (write and read speed to home directory)
    log_info "--- Simple I/O Test ---"
    report "--- Simple I/O Test ---"
    
    local io_test_file="$HOME/.io_test_$$"
    local write_speed="unknown"
    local read_speed="unknown"
    
    if cmd_exists dd; then
        # Write 100MB test
        local dd_output_write
        dd_output_write="$(dd if=/dev/zero of="$io_test_file" bs=1M count=100 conv=fdatasync 2>&1 || echo 'failed')"
        
        if [[ "$dd_output_write" != "failed" ]]; then
            write_speed="$(echo "$dd_output_write" | grep -oE '[0-9.]+ [MG]B/s' | tail -1 || echo 'parsed failed')"
            log_info "Sequential write (100MB): $write_speed"
            report "Sequential write speed: $write_speed"

            # Read 100MB test (clear cache first for better realism, requires sudo)
            if [[ "$DRY_RUN" != "true" ]]; then
                # Drop caches - note: this requires sudo
                run_sudo sysctl vm.drop_caches=3 >/dev/null 2>&1
            fi

            local dd_output_read
            dd_output_read="$(dd if="$io_test_file" of=/dev/null bs=1M count=100 2>&1 || echo 'failed')"
            
            if [[ "$dd_output_read" != "failed" ]]; then
                read_speed="$(echo "$dd_output_read" | grep -oE '[0-9.]+ [MG]B/s' | tail -1 || echo 'parsed failed')"
                log_info "Sequential read (100MB): $read_speed"
                report "Sequential read speed: $read_speed"
            fi
        fi
        rm -f "$io_test_file"
    fi
    
    # iostat if available
    if cmd_exists iostat; then
        log_info "--- iostat snapshot ---"
        report "--- iostat snapshot ---"
        local iostat_out
        iostat_out="$(iostat -x 1 1 2>/dev/null | tail -20 || echo 'failed')"
        log_info "$iostat_out"
        report "$iostat_out"
    fi
    
    json_set "io_write_speed" "\"$(json_escape "$write_speed")\""
    json_set "io_read_speed" "\"$(json_escape "$read_speed")\""
}

generate_summary() {
    log_section "Analysis & Recommendations"
    report_section "Analysis & Recommendations"
    
    local issues_found=()
    local actions_needed=()
    local it_requests=()
    
    # Analyze collected data and generate recommendations
    
    # TLS Interception
    if [[ "${JSON_DATA[tls_interception_detected]:-}" == "\"yes\"" ]]; then
        issues_found+=("TLS interception detected - HTTPS traffic is being inspected")
        actions_needed+=("Install corporate root CA certificate")
        it_requests+=("Request corporate root CA certificate for installation")
    fi
    
    # Docker
    if [[ "${JSON_DATA[docker_installed]:-}" == "\"no\"" ]]; then
        issues_found+=("Docker not installed")
        it_requests+=("Request Docker installation or permission to install")
    elif [[ "${JSON_DATA[docker_running]:-}" == *"sudo"* ]]; then
        actions_needed+=("Add user to docker group: sudo usermod -aG docker $CURRENT_USER")
    fi
    
    # cgroups
    if [[ "${JSON_DATA[cgroup_version]:-}" == "\"v1 (legacy)\"" ]]; then
        issues_found+=("cgroups v1 in use - some container features limited")
    fi
    
    # User namespaces
    if [[ "${JSON_DATA[user_namespaces]:-}" == "\"disabled\"" ]]; then
        issues_found+=("User namespaces disabled - rootless containers won't work")
        it_requests+=("Request enabling unprivileged user namespaces if rootless containers needed")
    fi
    
    # Snap
    if [[ "${JSON_DATA[snap_connectivity]:-}" == *"certificate"* ]]; then
        issues_found+=("Snap store blocked by TLS interception")
        actions_needed+=("Configure snap to use corporate proxy or request TLS exception")
    fi
    
    # PEP 668
    if [[ "${JSON_DATA[pep668_active]:-}" == "\"yes\"" ]]; then
        actions_needed+=("Use virtual environments (venv) or pipx for Python packages")
    fi
    
    # Output summary
    log_info ""
    log_info "======== SUMMARY ========"
    report ""
    report "======== SUMMARY ========"
    
    if [[ ${#issues_found[@]} -gt 0 ]]; then
        log_info ""
        log_info "Issues Found:"
        report ""
        report "Issues Found:"
        for issue in "${issues_found[@]}"; do
            log_info "  • $issue"
            report "  • $issue"
        done
    fi
    
    if [[ ${#actions_needed[@]} -gt 0 ]]; then
        log_info ""
        log_info "Actions You Can Take (no IT needed):"
        report ""
        report "Actions You Can Take (no IT needed):"
        for action in "${actions_needed[@]}"; do
            log_info "  → $action"
            report "  → $action"
        done
    fi
    
    if [[ ${#it_requests[@]} -gt 0 ]]; then
        log_info ""
        log_info "Items Requiring IT Assistance:"
        report ""
        report "Items Requiring IT Assistance:"
        for req in "${it_requests[@]}"; do
            log_info "  ⚠ $req"
            report "  ⚠ $req"
        done
    fi
    
    # Warnings and errors from scan
    if [[ ${#SCAN_WARNINGS[@]} -gt 0 ]]; then
        log_info ""
        log_info "Scan Warnings:"
        report ""
        report "Scan Warnings:"
        for warn in "${SCAN_WARNINGS[@]}"; do
            report "  [WARN] $warn"
        done
    fi
    
    # General recommendations
    cat >> "$OUT_TXT" <<'EOF'

======== RECOMMENDED NEXT STEPS ========

1) If TLS interception is detected:
   - Request the corporate root CA from IT
   - Install it: sudo cp corporate-ca.crt /usr/local/share/ca-certificates/
   - Update store: sudo update-ca-certificates
   - Configure tools (git, npm, pip) to use the CA or proxy

2) If package installation is restricted:
   - Provide IT with a list of required packages
   - Request an approved software bundle or elevated permissions
   - Consider using portable/user-space tools where possible

3) For container workflows:
   - If Docker unavailable, ask IT for Docker or Podman
   - If user not in docker group: sudo usermod -aG docker $USER && newgrp docker
   - For Kubernetes local dev: request kind, minikube, or k3d

4) For cloud provider access:
   - Test connectivity to each provider's endpoints
   - Configure appropriate CLI tools with credentials
   - Ensure proxy settings are correct for cloud API access

5) When requesting IT help, include:
   - This scan report file
   - Specific software list needed
   - Business justification

==============================================

EOF

    log_info ""
    log_info "Full report saved to: $OUT_TXT"
    log_info "JSON data saved to: $OUT_JSON"
}

generate_json() {
    # Build complete JSON from collected data
    {
        echo "{"
        echo "  \"scan_metadata\": {"
        echo "    \"version\": \"$VERSION\","
        echo "    \"generated_at\": \"$NOW\","
        echo "    \"hostname\": \"$HOSTNAME_VAL\","
        echo "    \"user\": \"$CURRENT_USER\","
        echo "    \"dry_run\": $DRY_RUN"
        echo "  },"
        
        echo "  \"system\": {"
        for key in os_release kernel arch vm_product vmware_tools guest_agents; do
            [[ -n "${JSON_DATA[$key]:-}" ]] && echo "    \"$key\": ${JSON_DATA[$key]},"
        done
        echo "    \"_\": null"
        echo "  },"
        
        echo "  \"virtualization\": {"
        for key in virtualization_type kvm_modules nested_virtualization cgroup_version user_namespaces seccomp; do
            [[ -n "${JSON_DATA[$key]:-}" ]] && echo "    \"$key\": ${JSON_DATA[$key]},"
        done
        echo "    \"_\": null"
        echo "  },"
        
        echo "  \"user\": {"
        for key in user uid gid groups in_docker_group in_sudo_group in_kvm_group passwordless_sudo; do
            [[ -n "${JSON_DATA[$key]:-}" ]] && echo "    \"$key\": ${JSON_DATA[$key]},"
        done
        echo "    \"_\": null"
        echo "  },"
        
        echo "  \"storage\": {"
        for key in root_fs_type root_fs_size root_fs_available root_fs_use_percent tmp_writable home_writable readonly_mounts io_write_speed io_read_speed; do
            [[ -n "${JSON_DATA[$key]:-}" ]] && echo "    \"$key\": ${JSON_DATA[$key]},"
        done
        echo "    \"_\": null"
        echo "  },"
        
        echo "  \"packages\": {"
        for key in apt_sources_count apt_locked apt_proxy snap_installed flatpak_installed python_version pip_version pipx_installed pep668_active node_version npm_version; do
            [[ -n "${JSON_DATA[$key]:-}" ]] && echo "    \"$key\": ${JSON_DATA[$key]},"
        done
        echo "    \"_\": null"
        echo "  },"
        
        echo "  \"network\": {"
        for key in default_gateway dns_method http_proxy https_proxy no_proxy git_proxy ufw_active; do
            [[ -n "${JSON_DATA[$key]:-}" ]] && echo "    \"$key\": ${JSON_DATA[$key]},"
        done
        echo "    \"_\": null"
        echo "  },"
        
        echo "  \"tls\": {"
        echo "    \"interception_detected\": ${JSON_DATA[tls_interception_detected]:-\"unknown\"},"
        echo "    \"tests\": ${JSON_DATA[tls_tests]:-[]},"
        echo "    \"cloud_connectivity\": ${JSON_DATA[cloud_connectivity]:-[]}"
        echo "  },"
        
        echo "  \"containers\": {"
        for key in docker_installed docker_version docker_running podman_installed podman_version containerd_installed snap_connectivity; do
            [[ -n "${JSON_DATA[$key]:-}" ]] && echo "    \"$key\": ${JSON_DATA[$key]},"
        done
        echo "    \"_\": null"
        echo "  },"
        
        echo "  \"security\": {"
        for key in apparmor_status selinux_status; do
            [[ -n "${JSON_DATA[$key]:-}" ]] && echo "    \"$key\": ${JSON_DATA[$key]},"
        done
        echo "    \"_\": null"
        echo "  },"
        
        echo "  \"devops\": {"
        for key in git_user git_email ssh_keys_present kubeconfig_exists aws_credentials_exist azure_credentials_exist gcloud_credentials_exist alibaba_credentials_exist oracle_credentials_exist; do
            [[ -n "${JSON_DATA[$key]:-}" ]] && echo "    \"$key\": ${JSON_DATA[$key]},"
        done
        echo "    \"_\": null"
        echo "  },"
        
        echo "  \"dev_tools\": ${JSON_DATA[dev_tools]:-{}},"
        
        echo "  \"warnings\": ["
        for i in "${!SCAN_WARNINGS[@]}"; do
            echo "    \"$(json_escape "${SCAN_WARNINGS[$i]}")\""$([[ $i -lt $((${#SCAN_WARNINGS[@]}-1)) ]] && echo ",")
        done
        echo "  ]"
        
        echo "}"
    } > "$OUT_JSON"
    
    # Clean up the JSON (remove trailing commas before closing braces and null placeholders)
    if cmd_exists python3; then
        python3 -c "
import json
import re

with open('$OUT_JSON', 'r') as f:
    content = f.read()

# Remove the placeholder null entries
content = re.sub(r',?\s*\"_\":\s*null', '', content)
# Remove trailing commas
content = re.sub(r',(\s*[}\]])', r'\1', content)

try:
    data = json.loads(content)
    with open('$OUT_JSON', 'w') as f:
        json.dump(data, f, indent=2)
except:
    with open('$OUT_JSON', 'w') as f:
        f.write(content)
" 2>/dev/null || true
    fi
}

#-------------------------------------------------------------------------------
# Main Execution
#-------------------------------------------------------------------------------

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --json-only)
                JSON_ONLY=true
                shift
                ;;
            --section)
                SECTION_FILTER="$2"
                shift 2
                ;;
            --help|-h)
                show_help
                ;;
            *)
                echo "Unknown option: $1"
                show_help
                ;;
        esac
    done
    
    # Create temp directory
    TMPDIR="$(mktemp -d)"
    trap 'rm -rf "$TMPDIR"' EXIT
    
    # Initialize output files
    rm -f "$OUT_TXT" "$OUT_JSON"
    
    if [[ "$JSON_ONLY" != "true" ]]; then
        cat > "$OUT_TXT" <<EOF
================================================================================
VM Environment Scan Report
================================================================================
Generated: $NOW
Hostname:  $HOSTNAME_VAL
User:      $CURRENT_USER
Scanner:   v$VERSION
Dry-run:   $DRY_RUN

This is a PASSIVE scan. It reports findings and flags items that typically
restrict developer workflows. It does NOT attempt to circumvent any controls.
================================================================================
EOF
    fi
    
    log_info "VM Environment Scanner v$VERSION"
    log_info "Starting scan at $NOW"
    log_info "Dry-run mode: $DRY_RUN"
    log_info ""

    # Check for critical dependencies
    check_dependencies
    
    log_info ""
    
    # Run scans (filtered if --section specified)
    run_section() {
        local name="$1"
        local func="$2"
        if [[ -z "$SECTION_FILTER" ]] || [[ "$SECTION_FILTER" == "$name" ]]; then
            $func
        fi
    }
    
    run_section "system"   scan_system_basics
    run_section "virt"     scan_virtualization
    run_section "user"     scan_user_permissions
    run_section "disk"     scan_disk_storage
    run_section "packages" scan_package_managers
    run_section "network"  scan_network
    run_section "firewall" scan_firewall
    run_section "tls"      scan_tls_interception
    run_section "snap"     scan_snap_connectivity
    run_section "docker"   scan_docker
    run_section "security" scan_security_frameworks
    run_section "tools"    scan_dev_tools
    run_section "devops"   scan_devops_specific
    run_section "storage"  scan_storage_io
    run_section "summary"  generate_summary
    
    # Generate JSON output
    generate_json
    
    log_info ""
    log_info "Scan complete."
    log_info "Reports saved to:"
    log_info "  Human-readable: $OUT_TXT"
    log_info "  Machine-readable: $OUT_JSON"
}

main "$@"