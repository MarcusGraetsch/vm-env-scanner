# VM Environment Scanner

A friendly, comprehensive environment scanner for Ubuntu virtual machines (and physical systems) that helps you understand your system's capabilities and restrictions—without breaking any rules.

## What Is This For?

### 🎯 Primary Use Case: Onboarding to DevOps & Development

You've been given a company laptop or VM and want to start working on development or DevOps projects. But you're hitting walls:

- "Why can't I install Docker?"
- "Why does `pip install` fail?"
- "Why can't I connect to GitHub?"

**This scanner tells you exactly what's going on** — in plain language — and suggests what to do next.

### 🤖 Secondary Use Case: Preparing Systems for AI Agents

AI coding assistants (like Claude, GitHub Copilot, or local agents) work best when they understand the environment they're operating in. This scanner produces both human-readable reports and machine-readable JSON that AI agents can consume to:

- Understand what tools are available
- Know which operations will fail before trying them
- Suggest workarounds within your system's constraints
- Help you communicate with IT about what you need

## Philosophy: Work Within the Rules

> **This tool does NOT attempt to bypass, circumvent, or disable any security controls.**

Corporate IT departments set up restrictions for good reasons: security, compliance, and stability. This scanner:

- ✅ **Observes** your environment passively
- ✅ **Reports** what it finds in clear language
- ✅ **Explains** what each restriction means for your workflow
- ✅ **Suggests** legitimate next steps (including what to ask IT for)
- ❌ **Does NOT** modify system settings
- ❌ **Does NOT** attempt to escalate privileges inappropriately
- ❌ **Does NOT** circumvent security controls

## What Does It Check?

| Category | What's Scanned |
|----------|----------------|
| **System Basics** | OS version, kernel, VM type, guest tools |
| **Virtualization** | Container support (cgroups v1/v2), nested virtualization, user namespaces |
| **User Permissions** | Groups, sudo access, docker group membership |
| **Storage** | Disk space, read-only mounts, write permissions |
| **Package Managers** | APT sources, Snap, Flatpak, pip/pipx, npm, PEP 668 status |
| **Network** | Interfaces, DNS, proxy configuration |
| **Firewall** | UFW, iptables, nftables rules |
| **TLS/Certificates** | Corporate CA detection, TLS interception (common cause of "certificate errors") |
| **Containers** | Docker, Podman, containerd availability and status |
| **Security Frameworks** | AppArmor, SELinux status |
| **Developer Tools** | Git, IDEs, Kubernetes tools, cloud CLIs, IaC tools |
| **Cloud Connectivity** | Reachability of AWS, Azure, GCP, IONOS, Stackit, Delos, and others |

## Installation

```bash
# Download the script
curl -O https://raw.githubusercontent.com/MarcusGraetsch/vm-env-scanner/main/vm_env_scanner.sh

# Make it executable
chmod +x vm_env_scanner.sh
```

Or clone the repository:

```bash
git clone https://github.com/MarcusGraetsch/vm-env-scanner.git
cd vm-env-scanner
chmod +x vm_env_scanner.sh
```

## Usage

### Basic Scan (Recommended for First Run)

```bash
./vm_env_scanner.sh
```

This runs all checks and produces:
- `~/vm_env_scan_report.txt` — Human-readable report
- `~/vm_env_scan_report.json` — Machine-readable data (for AI agents or automation)

### Preview Mode (See What Would Happen)

```bash
./vm_env_scanner.sh --dry-run
```

Shows what `sudo` commands would be executed without actually running them. Useful if you want to verify the script's behavior before running it fully.

### Scan Specific Section Only

```bash
./vm_env_scanner.sh --section tls      # Only TLS/certificate checks
./vm_env_scanner.sh --section docker   # Only container runtime checks
./vm_env_scanner.sh --section tools    # Only developer tools inventory
```

Available sections: `system`, `virt`, `user`, `disk`, `packages`, `network`, `firewall`, `tls`, `snap`, `docker`, `security`, `tools`, `devops`, `storage`, `summary`

### JSON Output Only (For Automation/AI Agents)

```bash
./vm_env_scanner.sh --json-only
```

Suppresses human-readable output; only generates the JSON report.

## Automated Environment Setup

After running the scanner and reviewing the results, you can use the **automated setup script** to install all missing DevOps tools and configure your environment.

### Quick Start

```bash
# 1. Run the scanner first
./vm_env_scanner_v2.sh

# 2. Review the generated report
cat ~/vm_env_scan_report.json

# 3. Run the automated setup
chmod +x vm_env_setup.sh
./vm_env_setup.sh
```

### What Gets Installed

The setup script automatically installs:

**Base Development Tools**
- Build essentials, git, curl, wget, jq, yq
- tmux, vim, nano, htop, tree

**Programming Languages & Runtimes**
- Node.js 20.x LTS + npm + yarn
- Go (latest stable)
- Rust (via rustup)
- Python development tools (respects PEP 668)

**Cloud Provider CLIs**
- AWS CLI v2
- Azure CLI
- Google Cloud SDK
- Oracle Cloud CLI (oci)
- Alibaba Cloud CLI (aliyun)
- IONOS Cloud CLI (ionosctl)
- STACKIT CLI

**Kubernetes Tools**
- kubectl
- Helm
- k9s
- Minikube
- kind
- k3d

**Infrastructure as Code**
- Terraform
- OpenTofu
- Pulumi

**IDEs & Editors**
- Visual Studio Code
- Cursor (AI-powered IDE)
- Neovim

**AI Coding Assistants**
- GitHub CLI (for Copilot)
- Claude Code CLI

**Container Tools**
- Docker (if not already installed)
- Proper docker group configuration

### Setup Script Options

```bash
# Dry run - see what would be installed without installing
./vm_env_setup.sh --dry-run

# Skip specific categories
./vm_env_setup.sh --skip-cloud    # Skip cloud provider CLIs
./vm_env_setup.sh --skip-k8s      # Skip Kubernetes tools
./vm_env_setup.sh --skip-iac      # Skip IaC tools
./vm_env_setup.sh --skip-ide      # Skip IDE installations

# Use a different scan file
./vm_env_setup.sh --scan-file /path/to/custom_scan.json

# Combine options
./vm_env_setup.sh --dry-run --skip-ide --skip-k8s
```

### Handling Corporate TLS Certificates

If the scanner detected TLS interception (common in corporate environments), use the certificate fixer:

```bash
chmod +x fix_tls_certificates.sh
./fix_tls_certificates.sh
```

This will:
1. Extract the corporate certificate from your HTTPS connections
2. Install it system-wide
3. Configure all development tools (git, npm, pip, curl, wget, docker) to use it
4. Test connectivity to common package registries

**Automatic installation:**
```bash
./fix_tls_certificates.sh --auto-install
```

**Test a different domain:**
```bash
./fix_tls_certificates.sh --test-domain pypi.org
```

### Post-Installation Steps

After running the setup script, you'll need to:

1. **Reload your shell configuration:**
   ```bash
   source ~/.bashrc
   # Or log out and log back in
   ```

2. **Authenticate with cloud providers:**
   ```bash
   aws configure          # AWS
   az login              # Azure
   gcloud auth login     # Google Cloud
   oci setup config      # Oracle Cloud
   aliyun configure      # Alibaba Cloud
   ionosctl login        # IONOS
   stackit auth login    # STACKIT
   ```

3. **Set up AI coding assistants:**
   ```bash
   gh auth login         # GitHub Copilot
   claude-code auth      # Claude Code
   ```

4. **Configure Docker (if user group was changed):**
   - Log out and log back in for docker group membership to take effect
   - Or run: `newgrp docker`

### Logs and Reports

The setup script generates detailed logs:
- `vm_env_setup_YYYYMMDD_HHMMSS.log` - Full installation log
- `vm_env_setup_complete_YYYYMMDD_HHMMSS.json` - Summary of what was installed, failed, or skipped

## Understanding the Output

### The Human Report (`~/vm_env_scan_report.txt`)

The report is organized into sections. At the end, you'll find:

**Issues Found** — Problems that may block your work
```
• TLS interception detected - HTTPS traffic is being inspected
• Docker not installed
```

**Actions You Can Take** — Things you can fix yourself
```
→ Add user to docker group: sudo usermod -aG docker yourname
→ Use virtual environments (venv) or pipx for Python packages
```

**Items Requiring IT Assistance** — Things you need to request
```
⚠ Request corporate root CA certificate for installation
⚠ Request Docker installation or permission to install
```

### The JSON Report (`~/vm_env_scan_report.json`)

Structured data that can be parsed by scripts or AI agents:

```json
{
  "scan_metadata": {
    "version": "2.0.0",
    "generated_at": "2025-01-15T10:30:00+01:00",
    "hostname": "dev-vm-01",
    "user": "developer"
  },
  "containers": {
    "docker_installed": "yes",
    "docker_running": "yes (requires sudo)"
  },
  "tls": {
    "interception_detected": "yes",
    "tests": [...]
  }
}
```

## Common Scenarios & Solutions

### "I can't install anything with pip"

**What the scanner shows:** `PEP 668 (externally managed): yes`

**What this means:** Modern Ubuntu uses "externally managed" Python to prevent system breakage.

**What to do:**
```bash
# Option 1: Use pipx for CLI tools
pipx install ansible

# Option 2: Use virtual environments for projects
python3 -m venv myproject-venv
source myproject-venv/bin/activate
pip install whatever-you-need
```

### "Docker commands require sudo"

**What the scanner shows:** `In docker group: no`

**What to do:**
```bash
sudo usermod -aG docker $USER
# Then log out and back in (or run: newgrp docker)
```

### "I get certificate errors connecting to GitHub/PyPI/Docker Hub"

**What the scanner shows:** `TLS interception detected` with issuer showing corporate security vendor

**What this means:** Your company inspects HTTPS traffic for security. This breaks certificate verification for many tools.

**What to do:**
1. Request the corporate root CA certificate from IT
2. Install it:
   ```bash
   sudo cp corporate-ca.crt /usr/local/share/ca-certificates/
   sudo update-ca-certificates
   ```
3. Configure tools that need it (git, npm, pip may need additional config)

### "Snap packages won't install"

**What the scanner shows:** Snap connectivity errors mentioning "certificate"

**What this means:** Same TLS interception issue affecting the Snap store.

**What to do:** Ask IT about Snap store access or use alternative installation methods (APT, direct downloads, Flatpak if available).

## For AI Agents

If you're an AI agent reading this repository or consuming the JSON output:

1. **Parse `~/vm_env_scan_report.json`** for structured environment data
2. **Check `tls.interception_detected`** before suggesting commands that fetch from the internet
3. **Check `containers.docker_installed`** and `containers.docker_running`** before suggesting Docker commands
4. **Check `packages.pep668_active`** before suggesting `pip install` without a virtual environment
5. **Check `user.in_docker_group`** to know if Docker commands need `sudo`
6. **Review `warnings`** array for known issues

The JSON schema is designed to be self-documenting. Unknown or failed checks return `"unknown"` rather than causing parse errors.

## Requirements

- Ubuntu 20.04+ (may work on other Debian-based systems)
- Bash 4.0+
- Standard Unix tools (coreutils, grep, sed, awk)
- `openssl` for TLS checks
- Optional: `sudo` access for deeper inspection (firewall rules, AppArmor status)

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-check`)
3. Make your changes
4. Test on a clean Ubuntu VM
5. Submit a pull request

See [CHANGELOG.md](CHANGELOG.md) for version history.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Inspired by the need to onboard developers onto restricted corporate environments without friction
- Built with assistance from Claude (Anthropic) as a practical DevOps tool

## Support

If you find this useful, consider:
- ⭐ Starring the repository
- 🐛 Reporting issues you encounter
- 💡 Suggesting new checks that would help others
- 🤝 Contributing improvements

---

*This tool helps you understand your environment. It doesn't change it. Always work with your IT department, not around them.*
