# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- macOS support
- Windows WSL2 detection and scanning
- Interactive mode with guided remediation
- Integration with common CI/CD systems
- Ansible playbook generation based on scan results

## [2.0.0] - 2025-11-27

### Added
- Complete rewrite with modular architecture
- `--dry-run` flag to preview sudo commands without execution
- `--section NAME` flag to run individual scan sections
- `--json-only` flag for automation and AI agent consumption
- cgroups v1 vs v2 detection (critical for container compatibility)
- User namespace support detection (rootless containers)
- Seccomp availability check
- systemd-resolved vs traditional DNS detection
- Corporate CA certificate detection in `/usr/local/share/ca-certificates/`
- Git credential helper and SSH key detection
- Kubernetes config and context enumeration
- Cloud provider credential existence checks (AWS, Azure, GCP, Alibaba, Oracle)
- Cloud endpoint connectivity tests (AWS, Azure, GCP, IONOS, Stackit, Delos, Alibaba, Oracle)
- IDE configuration detection (VS Code, Cursor)
- Known TLS interception vendor detection (ZScaler, Palo Alto, Fortinet, etc.)
- Comprehensive developer tools inventory with version detection
- Structured JSON output with proper escaping
- Timeout protection on all network operations
- Warning and error collection with summary reporting
- Clear separation of "self-service actions" vs "IT requests needed"
- Critical dependency check (jq) at startup for reliable JSON parsing.
- Sequential read I/O performance testing to complement write speed.

### Changed
- Renamed script to `vm_env_scanner.sh` (dropped `_v2` suffix)
- All scan functions now modular and independently callable
- JSON output now properly built from collected data (was hardcoded skeleton)
- Improved PEP 668 detection (checks `EXTERNALLY-MANAGED` file properly)
- Better proxy environment variable detection (checks both lowercase and uppercase)
- More informative TLS test output with issuer organization

### Fixed
- `log -e` not interpreting escape sequences (was using printf incorrectly)
- `USER` variable shadowing built-in (renamed to `CURRENT_USER`)
- PEP 668 check was grepping filename instead of file contents
- JSON data collected via `jadd` was never used in final output
- Removed dead code (`safe_cmd` function)
- Proper cleanup of temporary directory on exit

### Security
- Script remains strictly observational (no system modifications)
- Added explicit documentation about security philosophy
- Dry-run mode allows verification before any sudo execution

## [1.0.0] - 2025-01-14

### Added
- Initial version created as proof-of-concept
- Basic system information gathering
- APT, Snap, pip package manager detection
- Network interface and proxy detection
- TLS certificate chain inspection
- Docker presence check
- UFW/iptables/nftables status
- AppArmor and SELinux detection
- Basic developer tool inventory
- Human-readable text report output
- Skeleton JSON output

### Known Issues (Fixed in 2.0.0)
- `log -e` escape sequences not working
- Variable shadowing with `USER`
- JSON output incomplete
- No timeout on network operations
- PEP 668 detection unreliable

---

## Version History Summary

| Version | Date | Highlights |
|---------|------|------------|
| 2.0.0 | 2025-11-27 | Complete rewrite, modular architecture, AI-ready JSON |
| 1.0.0 | 2025-11-25 | Initial proof-of-concept |

## Upgrade Guide

### From 1.0.0 to 2.0.0

The script has been completely rewritten. Key changes:

1. **Filename changed**: `vm_env_scanner_v2.sh` → `vm_env_scanner.sh`
2. **JSON output format changed**: If you have scripts parsing the JSON, review the new structure
3. **New command-line options**: `--dry-run`, `--section`, `--json-only` now available
4. **Report location unchanged**: Still outputs to `~/vm_env_scan_report.txt` and `~/vm_env_scan_report.json`

No configuration migration needed—the script has no persistent configuration.