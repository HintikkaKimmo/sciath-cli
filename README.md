# sciath-cli

[![PyPI](https://img.shields.io/pypi/v/sciath-cli)](https://pypi.org/project/sciath-cli/)
[![Python](https://img.shields.io/pypi/pyversions/sciath-cli)](https://pypi.org/project/sciath-cli/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

[![Upload Python Package](https://github.com/HintikkaKimmo/sciath-cli/actions/workflows/python-publish.yml/badge.svg?branch=master)](https://github.com/HintikkaKimmo/sciath-cli/actions/workflows/python-publish.yml)

Command-line interface for [Sciath](https://sciath.io) — CRA compliance
automation for embedded Linux.

See [CHANGELOG.md](CHANGELOG.md) for release notes.

## Install

Requires Python 3.11 or newer. Scanning and reports require a Sciath account
and access to the Sciath API.

```bash
pip install sciath-cli
```

For development (from this repo):

```bash
pip install -e ".[dev]"
```

Maintainers: see [the release guide](docs/RELEASING.md) for PyPI setup and
publishing. This release provides a Python package; standalone executables
are not included.

---

## Quickstart

### 1. Log in

```bash
sciath login
```

Follow the device-code prompt in your browser. Your API key is saved to
`~/.sciath/config.json`.

### 2. Select a project

```bash
sciath project list
sciath project select "IoT Gateway v3"
```

### 3. Run a scan

```bash
# Auto-detect: finds sbom.json, .config, *.dts in current directory
sciath scan

# Or specify everything explicitly
sciath scan run firmware.cdx.json \
  --kconfig .config \
  --dtb device.dts \
  --version v3.2.0

# Auto-discover from a Yocto build directory (finds all artifacts automatically)
sciath scan run --auto-discover --build-dir /home/build/poky/build

# With build system hint
sciath scan run --auto-discover --build-dir /home/build/poky/build --build-system yocto
```

### 4. Review results

```bash
# Table summary with suppression waterfall (default)
sciath scan run firmware.cdx.json

# With filter reasoning (why each CVE was suppressed/flagged)
sciath scan run firmware.cdx.json --explain

# CRA readiness check
sciath scan run firmware.cdx.json --cra-check

# JSON for scripting / LLM agents
sciath scan run firmware.cdx.json --format json | jq '.summary'
```

### 5. CI pipeline gating

```bash
# Exit 1 if any critical CVE is open
sciath scan run firmware.cdx.json \
  --severity-threshold critical \
  --format quiet

# Exit 1 if any CISA KEV entry is open
sciath scan run firmware.cdx.json \
  --fail-on-kev \
  --format quiet

# Exit 1 if not CRA-shippable
sciath scan cra-check <scan-id>
```

### 6. Export reports

```bash
# Article 13 Technical File (PDF)
sciath report <scan-id> --format pdf --output report.pdf

# CycloneDX VEX (JSON)
sciath vex <scan-id> --format vex_cdx --output vex.json

# SARIF 2.1.0 (GitHub Code Scanning compatible)
sciath vex <scan-id> --format sarif --output findings.sarif.json

# CSAF VEX (JSON)
sciath vex <scan-id> --format vex_csaf --output csaf.json
```

---

## Command Reference

### Authentication

| Command | Description |
|---------|-------------|
| `sciath login` | Authenticate via device-code flow |
| `sciath logout` | Clear stored credentials |
| `sciath whoami` | Show current user, customer, active project |

### Projects

| Command | Description |
|---------|-------------|
| `sciath project list` | List projects for your customer |
| `sciath project create <name>` | Create a new product/project |
| `sciath project select <name>` | Set the active project |
| `sciath project info` | Show active project details |

### Scanning

| Command | Description |
|---------|-------------|
| `sciath scan` | Auto-detect SBOM and scan (zero-config) |
| `sciath scan run <sbom>` | Upload SBOM and trigger analysis |
| `sciath scan run --auto-discover` | Discover all artifacts from build directory |
| `sciath scan status <id>` | Check scan analysis status |
| `sciath scan list` | List recent scans |
| `sciath scan reanalyse <id>` | Re-run analysis on existing scan |
| `sciath scan cra-check <id>` | CRA readiness verdict (exits 1 if not shippable) |

### Scan Options

| Flag | Description |
|------|-------------|
| `--kconfig, -k <path>` | Kernel .config for hardware-aware filtering |
| `--dtb, -d <path>` | Device Tree Blob for hardware filtering |
| `--depgraph <path>` | Bitbake dependency graph (dot format) |
| `--custom-filter, -cf <path>` | Custom filter rules (JSON) |
| `--version, -v <label>` | Version label (default: timestamp) |
| `--project, -p <id>` | Override active project |
| `--format, -f <fmt>` | Output: `table` (default), `json`, `quiet` |
| `--explain, -e` | Show filter reasoning per CVE |
| `--severity-threshold <level>` | Exit 1 if findings >= level (`critical`/`high`/`medium`/`low`) |
| `--fail-on-kev` | Exit 1 if any open CISA KEV finding |
| `--cra-check` | Show CRA readiness verdict after scan |
| `--policy <name>` | Apply a named filter policy to the scan |
| `--no-cache` | Skip local cache, force fresh upload |
| `--auto-discover` | Auto-discover artifacts from build directory |
| `--build-dir <path>` | Build directory for `--auto-discover` (default: cwd) |
| `--build-system <name>` | Build system hint: `yocto`, `buildroot`, `debian`, `openwrt` |

### Build Setup

| Command | Description |
|---------|-------------|
| `sciath init yocto <build-dir>` | Scaffold Sciath integration into a Yocto build |

### Assessments

| Command | Description |
|---------|-------------|
| `sciath assess list <scan-id>` | List vulnerability assessments |
| `sciath assess approve <id>` | Approve an assessment |
| `sciath assess reject <id>` | Reject / dispute an assessment |

### Policies

| Command | Description |
|---------|-------------|
| `sciath policy list` | List filter policies |
| `sciath policy show <id>` | Show policy details and rules |
| `sciath policy create <name>` | Create a new filter policy |
| `sciath policy delete <id>` | Delete a policy |
| `sciath policy history <id>` | View policy change history |
| `sciath policy import-vex <file>` | Import rules from a VEX document |

### Reports & Export

| Command | Description |
|---------|-------------|
| `sciath report <scan-id>` | Generate and download a compliance report |
| `sciath vex <scan-id>` | Direct export (no report record) — faster for CI |

### Export Formats

| Format | Flag | Use Case |
|--------|------|----------|
| Article 13 PDF | `--format pdf` | Regulatory submission |
| CRA Evidence Pack | `--format evidence-pack` | Full audit ZIP (SBOM + VEX + PDF + CSV) |
| CycloneDX VEX | `--format vex_cdx` | Supply chain tooling |
| CSAF VEX | `--format vex_csaf` | CSIRT notification |
| SPDX 2.3 | `--format spdx` | SPDX ecosystem tooling |
| SARIF 2.1.0 | `--format sarif` | GitHub Code Scanning, VS Code |
| CycloneDX SBOM | `--format sbom_cdx` | SBOM-only export |
| Combined SBOM+VEX | `--format sbom_vex_cdx` | Full disclosure |

### MCP Server (Editor Integration)

```bash
sciath mcp
```

Starts an MCP server with stdio transport for integration with Claude Code,
Cursor, Windsurf, and other MCP-aware editors.

**Available tools:**

- `scan_sbom` — Upload and analyse an SBOM
- `get_scan_status` — Check scan status
- `list_findings` — List CVE findings with filter reasoning
- `get_compliance_status` — CRA readiness summary

**Claude Code configuration** (`~/.claude/settings.json`):

```json
{
  "mcpServers": {
    "sciath": {
      "command": "sciath",
      "args": ["mcp"]
    }
  }
}
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success (or findings below threshold) |
| 1 | Findings above threshold, KEV found, or error |
| 2 | Tool error (reserved) |

---

## Auto-Detection

When you run `sciath scan` without specifying files, the CLI searches
the current directory for:

**SBOM files** (first match used):

- `sbom.json`, `bom.json`, `sbom.xml`, `bom.xml`
- `sbom.cdx.json`, `sbom.spdx.json`
- `build/tmp/deploy/*/sbom-*.json` (Yocto builds)

**Kconfig** (auto-detected if present):

- `.config`, `build/.config`

**Device Tree** (auto-detected if present):

- `*.dts`, `*.dtb` in current directory

### Build Directory Discovery (`--auto-discover`)

For Yocto and other build systems, `--auto-discover` walks the entire
build tree and extracts all available artifacts automatically:

- **SBOM** from `tmp/deploy/spdx/`, `tmp/deploy/cve/`, or CycloneDX output
- **Kernel .config** from staging or work directories
- **DTBs** from `tmp/deploy/images/` (capped at 20 by default)
- **Busybox .config** from busybox work directory
- **PACKAGECONFIG** flags per recipe (with CVE suppression mapping)
- **BSP patches** from vendor layers (static analysis, no BitBake required)

PACKAGECONFIG suppressions are serialized into custom filter rules and
submitted alongside the scan. This enables the suppression waterfall to
show exactly which CVEs are eliminated by build configuration.

---

## CRA Compliance

### Evidence Pack

Download everything an auditor needs in one command:

```bash
sciath report <scan-id> --format evidence-pack
```

The ZIP contains: SBOM, VEX document, Article 13 PDF, suppression
rationale CSV, CRA readiness verdict, and scan metadata.

### Readiness Check

```bash
sciath scan cra-check <scan-id>
```

Returns SHIPPABLE or NOT READY with article-mapped checklist,
compliance percentage, and blockers. Exits 1 if not shippable
(useful for CI gating).

---

## Input Caching

The CLI caches scan results locally at `~/.sciath/cache/`. If you run
the same scan with identical inputs (same SBOM + kconfig + DTB content),
the CLI returns the cached result without re-uploading.

- Cache TTL: 1 hour
- Force fresh: `--no-cache`
- Cache key: SHA-256 of project ID + file contents

---

## Configuration

Credentials stored at `~/.sciath/config.json` (mode 0600).

**Environment variable overrides:**

| Variable | Description |
|----------|-------------|
| `SCIATH_API_URL` | Override API URL (highest precedence) |

---

## Network & Proxy Configuration

The CLI needs outbound HTTPS access to the Sciath API. If your
environment uses a corporate proxy or firewall allowlisting, see below.

### Firewall allowlist

Allow outbound HTTPS (port 443) to:

| Domain | Purpose |
|--------|---------|
| `api.sciath.io` | API requests |
| `sciath.io` | Device-code login flow |

> **Note:** Sciath is hosted behind a load balancer without static IPs.
> Use domain-based (FQDN) rules, not IP-based rules.

### HTTP/HTTPS proxy

The CLI uses [httpx](https://www.python-httpx.org/) which respects
standard proxy environment variables:

```bash
export HTTPS_PROXY=http://proxy.corp.example:8080

# With authentication
export HTTPS_PROXY=http://user:password@proxy.corp.example:8080
```

### Custom TLS certificates

If your proxy performs TLS inspection (MITM), you need to trust its
CA certificate:

```bash
export SSL_CERT_FILE=/path/to/corporate-ca-bundle.crt
```

`REQUESTS_CA_BUNDLE` and `CURL_CA_BUNDLE` are also supported.

### Private / on-prem API endpoint

If you run a self-hosted Sciath instance, point the CLI at it:

```bash
# Persistent (saved to ~/.sciath/config.json)
sciath config set api_url https://sciath.internal.example.com

# Or per-session via environment variable
export SCIATH_API_URL=https://sciath.internal.example.com
```

---

## Sample SBOM

Save as `sbom.json` and run `sciath scan`:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "metadata": {
    "component": {
      "type": "firmware",
      "name": "imx8m-gateway",
      "version": "v3.2.0"
    }
  },
  "components": [
    {
      "type": "library",
      "name": "linux-kernel",
      "version": "5.15.32",
      "cpe": "cpe:2.3:o:linux:linux_kernel:5.15.32:*:*:*:*:*:*:*"
    },
    {
      "type": "library",
      "name": "openssl",
      "version": "3.0.7",
      "cpe": "cpe:2.3:a:openssl:openssl:3.0.7:*:*:*:*:*:*:*"
    },
    {
      "type": "application",
      "name": "busybox",
      "version": "1.35.0",
      "cpe": "cpe:2.3:a:busybox:busybox:1.35.0:*:*:*:*:*:*:*"
    }
  ]
}
```
