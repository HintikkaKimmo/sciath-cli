# sciath-cli

[![PyPI](https://img.shields.io/pypi/v/sciath-cli)](https://pypi.org/project/sciath-cli/)
[![Python](https://img.shields.io/pypi/pyversions/sciath-cli)](https://pypi.org/project/sciath-cli/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Command-line interface for [Sciath](https://sciath.io) — CRA compliance
automation for embedded Linux.

See [CHANGELOG.md](CHANGELOG.md) for release notes.

## Install

```bash
pip install sciath-cli
```

For development (from this repo):

```bash
pip install -e ".[dev]"
```

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
```

### 4. Review results

```bash
# Table summary (default)
sciath scan run firmware.cdx.json

# With filter reasoning (why each CVE was suppressed/flagged)
sciath scan run firmware.cdx.json --explain

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
| `sciath scan status <id>` | Check scan analysis status |
| `sciath scan list` | List recent scans |
| `sciath scan reanalyse <id>` | Re-run analysis on existing scan |

### Scan Options

| Flag | Description |
|------|-------------|
| `--kconfig, -k <path>` | Kernel .config for hardware-aware filtering |
| `--dtb, -d <path>` | Device Tree Blob for hardware filtering |
| `--version, -v <label>` | Version label (default: timestamp) |
| `--project, -p <id>` | Override active project |
| `--format, -f <fmt>` | Output: `table` (default), `json`, `quiet` |
| `--explain, -e` | Show filter reasoning per CVE |
| `--severity-threshold <level>` | Exit 1 if findings >= level (`critical`/`high`/`medium`/`low`) |
| `--fail-on-kev` | Exit 1 if any open CISA KEV finding |
| `--no-cache` | Skip local cache, force fresh upload |

### Assessments

| Command | Description |
|---------|-------------|
| `sciath assess list <scan-id>` | List vulnerability assessments |
| `sciath assess approve <id>` | Approve an assessment |
| `sciath assess reject <id>` | Reject / dispute an assessment |

### Reports & Export

| Command | Description |
|---------|-------------|
| `sciath report <scan-id>` | Generate and download a compliance report |
| `sciath vex <scan-id>` | Direct export (no report record) — faster for CI |

### Export Formats

| Format | Flag | Use Case |
|--------|------|----------|
| Article 13 PDF | `--format pdf` | Regulatory submission |
| CycloneDX VEX | `--format vex_cdx` | Supply chain tooling |
| CSAF VEX | `--format vex_csaf` | CSIRT notification |
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
