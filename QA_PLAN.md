# Sciath CLI — QA Test Plan

Cross-environment testing for the CLI across all supported modes, outputs,
and integration points.

## Environments Matrix

| # | Environment | Python | Install Method | Auth | Network |
|---|-------------|--------|----------------|------|---------|
| 1 | macOS terminal (dev) | 3.11+ | pip install -e | device flow | localhost:8000 |
| 2 | Linux terminal | 3.11+ | pip install | API key | production |
| 3 | Docker container | 3.12 | pip install | API key env | production |
| 4 | GitHub Actions | 3.12 | pip install | secret | production |
| 5 | GitLab CI | 3.12 | pip install | variable | production |
| 6 | PyInstaller binary | bundled | standalone | device flow | production |
| 7 | MCP (Claude Code) | host | pip install | stored key | production |
| 8 | MCP (Cursor) | host | pip install | stored key | production |
| 9 | Piped output | any | any | any | any |

## Test Scenarios

### A. Core Scan Flow (run in every environment)

```bash
# A1. Basic scan with auto-detection
cd /path/to/firmware-project
sciath scan
# Expected: auto-detects sbom.json, runs analysis, shows table summary

# A2. Explicit scan with all artifacts
sciath scan run firmware.cdx.json \
  --kconfig .config \
  --dtb device.dts \
  --version v2.4.1

# A3. JSON output (verify parseable by jq)
sciath scan run firmware.cdx.json --format json | jq '.summary'
# Expected: prints summary string, exit 0

# A4. Quiet mode for CI
sciath scan run firmware.cdx.json --format quiet
echo "Exit code: $?"
# Expected: no output, exit 0 or 1

# A5. SARIF export
sciath vex <scan-id> --format sarif --output findings.sarif.json
# Expected: valid SARIF 2.1.0 file
```

### B. Exit Code Policy (CI pipeline gating)

```bash
# B1. Severity threshold — no critical findings
sciath scan run firmware.cdx.json --severity-threshold critical --format quiet
echo "Exit: $?"
# Expected: exit 0 if no critical open CVEs, exit 1 if any

# B2. KEV gating
sciath scan run firmware.cdx.json --fail-on-kev --format quiet
echo "Exit: $?"
# Expected: exit 1 if open KEV finding exists

# B3. Combined threshold + KEV
sciath scan run firmware.cdx.json \
  --severity-threshold high \
  --fail-on-kev \
  --format quiet
```

### C. Explain Mode

```bash
# C1. Table with filter reasoning
sciath scan run firmware.cdx.json --explain
# Expected: SCAN SUMMARY table + FILTER REASONING table showing
#           CVE ID, layer, status, justification for each filtered CVE

# C2. JSON with reasoning
sciath scan run firmware.cdx.json --format json --explain | jq '.assessments[0]'
# Expected: each assessment includes filter_layer, justification, confidence
```

### D. Auto-Detection

```bash
# D1. SBOM auto-detect (sbom.json in cwd)
cp firmware.cdx.json sbom.json
sciath scan
# Expected: "Auto-detected SBOM: sbom.json"

# D2. Yocto build directory
mkdir -p build/tmp/deploy/images
cp firmware.manifest build/tmp/deploy/images/sbom-core.json
sciath scan
# Expected: "Auto-detected SBOM: build/tmp/deploy/images/sbom-core.json"

# D3. No SBOM found
cd /tmp/empty-dir
sciath scan
# Expected: "No SBOM file found. Checked: ..." with helpful list

# D4. Kconfig auto-detect
echo "CONFIG_BT=n" > .config
sciath scan run firmware.cdx.json
# Expected: "Auto-detected: .config"

# D5. Multiple SBOMs found
cp firmware.cdx.json sbom.json
cp firmware.cdx.json bom.json
sciath scan
# Expected: uses first (sbom.json), no warning for named files
```

### E. Input Caching

```bash
# E1. First run — uploads
sciath scan run firmware.cdx.json --version v1.0
# Expected: uploads, analyses, shows result

# E2. Same inputs — cache hit
sciath scan run firmware.cdx.json --version v1.0
# Expected: "Cache hit — using previous scan result" (no upload)

# E3. Force fresh
sciath scan run firmware.cdx.json --version v1.0 --no-cache
# Expected: uploads fresh (no cache message)

# E4. Cache TTL expiry
# Wait >1 hour, then:
sciath scan run firmware.cdx.json --version v1.0
# Expected: cache expired, uploads fresh

# E5. Modified SBOM — cache miss
echo '{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"name":"new"}]}' > firmware.cdx.json
sciath scan run firmware.cdx.json --version v1.0
# Expected: different hash, uploads fresh
```

### F. SARIF Integration

```bash
# F1. Generate SARIF
sciath vex <scan-id> --format sarif --output findings.sarif.json

# F2. Validate SARIF structure
cat findings.sarif.json | jq '.version'
# Expected: "2.1.0"

cat findings.sarif.json | jq '.runs[0].tool.driver.name'
# Expected: "Sciath"

cat findings.sarif.json | jq '.runs[0].results | length'
# Expected: number of assessments

# F3. GitHub Code Scanning upload (GitHub Actions only)
# In .github/workflows/security.yml:
#   - name: Upload SARIF
#     uses: github/codeql-action/upload-sarif@v3
#     with:
#       sarif_file: findings.sarif.json

# F4. SARIF properties bag
cat findings.sarif.json | jq '.runs[0].results[0].properties'
# Expected: sciath_status, filter_layer, justification_text, confidence
```

### G. MCP Server

```bash
# G1. Server starts
sciath mcp
# Expected: stdio transport starts, no output to stderr

# G2. Claude Code integration test
# In Claude Code settings, add:
# {
#   "mcpServers": {
#     "sciath": {
#       "command": "sciath",
#       "args": ["mcp"]
#     }
#   }
# }
# Then in Claude Code: "check my sbom.json for critical CVEs"
# Expected: agent calls scan_sbom tool, returns findings

# G3. Tool: scan_sbom
# Send MCP tool call:
# {"name": "scan_sbom", "arguments": {"sbom_path": "firmware.cdx.json", "project_id": "..."}}
# Expected: JSON response with scan_id, status, total_vulnerabilities

# G4. Tool: list_findings
# {"name": "list_findings", "arguments": {"scan_id": "..."}}
# Expected: JSON with findings array including cve_id, cvss, status

# G5. Tool: get_compliance_status
# {"name": "get_compliance_status", "arguments": {"project_id": "..."}}
# Expected: JSON with total_cves, suppressed, remaining, noise_reduction_pct

# G6. Unauthenticated MCP
# Clear ~/.sciath/config.json, then start MCP
# Send any tool call
# Expected: "Error: Not authenticated. Run 'sciath login' first."
```

### H. Piped Output Verification

```bash
# H1. No ANSI codes in piped JSON
sciath scan run firmware.cdx.json --format json | cat -v | grep -c '\[' || echo "Clean"
# Expected: no ANSI escape sequences

# H2. JSON parseable
sciath scan run firmware.cdx.json --format json | python -m json.tool > /dev/null
# Expected: exit 0 (valid JSON)

# H3. Pipe to jq
sciath scan run firmware.cdx.json --format json | jq -r '.summary'
# Expected: human-readable summary string

# H4. SARIF to file
sciath vex <scan-id> --format sarif | python -m json.tool > /dev/null
# Expected: exit 0 (valid JSON)
```

### I. Error Handling

```bash
# I1. Invalid API URL
SCIATH_API_URL=http://invalid:9999 sciath scan run firmware.cdx.json
# Expected: "Connection failed: ..." (clear error, not stack trace)

# I2. Expired API key
# Revoke key in web UI, then:
sciath scan run firmware.cdx.json
# Expected: "Not authenticated — run sciath login"

# I3. Non-existent project
sciath scan run firmware.cdx.json --project nonexistent-uuid
# Expected: "Resource not found" or "Not found"

# I4. Invalid SBOM content
echo "not json" > bad.txt
sciath scan run bad.txt
# Expected: "Validation error" from API (clear message)

# I5. Server down
SCIATH_API_URL=http://localhost:1 sciath scan run firmware.cdx.json
# Expected: "Connection failed" (not stack trace)
```

### J. Docker / CI Environment

```dockerfile
# J1. Dockerfile test
FROM python:3.12-slim
RUN pip install sciath-cli
ENV SCIATH_API_URL=https://api.sciath.io
ENV SCIATH_API_KEY=sk_test_...
RUN sciath scan run /data/firmware.cdx.json --format json --severity-threshold critical
```

```yaml
# J2. GitHub Actions test
name: Firmware Security Scan
on: push
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install sciath-cli
      - name: Run scan
        env:
          SCIATH_API_URL: ${{ secrets.SCIATH_API_URL }}
        run: |
          sciath login --api-key ${{ secrets.SCIATH_API_KEY }}
          sciath scan run firmware.cdx.json \
            --format sarif \
            --severity-threshold high \
            --fail-on-kev \
            --output results.sarif.json
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif.json
```

## Test Data Requirements

| Item | Source | Notes |
|------|--------|-------|
| CycloneDX SBOM (small) | i.MX8 demo fixture | ~50 components |
| CycloneDX SBOM (large) | Real Yocto build | ~500 components |
| SPDX SBOM | Converted from CDX | Format detection test |
| Yocto manifest | Real build output | .manifest format |
| Kernel .config | i.MX8 defconfig | Kconfig filtering test |
| Device tree | i.MX8 .dts | DTB filtering test |
| Custom filter JSON | Test fixture | Custom suppression test |

## Pass Criteria

- All exit codes match expected values
- No ANSI codes in piped output
- JSON output parseable by `jq` and `python -m json.tool`
- SARIF accepted by GitHub Code Scanning upload action
- MCP server responds to all 4 tool calls
- Cache correctly skips re-upload on identical inputs
- Auto-detection finds files in all documented locations
- Error messages are human-readable (no stack traces in production mode)
- PyInstaller binary behaves identically to pip install

## Regression Checklist (run before every release)

- [ ] `sciath scan run <sbom>` (basic flow)
- [ ] `sciath scan` (auto-detection)
- [ ] `--format json | jq .summary` (parseable)
- [ ] `--format quiet` + `echo $?` (exit code only)
- [ ] `--severity-threshold critical` (gating)
- [ ] `--explain` (filter reasoning)
- [ ] `sciath vex <id> --format sarif` (SARIF export)
- [ ] `sciath mcp` starts without error
- [ ] Cache hit on repeated inputs
- [ ] `--no-cache` forces fresh
- [ ] Piped output has no ANSI
- [ ] Invalid API URL shows clear error
