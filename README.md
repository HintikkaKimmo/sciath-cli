# sciath-cli

[![PyPI](https://img.shields.io/pypi/v/sciath-cli)](https://pypi.org/project/sciath-cli/)
[![Python](https://img.shields.io/pypi/pyversions/sciath-cli)](https://pypi.org/project/sciath-cli/)

Command-line interface for [Sciath](https://sciath.io) — CRA compliance automation for embedded Linux.

## Install

```bash
pip install sciath-cli
```

For development (from this repo):

```bash
pip install -e sciath-cli/
```

---

## Quickstart

### 1. Log in

```bash
sciath login https://your-sciath-instance.example.com
```

Follow the device-code prompt. Your API key is saved to `~/.sciath/config.json`.

### 2. Create a project

```bash
sciath project create --name "i.MX8M Plus Gateway" --customer-id <customer-id>
```

Note the **project ID** from the output.

### 3. Run a scan

```bash
sciath scan run \
  --project <project-id> \
  --sbom sciath-cli/tests/fixtures/demo-imx8.bom.json \
  --version-label "kirkstone-5.15.32-1.0.0"
```

Note the **scan ID** from the output.

### 4. Triage in the UI

Open the web UI and review the vulnerability assessments. Mark each finding as
`affected`, `not_affected`, `fixed`, or `under_investigation`.

Or triage from the CLI:

```bash
sciath assess list --scan <scan-id>
sciath assess update <assessment-id> --status not_affected \
  --justification "CONFIG_BPF_SYSCALL=n — subsystem compiled out"
```

### 5. Download a compliance report

```bash
# Article 13 Technical File (PDF)
sciath report <scan-id> --format pdf --output my-report.pdf

# CycloneDX VEX (JSON)
sciath report <scan-id> --format vex --output vex.json

# CSAF VEX (JSON)
sciath report <scan-id> --format csaf --output csaf.json
```

### 6. Done

Your PDF is ready for submission to a notified body or for your internal CRA file.

---

## Sample SBOM (test without your real firmware)

Save this as `demo.bom.json` and pass it to `sciath scan run --sbom demo.bom.json`:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "version": 1,
  "metadata": {
    "component": {
      "type": "firmware",
      "name": "imx8m-gateway",
      "version": "kirkstone-5.15.32-1.0.0"
    }
  },
  "components": [
    {
      "type": "library",
      "name": "linux-kernel",
      "version": "5.15.32",
      "cpe": "cpe:2.3:o:linux:linux_kernel:5.15.32:*:*:*:*:*:*:*",
      "purl": "pkg:generic/linux-kernel@5.15.32"
    },
    {
      "type": "library",
      "name": "openssl",
      "version": "3.0.7",
      "cpe": "cpe:2.3:a:openssl:openssl:3.0.7:*:*:*:*:*:*:*",
      "purl": "pkg:generic/openssl@3.0.7"
    },
    {
      "type": "application",
      "name": "busybox",
      "version": "1.35.0",
      "cpe": "cpe:2.3:a:busybox:busybox:1.35.0:*:*:*:*:*:*:*",
      "purl": "pkg:generic/busybox@1.35.0"
    }
  ]
}
```

---

## Command reference

| Command | Description |
|---------|-------------|
| `sciath login <url>` | Authenticate via device-code flow |
| `sciath project list` | List projects for your customer |
| `sciath project create` | Create a new product/project |
| `sciath scan run` | Upload an SBOM and trigger analysis |
| `sciath scan status <id>` | Check scan progress |
| `sciath assess list` | List vulnerability assessments for a scan |
| `sciath assess update <id>` | Set VEX status and justification |
| `sciath report <scan-id>` | Generate and download a compliance report |

---

## Report formats

| Flag | Format | Use case |
|------|--------|----------|
| `--format pdf` | Article 13 Technical File (PDF/A) | Regulatory submission, internal audit |
| `--format vex` | CycloneDX VEX (JSON) | Supply chain tooling, SBOM viewers |
| `--format csaf` | CSAF VEX (JSON) | CSIRT notification, vulnerability advisories |
