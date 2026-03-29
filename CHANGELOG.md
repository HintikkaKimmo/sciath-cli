# Changelog

All notable changes to sciath-cli will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **OAuth2 token support.** `sciath login` now supports OAuth2 bearer tokens with
  automatic refresh. Works alongside existing API key auth.
- **`--debug` flag.** Global `--debug` flag enables verbose logging across all commands.
  Silent exception swallows replaced with proper error logging.
- **SPDX export format.** `sciath report` and `sciath vex` now support `--format spdx`
  for SPDX 2.3 output.
- **Policy management commands.** `sciath policy list`, `sciath policy create`,
  `sciath policy delete` for managing suppression policies. New `--policy` flag on
  `sciath scan run` to attach a policy to the scan.
- **`--depgraph` flag.** `sciath scan run --depgraph` uploads bitbake dependency graph
  dot output alongside the SBOM.
- **SECURITY.md, CODEOWNERS.** Semgrep scanning and SHA-pinned GitHub Actions.
- **Sigstore signing.** Release artifacts get Sigstore signatures, SLSA provenance,
  and CycloneDX SBOM.
- **CI workflow.** GitHub Actions for linting (ruff), type checking (mypy), and tests.
  Pre-commit hooks added.

### Changed

- Strict mypy enabled — type annotations added across all modules.
- Conventional commit enforcement via pre-commit hook and CI.

### Fixed

- `sciath project create` flag parsing corrected.
- Scan ID prefix resolution now works with short prefixes.
- Error messages across all commands improved with actionable hints.

[Unreleased]: https://github.com/HintikkaKimmo/sciath-cli/compare/v0.2.0...HEAD

## [0.2.0] - 2026-03-26

### Added

- **Custom filter upload.** New `--custom-filter` / `-cf` option on `sciath scan run`
  to upload organisational CVE filter rules (JSON). Auto-detects `custom_filter.json`
  in the current directory.
- **Yocto metadata.** New `--yocto-machine`, `--yocto-distro`, and `--kernel-version`
  options on `sciath scan run` for improved build-system-aware filtering.
- **SBOM quality score.** Scan summary now shows SBOM quality score and letter grade
  (A-F) when the server provides it.
- **Assessment CVSS and EPSS columns.** `sciath assess list` now shows CVSS score,
  EPSS exploit probability, and source confidence tier alongside each finding.
- **Filter layer filtering.** New `--filter-layer` option on `sciath assess list`
  to filter by specific suppression layer (kconfig, dtb, busybox, packageconfig,
  patch, custom, build_time, deployment).
- **Remaining count.** Scan list and summary now show server-provided remaining CVE
  count alongside suppressed count.
- **Applied filter layers in explain mode.** Filter reasoning table now shows all
  layers that contributed to multi-layer assessments.
- **Enriched JSON output.** JSON mode now includes `epss_score`, `matched_sources`,
  `confidence_tier`, `applied_filter_layers`, `contextual_cvss`, and
  `sbom_quality_score` fields.

### Changed

- Assessment list displays 8 columns (was 5): CVE ID, CVSS, Status, Filter Layer,
  Confidence, EPSS, Sources, ID.
- Scan list displays 7 columns (was 6): added Remaining.
- Cache key now includes custom filter content — changing the filter invalidates
  the cache correctly.

[0.2.0]: https://github.com/HintikkaKimmo/sciath-cli/releases/tag/v0.2.0

## [0.1.0] - 2026-03-24

### Added

- Network & proxy configuration guide in README (proxy, TLS inspection, firewall allowlist)

- `sciath login` — device-flow OAuth authentication (Google, GitHub, GitLab)
- `sciath scan upload` — upload SBOM (CycloneDX, SPDX, Yocto manifest) with optional Kconfig and DTB
- `sciath scan status` — poll scan analysis progress with live progress bar
- `sciath scan list` — list scans with filtering by project
- `sciath assess list` — list vulnerability assessments with status/severity filters
- `sciath assess update` — update assessment status and justification
- `sciath report generate` — trigger Article 13 PDF, CycloneDX VEX, or CSAF VEX generation
- `sciath report download` — download generated reports via presigned URL
- `sciath vex` — direct CycloneDX VEX/SBOM export
- `sciath explain` — human-readable scan summary with noise reduction stats
- Input caching — repeat uploads skip unchanged files
- MCP server for editor integration (`sciath mcp`)
- JSON output mode (`--json`) for CI/CD pipelines
- Auto-detection of SBOM format
- Idempotent uploads via content-hash deduplication

[0.1.0]: https://github.com/HintikkaKimmo/sciath-cli/releases/tag/v0.1.0
