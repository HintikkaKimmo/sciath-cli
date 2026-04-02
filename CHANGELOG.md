# Changelog

All notable changes to sciath-cli will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **Suppression funnel waterfall.** Scan results now display a per-layer
  suppression waterfall showing CVE count at each filter stage (build-time →
  Kconfig → DTB → PACKAGECONFIG → busybox → patch → custom → deployment).
  Renders in both table format (terminal) and JSON output. Skipped layers
  show why they were skipped.

- **Per-CVE suppression rationale in `--explain` mode.** The explain table now
  shows artifact-specific rationale for each suppressed CVE (e.g.
  `CONFIG_BT=n — subsystem not compiled (.config)`) instead of generic
  justification categories. JSON output includes `suppression_rationale` per
  assessment.

- **"Why it matters" for surviving CVEs.** `--explain` mode now shows a
  "WHY THESE CVEs MATTER" section for unsuppressed findings, sorted by
  severity (KEV first, then CVSS descending). Shows CVSS, EPSS, KEV flags,
  and survival rationale explaining why each CVE passed through filters.

- **CRA Evidence Pack download.** `sciath report <scan-id> --format evidence-pack`
  downloads a ZIP containing SBOM, VEX, Article 13 PDF, suppression rationale
  CSV, CRA readiness verdict, and scan metadata. One command for everything
  an auditor needs.

- **CRA readiness check.** New `sciath scan cra-check <scan-id>` command
  shows a single CRA readiness verdict (SHIPPABLE / NOT READY) with
  article-mapped checklist, compliance percentage, and blockers. Also
  available as `--cra-check` flag on `sciath scan run`. Exits 1 if not
  shippable (useful for CI gating). Supports table, json, quiet formats.


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

- **Deduplicated scan display** — consolidated `_quality_grade()` and scan summary rendering into `OutputFormatter` (single source of truth)
- **HTTP 429 handling** — API client now raises `RateLimitError` with retry-after information
- **Expanded test coverage** — added `test_output_formatter.py` (quality grade boundaries, JSON/quiet format, exit code logic) and `test_api_client.py` 429 tests
- **Updated CLAUDE.md** — documented consolidated `OutputFormatter` as single display path, added `RateLimitError` to exception list, added `policy.py` to project structure
- **Updated README.md** — added missing policy command reference (6 commands), added `--policy` scan flag
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
