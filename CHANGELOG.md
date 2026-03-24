# Changelog

All notable changes to sciath-cli will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

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
