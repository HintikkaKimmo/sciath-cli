# sciath-cli — Claude Context

## What is this?

CLI for [Sciath](https://sciath.io) — CRA compliance automation for embedded Linux.
Talks to the Sciath API over HTTP. No server code here — the server lives at
[HintikkaKimmo/sciath](https://github.com/HintikkaKimmo/sciath).

## Tech stack

| Layer | Technology |
|-------|-----------|
| CLI framework | Typer + Rich |
| HTTP client | httpx (persistent connections, typed exceptions) |
| Config | `~/.sciath/config.json` (API URL + key) |
| Auth | Device-flow OAuth → API key stored locally |
| Build | Hatchling (PEP 517), PyInstaller for binaries |
| Tests | pytest + pytest-httpx |
| License | MIT |

## Project structure

```
sciath-cli/
├── sciath_cli/
│   ├── __init__.py          # __version__ (single source of truth)
│   ├── main.py              # Typer app + CLI entrypoint
│   ├── api.py               # HTTP client (SciathAPI class)
│   ├── config.py            # Config file management (~/.sciath/)
│   ├── cache.py             # Input caching (skip unchanged uploads)
│   ├── console.py           # Rich console helpers
│   ├── output.py            # OutputFormatter (human/JSON modes), _quality_grade()
│   ├── mcp_server.py        # MCP server for editor integration
│   ├── commands/
│   │   ├── auth.py           # sciath login / logout
│   │   ├── scan.py           # sciath scan run / status / list / cra-check
│   │   ├── assess.py         # sciath assess list / update
│   │   ├── report.py         # sciath report generate / download
│   │   ├── project.py        # sciath project list / create
│   │   ├── policy.py         # sciath policy list / create / import-vex
│   │   ├── init_cmd.py       # sciath init yocto — one-step build setup
│   │   └── vex.py            # sciath vex (direct CycloneDX export)
│   └── discovery/
│       ├── __init__.py       # auto_discover() entry point
│       ├── base.py           # ArtifactBundle dataclass, BuildSystemDiscovery ABC
│       ├── submit.py         # bundle_to_payload() — ArtifactBundle → API payload
│       ├── yocto.py          # YoctoDiscovery (fully implemented)
│       ├── bsp_ingest.py     # BSP layer ingestion orchestrator
│       ├── kernel_fork.py    # Kernel fork analysis (vendor forks, SRCREV)
│       ├── vulns_corpus.py   # vulns.git database parser
│       ├── layer_resolver.py # Static layer path resolver (no bitbake)
│       ├── fingerprint.py    # Diff fingerprinting utilities
│       ├── buildroot.py      # BuildrootDiscovery (stub)
│       ├── debian.py         # DebianDiscovery (stub)
│       ├── openwrt.py        # OpenwrtDiscovery (stub)
│       ├── packageconfig_maps/  # JSON maps: recipe → flag → CVE suppressions
│       └── data/             # Pre-built vulns database, vendor profiles
├── tests/
├── pyproject.toml
├── CHANGELOG.md
├── LICENSE                   # MIT
└── .github/workflows/
    ├── python-publish.yml    # Test/build/publish Python package on release
    └── release.yml           # Manual standalone binaries (unfinished)
```

## Commands

```bash
pip install -e ".[dev]"      # install with dev deps
pytest -v                    # run tests
python -m build              # build sdist + wheel
```

## Versioning

**Single source of truth:** `sciath_cli/__init__.py` → `__version__ = "X.Y.Z"`

Hatchling reads this via `[tool.hatch.version]` in `pyproject.toml`.
Never put version strings anywhere else.

We use [Semantic Versioning](https://semver.org/):
- **MAJOR** — breaking CLI interface changes (renamed commands, changed output format)
- **MINOR** — new commands or flags (backward-compatible)
- **PATCH** — bug fixes, performance improvements

## Release workflow

Follow [docs/RELEASING.md](docs/RELEASING.md). Publishing a GitHub Release as a
maintainer triggers `python-publish.yml`: version checks, tests and audits,
clean wheel/source installations, then PyPI Trusted Publishing using the
`pypi` environment. Version is read from `sciath_cli/__init__.py`.

Update CHANGELOG.md and pass all CI jobs before tagging. The standalone binary
workflow is manual and unfinished; it is not part of the Python release.

## Discovery module (sciath_cli/discovery/)

Bundled artifact discovery for embedded Linux build systems. Walks a build
directory, finds SBOMs, kernel configs, DTBs, PACKAGECONFIG, and BSP patches
without requiring a running BitBake environment (static analysis only).

### Auto-discover flow

```bash
# From a Yocto build directory:
sciath scan run --auto-discover --build-dir /home/build/poky/build --build-system yocto

# Or let it auto-detect the build system:
sciath scan run --auto-discover --build-dir /home/build/poky/build
```

1. `auto_discover(build_dir, build_system)` tries each registered discovery module
2. The matching module's `collect()` walks the build tree and returns an `ArtifactBundle`
3. `bundle_to_payload()` reads all artifact files and serializes them into the API format
4. PACKAGECONFIG suppressions are serialized into `custom_filter_raw` rules
5. The payload is submitted via `api.create_scan()`

### Key types

- **`ArtifactBundle`** — dataclass holding paths to all discovered artifacts
  (SBOM, kconfig, DTBs, busybox config, PACKAGECONFIG flags, metadata)
- **`BuildSystemDiscovery`** — ABC that each build system implements (`detect()` + `collect()`)
- **`bundle_to_payload()`** — converts ArtifactBundle to scan API payload dict

### BSP ingestion

The discovery module can also analyse vendor BSP layers:
- Static recipe parsing (SRC_URI, SRCREV, LINUX_VERSION)
- Vendor detection (Raspberry Pi, Toradex, NXP, PHYTEC)
- Kernel fork analysis (vendor forks vs. upstream stable)
- vulns.git database cross-referencing for version-based CVE suppression

### Init command

```bash
sciath init yocto /path/to/build   # scaffolds conf/local.conf integration
```

## API client pattern

All HTTP requests go through `SciathAPI._request()` which centralises:
- Auth header injection (`X-API-Key`)
- Typed exception hierarchy (`AuthError`, `ScopeError`, `NotFoundError`, `ValidationError`, `ServerError`, `RateLimitError`)
- Rate limit handling (HTTP 429 with `Retry-After` header support)
- Connection reuse via persistent `httpx.Client`

Commands should never call `httpx` directly — always go through `SciathAPI`.

## Output formatting

All scan display logic is consolidated in `OutputFormatter` (`output.py`):
- `_quality_grade()` — SBOM quality score to letter grade (A-F)
- `render_scan()` — dispatches to table, JSON, or quiet format
- `_render_table()` — Rich table with scan summary + optional explain mode
- Exit code logic — severity threshold, KEV gating

**There is exactly one code path for scan summary display.** Do not create
alternative display functions in command modules — use `OutputFormatter`.

## Logging

### Architecture

- Logging goes to **stderr** (stdout is reserved for command output like JSON)
- Default level: `WARNING` (silent unless something goes wrong)
- `--debug` global flag sets level to `DEBUG` (verbose diagnostics)
- Format: `%(levelname)s %(name)s: %(message)s` (no timestamps)

### Rules

- Always `logging.getLogger(__name__)`. No string literals.
- **NEVER log:** API keys, OAuth2 tokens, config file contents, SBOM data,
  request/response bodies
- Every `except` block must either re-raise OR log before continuing.
  **No silent exception swallows.** Use `logger.debug(..., exc_info=True)` at minimum.
- `DEBUG`: API requests (method + path + status), token refresh attempts,
  cache hits/misses, config load, auto-detection of files
- `WARNING`: corrupted config files, malformed API response parsing
- `ERROR`: rare — most errors surface to the user via `console.print("[red]...")`

### Testing logging

```bash
# Verify --debug shows API traffic on stderr, stdout stays clean
sciath --debug scan list 2>debug.log
sciath scan list --format json | jq .   # stdout must be valid JSON
```

## CHANGELOG and VERSION — update on every commit

**Every commit that changes functionality must update `CHANGELOG.md`.**

- Add a bullet under `## [Unreleased]` in the appropriate section (`Added`, `Changed`, `Fixed`).
- Use the same voice as existing entries: bold lead phrase, then one-sentence description.
- `VERSION` (in `sciath_cli/__init__.py`) is only bumped when cutting a release, not on every commit.

**Exceptions:** Pure docs changes, CI config tweaks, and dependency-only updates
do not need a CHANGELOG entry.

## Relationship to the server

- CLI talks to the server API at the URL stored in `~/.sciath/config.json`
- Default: `https://api.sciath.io` (prod), override with `sciath config set api_url http://localhost:8000`
- CLI does NOT import any server code — fully independent repo
- API contract is defined by the server's OpenAPI schema (`/api/openapi.json`)
