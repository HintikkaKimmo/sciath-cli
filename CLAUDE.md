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
│   ├── output.py            # OutputFormatter (human/JSON modes)
│   ├── mcp_server.py        # MCP server for editor integration
│   └── commands/
│       ├── auth.py           # sciath login / logout
│       ├── scan.py           # sciath scan upload / status / list
│       ├── assess.py         # sciath assess list / update
│       ├── report.py         # sciath report generate / download
│       ├── project.py        # sciath project list / create
│       └── vex.py            # sciath vex (direct CycloneDX export)
├── tests/
├── pyproject.toml
├── CHANGELOG.md
├── LICENSE                   # MIT
└── .github/workflows/
    └── release.yml           # Build binaries + GitHub Release on tag push
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

### Steps to release a new version

1. **Bump version** in `sciath_cli/__init__.py`:
   ```python
   __version__ = "0.2.0"
   ```

2. **Update CHANGELOG.md** — add a new section at the top:
   ```markdown
   ## [0.2.0] - YYYY-MM-DD

   ### Added
   - New feature description

   ### Fixed
   - Bug fix description

   [0.2.0]: https://github.com/HintikkaKimmo/sciath-cli/releases/tag/v0.2.0
   ```

3. **Commit and tag:**
   ```bash
   git add sciath_cli/__init__.py CHANGELOG.md
   git commit -m "release: v0.2.0"
   git tag v0.2.0
   git push origin master --tags
   ```

4. **GitHub Actions** (automatic on tag push):
   - Runs tests
   - Builds PyInstaller binaries (linux x86_64/aarch64, macOS arm64/x86_64)
   - Creates GitHub Release with binaries + checksums

5. **Publish to PyPI** (manual for now):
   ```bash
   python -m build
   twine upload dist/sciath_cli-0.2.0*
   ```

### What NOT to do

- Don't edit version in `pyproject.toml` — it's read from `__init__.py` automatically
- Don't create a release without updating CHANGELOG.md
- Don't push a tag without running tests first (`pytest -v`)

## API client pattern

All HTTP requests go through `SciathAPI._request()` which centralises:
- Auth header injection (`X-API-Key`)
- Typed exception hierarchy (`AuthError`, `ScopeError`, `NotFoundError`, `ValidationError`, `ServerError`)
- Connection reuse via persistent `httpx.Client`

Commands should never call `httpx` directly — always go through `SciathAPI`.

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
