# Contributing to sciath-cli

Thanks for your interest in contributing to sciath-cli! This guide covers
everything you need to get started.

## Prerequisites

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) (recommended) or pip
- Git

## Setup

```bash
git clone https://github.com/HintikkaKimmo/sciath-cli.git
cd sciath-cli

# Create venv and install with dev dependencies
uv sync --extra dev

# Or with pip
pip install -e ".[dev]"
```

Verify the install:

```bash
sciath --version
pytest -v
```

## Project structure

```
sciath-cli/
├── sciath_cli/
│   ├── __init__.py          # __version__ (single source of truth)
│   ├── main.py              # Typer app + CLI entrypoint
│   ├── api.py               # HTTP client (SciathAPI class)
│   ├── config.py            # Config management (~/.sciath/)
│   ├── cache.py             # Input caching
│   ├── console.py           # Rich console instance
│   ├── output.py            # OutputFormatter (table/json/quiet)
│   ├── mcp_server.py        # MCP server for editor integration
│   └── commands/
│       ├── auth.py           # login / logout / whoami
│       ├── scan.py           # scan run / status / list
│       ├── assess.py         # assess list / approve / reject
│       ├── report.py         # report generation + download
│       ├── project.py        # project list / create / select
│       └── vex.py            # CycloneDX direct export
├── tests/
├── pyproject.toml
├── uv.lock                   # Pinned dependency lockfile
├── requirements.txt          # Pinned production deps
└── requirements-dev.txt      # Pinned dev deps (includes pip-audit)
```

## Development workflow

### Running tests

```bash
pytest -v
```

Tests use `pytest-httpx` to mock all HTTP calls — no server needed.

### Dependency management

Dependencies are declared in `pyproject.toml` and pinned in `uv.lock`.

```bash
# Add a new dependency
# 1. Edit pyproject.toml
# 2. Re-lock
uv lock

# 3. Re-export requirements files
uv export --no-hashes --no-dev -o requirements.txt
uv export --no-hashes --extra dev -o requirements-dev.txt
```

Always commit `uv.lock`, `requirements.txt`, and `requirements-dev.txt` together
when changing dependencies.

### Security audit

```bash
uv run pip-audit
```

This checks all installed packages against the OSV vulnerability database.
Run before submitting a PR that changes dependencies.

### Code style

- Follow existing patterns in the codebase
- All HTTP requests go through `SciathAPI._request()` — never call `httpx` directly
- Use `console.print()` from `sciath_cli.console` for user-facing output
- Use `typer.Exit(code)` for exit codes, not `sys.exit()`

## Making changes

### Branch naming

```
feat/<short-description>    # New features
fix/<short-description>     # Bug fixes
chore/<short-description>   # Maintenance, deps, docs
```

### Commit messages

```
feat(scan): add --custom-filter flag
fix(auth): handle expired device codes gracefully
chore(deps): update httpx to 0.28.1
```

Format: `type(scope): description` where type is `feat`, `fix`, `chore`, `docs`,
or `refactor`.

### Pull request process

1. Fork the repo and create a feature branch
2. Make your changes
3. Run `pytest -v` — all tests must pass
4. Run `uv run pip-audit` if you changed dependencies
5. Open a PR against `master`
6. Describe what changed and why in the PR body

### Adding a new command

1. Create `sciath_cli/commands/yourcommand.py`
2. Define a `typer.Typer()` app with your subcommands
3. Register it in `main.py` via `app.add_typer()`
4. Add tests in `tests/test_cli_yourcommand.py`
5. Update the Command Reference table in `README.md`

### Adding an API method

1. Add the method to `SciathAPI` in `api.py`
2. Follow the existing pattern: return `self._request(method, path, ...)`
3. Add tests using `pytest-httpx` fixtures

## Architecture notes

- **sciath-cli is a thin API client.** It has no local vulnerability database or
  analysis engine. All intelligence lives on the server.
- **Config is stored at `~/.sciath/config.json`** (chmod 600). The API key is
  obtained via device-flow OAuth and stored locally.
- **The MCP server** (`sciath mcp`) uses stdio transport for local editor
  integration. It proxies the same API methods as the CLI.

## Versioning

We use [Semantic Versioning](https://semver.org/):

- **MAJOR** — breaking CLI interface changes
- **MINOR** — new commands or flags (backward-compatible)
- **PATCH** — bug fixes

Version is defined in `sciath_cli/__init__.py` — single source of truth.

## License

By contributing, you agree that your contributions will be licensed under the
[MIT License](LICENSE).
