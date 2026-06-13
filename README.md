# Credential Exposure Scanner

An OSINT-style scanner for domains and email addresses. It surfaces public evidence of credential exposure, deduplicates findings across rescans, and keeps the storage layer free from raw credential material.

## What it does

- Accepts a domain or email address as input
- Normalizes the target into a canonical form (lowercased, plus-tag stripped for emails)
- Runs multiple internet-facing scanners concurrently with configurable parallelism
- Deduplicates and severity-ranks findings in a local SQLite database
- Provides both a CLI and a local web UI

## Scanners

| Scanner | Target | Auth required | Source |
|---|---|---|---|
| `crtsh` | domain | no | certificate transparency logs |
| `github_search` | domain, email | GitHub token | GitHub code search API |
| `exact_email_search` | email | GitHub token | GitHub code search API |
| `lead_fetch` | domain, email | GitHub token | GitHub code search API (credential-dense file types) |
| `dorks` | domain, email | no | DuckDuckGo HTML endpoint |
| `hibp` | email | HIBP API key (paid) | Have I Been Pwned v3 API |

Scanners that require auth are automatically skipped when credentials are absent.

## Finding model

Each finding has:

| Field | Description |
|---|---|
| `source` | Scanner name |
| `target` | `kind:value` — e.g. `email:user@example.com` |
| `kind` | Finding subtype — e.g. `exposed_aws_access_key`, `breach`, `search_hit` |
| `severity` | `info` / `low` / `medium` / `high` / `critical` |
| `title` | Human-readable summary |
| `evidence_url` | Link to the public source (when available) |
| `raw` | Sanitized metadata (no raw credential values stored) |
| `first_seen` / `last_seen` | UTC timestamps |

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
# optional test/dev tools
pip install -e .[dev]
```

Requires Python 3.11+.

## Configure

```bash
cp config.example.toml ~/.config/credscan/config.toml
chmod 600 ~/.config/credscan/config.toml   # contains API keys — keep private
```

Edit the file to add tokens and adjust limits. The config location can be
overridden with the `CREDSCAN_CONFIG_DIR` environment variable.

### Key settings (`[app]`)

| Key | Default | Description |
|---|---|---|
| `concurrency` | `5` | Max parallel scanner tasks |
| `scanner_timeout` | `120` | Seconds before a single scanner is cancelled |
| `db_path` | `~/.config/credscan/findings.db` | SQLite database path |

### Scanner tokens

- `[scanners.github_search]` / `[scanners.exact_email_search]` / `[scanners.lead_fetch]`: set `token = "ghp_..."` or export `GITHUB_TOKEN`
- `[scanners.hibp]`: set `api_key = "..."` (requires a paid HIBP subscription)

## Usage

Scan a target:

```bash
credscan scan example.com
credscan scan alice@example.com --output json
credscan scan example.com --verbose
```

Run the local web UI:

```bash
credscan serve
# or with explicit address
credscan serve --host 127.0.0.1 --port 8765
```

View recent scan history or scanner execution telemetry:

```bash
credscan history
credscan history --limit 50
credscan history --scan-id 1
```

Validate configuration and test connectivity to external APIs:

```bash
credscan doctor
```

## Repository layout

```text
src/credscan/
  __init__.py          # version + USER_AGENT
  cli.py               # typer CLI (scan / serve / history)
  config.py            # TOML config loader
  http.py              # shared GET-with-retry helper
  models.py            # Target, Finding, ScanResult, Severity
  normalize.py         # input normalization
  runner.py            # concurrent scanner orchestration
  store.py             # SQLite persistence (findings + scan history)
  web.py               # FastAPI web GUI
  scanners/
    base.py            # Scanner ABC
    registry.py        # scanner list + build_scanners()
    _github.py         # shared GitHub API helpers + SECRET_PATTERNS
    crtsh.py
    dorks.py
    exact_email_search.py
    github_search.py
    hibp.py
    lead_fetch.py
  templates/
    index.html         # single-page web UI

test_*.py              # pytest test modules (root level)
conftest.py            # shared fixtures (sleep patching)
config.example.toml    # annotated config template
pyproject.toml         # package metadata + tool config
```

## Architecture

```
User input (domain / email)
    │
    ▼
normalize()  →  Target(kind, value, domain)
    │
    ▼
build_scanners(config)  →  [Scanner, ...]
    │
    ▼
Runner (asyncio.Semaphore for concurrency, asyncio.timeout per scanner)
    ├─→ CrtShScanner
    ├─→ GitHubSearchScanner
    ├─→ ExactEmailSearchScanner
    ├─→ LeadFetchScanner
    ├─→ DorkScanner
    └─→ HIBPScanner
         │  (each yields Finding objects)
    ▼
Store.upsert()  →  SQLite (WAL mode, dedup by SHA-256 key)
    │
    ▼
ScanResult  →  CLI table / JSON / Web UI
```

## Design constraints

- No raw credential values are stored — findings record metadata (kind, severity, evidence URL) only
- Deduplication is deterministic: the same finding reported on a rescan updates `last_seen` and refreshes mutable fields without creating a duplicate row
- Scanner exceptions are isolated — one failing scanner does not cancel the rest of the scan
- Each scanner has a per-run timeout to prevent hung HTTP requests from blocking the semaphore indefinitely
- Search-engine hits (dorks) are leads, not confirmed exposures — treat them as starting points for manual review
