# credscan

Self-hosted credential exposure scanner. Input an email or domain you own; credscan queries free OSINT sources for leaks, exposed secrets, and subdomain sprawl, then stores findings in a local SQLite database.

**Status**: alpha. Free scanners are functional; paid sources (HIBP) are stubbed behind a config flag and activate automatically when you add an API key.

## What it scans for

| Scanner | What it finds | Cost | Auth |
|---|---|---|---|
| `crtsh` | Subdomains from certificate transparency logs | Free | None |
| `github_search` | Secrets (AWS/GitHub/Slack/OpenAI keys, private keys, password literals) in public code that mentions your domain | Free | GitHub PAT |
| `dorks` | Pastebin, gist, exposed `.env` and log files matching your domain | Free | None |
| `hibp` | Breached accounts | $3.50/mo | HIBP API key |

Add a GitHub PAT (the cheapest and most valuable addition) by exporting `GITHUB_TOKEN` or adding it to the config file.

## Install

```bash
git clone https://github.com/yourname/credscan.git
cd credscan
pip install -e ".[dev]"
```

Requires Python 3.11+.

## Usage

### CLI

```bash
# Scan a domain
credscan scan example.com

# Scan an email
credscan scan user@example.com

# JSON output (pipeable)
credscan scan example.com --output json

# Scan history
credscan history
```

### Web GUI

```bash
credscan serve
# then open http://127.0.0.1:8765
```

The GUI shows which scanners are enabled, accepts domain or email input, runs the scan, and displays findings sorted by severity. Scan history is persisted across restarts.

## Configuration

Default config path: `~/.config/credscan/config.toml` (override with `CREDSCAN_CONFIG_DIR`).

```toml
[scanners.github_search]
token = "ghp_your_token_here"

[scanners.hibp]
api_key = "your_hibp_key"
```

Alternatively, set `GITHUB_TOKEN` in the environment.

The findings database lives at `~/.config/credscan/findings.db` by default. Override with `--db`.

## Adding a scanner

1. Subclass `Scanner` in `src/credscan/scanners/your_scanner.py`
2. Implement `supports(target)` and `scan(target)` (async generator yielding `Finding` objects)
3. Register it in `cli.py` and `web.py` `build_scanners()`

Minimal example:

```python
from credscan.scanners.base import Scanner
from credscan.models import Finding, Severity, Target, TargetKind

class MySource(Scanner):
    name = "mysource"

    def supports(self, target: Target) -> bool:
        return target.kind == TargetKind.DOMAIN

    async def scan(self, target: Target):
        # query your source, yield Finding objects
        yield Finding(
            source=self.name,
            target=str(target),
            kind="example",
            severity=Severity.MEDIUM,
            title="Example finding",
            evidence_url="https://...",
        )
```

## Architecture

```
[CLI / Web UI]
      ↓
  [Normalize] → Target(kind, value, domain)
      ↓
   [Runner] ──→ applicable scanners run concurrently
      ↓
   [Store]  ──→ SQLite with content-hash dedup
      ↓
  [Report: rich table | JSON | HTML page]
```

Scanners are independent. Each runs in its own task with a shared semaphore for bounded concurrency. A failure in one does not affect others.

## Development

```bash
# Run tests
pytest

# Lint
ruff check src tests

# Type-check (optional)
mypy src
```

## Responsible use

Only scan domains and email addresses you own or have written authorization to scan. Some scanners issue queries to third-party services (GitHub, crt.sh, DuckDuckGo, HIBP) that may log those queries. Do not use this tool against targets you don't have permission to scan.

The tool stores finding metadata locally. When a scanner encounters what appears to be a live secret, only the URL and pattern type are persisted; raw credential text is not written to the database.

## Roadmap

- Continuous mode with diff-based alerting (webhook, email)
- Gitleaks-compatible rule file for the GitHub scanner
- Paste site polling (Pastebin scraping API)
- HTML report export with severity grouping
- Dockerfile for one-command deployment

## License

MIT
