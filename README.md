# Credential Exposure Scanner

Credential Exposure Scanner is a focused OSINT-style scanner for domains and email addresses. It is built to surface public evidence of exposure, separate confirmed findings from weak leads, and keep the storage layer free from raw credential material.

## What it does

- Accepts a domain or email address as input
- Normalizes the target into a canonical form
- Runs multiple internet-facing scanners
- Distinguishes between confirmed exposure, unverified leads, and asset intelligence
- Stores findings in SQLite with deduplication and scan history
- Provides both a CLI and a small local web UI

## Current scanner classes

- `crtsh`: certificate-transparency-derived subdomain intelligence
- `github_search`: public code search for target-linked secret exposure indicators
- `hibp`: Have I Been Pwned email breach lookups when an API key is configured
- `dorks`: search-engine lead collection
- `lead_fetch`: fetch-and-classify stage for lead URLs
- `exact_email_search`: exact email public reference checks

## Finding model

Every finding carries:

- `exposure_type`: `breach_exposure`, `public_secret_exposure`, `artifact_lead`, or `asset_intelligence`
- `verification_state`: `verified`, `unverified`, or `discarded`
- `severity`
- `confidence`
- sanitized evidence metadata

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Configure

Copy the example config and edit it:

```bash
cp config.example.toml ~/.config/credscan/config.toml
```

## Usage

Scan a target:

```bash
credscan scan example.com
credscan scan alice@example.com --output json
```

Run the local web UI:

```bash
credscan serve --host 127.0.0.1 --port 8765
```

View recent scan history:

```bash
credscan history
```

## Repository layout

```text
src/credscan/
  cli.py
  config.py
  evidence.py
  models.py
  normalize.py
  registry.py
  runner.py
  scoring.py
  store.py
  taxonomy.py
  verification.py
  web/
  scanners/
```

## Design constraints

- No raw credential storage
- Verification and scoring are centralized rather than embedded inside each scanner
- Search-engine hits are treated as leads until fetched and classified
- Asset discovery is stored separately from exposure findings

## Notes

This repository is structured to be upload-ready for GitHub. Some scanners rely on third-party services and may require API credentials, rate-limit handling, or stricter HTML parsers before production use.
