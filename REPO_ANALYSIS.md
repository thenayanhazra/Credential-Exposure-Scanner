# Repository Analysis and Recommendations

## Executive summary

The project has a solid architecture baseline: target normalization is centralized, scanners are modular, and persistence has deterministic dedup behaviour. This document tracks code-review findings, their severity, and their current resolution status.

---

## Findings

### 1. No scanner-level timeout in runner — **HIGH** — FIXED

**Problem:** `asyncio.gather` ran scanner tasks with no time bound. A stuck HTTP connection could hold a semaphore slot indefinitely, blocking subsequent scans.

**Fix applied (`runner.py`):** Each `_run_one` call is now wrapped in `asyncio.timeout(self.scanner_timeout)`. Default is 120 seconds. Configurable via `[app] scanner_timeout` in config.

---

### 2. Backoff formula used wrong base — **MEDIUM** — FIXED

**Problem:** `_BASE_DELAY**attempt` in `http.py` gave 1.0 s on the first retry (attempt=0), not the intended 2.0 s. Subsequent delays were also compressed relative to what `_BASE_DELAY = 2.0` implied.

**Fix applied (`http.py`):** Changed to `_BASE_DELAY * (2**attempt)`, giving 2 s → 4 s → 8 s on successive retries. Both the network-error path and the transient-status-code path were corrected.

---

### 3. OpenAI key regex missed the current key format — **MEDIUM** — FIXED

**Problem:** Pattern `sk-[A-Za-z0-9]{20,}` matched the old 51-character `sk-` prefix format only. OpenAI now issues `sk-proj-…` and `sk-svcacct-…` keys; the old pattern did not match these.

**Fix applied (`scanners/_github.py`):** Updated to `sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}`, covering both legacy and current key formats.

---

### 4. FastAPI app hardcoded a stale version string — **LOW** — FIXED

**Problem:** `web.py` passed `version="0.1.0"` to `FastAPI(...)` while `pyproject.toml` declared `0.2.0`. The OpenAPI schema reported the wrong version.

**Fix applied (`web.py`):** Version is now read from `credscan.__version__` (which itself reads from package metadata), so it stays in sync automatically.

---

### 5. SQLite WAL mode not enabled — **LOW** — FIXED

**Problem:** The default SQLite journal mode (DELETE) causes readers to block writers and vice versa. Under the web server, concurrent `/scan` and `/findings` requests could serialize unnecessarily.

**Fix applied (`store.py`):** `PRAGMA journal_mode=WAL` is set on every new connection, allowing concurrent reads and a single writer without mutual blocking.

---

### 6. Per-finding DB commits reduce throughput under concurrency — **HIGH** — OPEN

`Runner._run_one()` calls `store.upsert()` for every finding, and each `upsert` commits immediately. This creates unnecessary lock churn when scanner output is large.

**Recommendation:** Add `upsert_many(findings)` that commits once per batch. Keep the current per-finding behaviour as a "safe mode" fallback for debugging.

**Affected files:** `src/credscan/runner.py`, `src/credscan/store.py`

---

### 7. Config loading is unvalidated — **MEDIUM** — OPEN

`load_config()` returns a raw TOML dict. Malformed values (wrong types, out-of-range integers) fail later with confusing errors or are silently ignored.

**Recommendation:** Add typed validation (Pydantic or dataclass) for common keys. Add a `credscan doctor` CLI command to validate config and test external API connectivity.

**Affected file:** `src/credscan/config.py`

---

### 8. Scan history has no per-scanner telemetry — **MEDIUM** — OPEN

The `scans` table tracks only top-level start/finish/status/finding_count. There is no per-scanner breakdown, making performance tuning and incident debugging harder.

**Recommendation:** Add a `scan_runs` table with columns `(scan_id, scanner, started_at, finished_at, status, finding_count, error)`. Surface per-scanner stats in the CLI and web UI.

**Affected file:** `src/credscan/store.py`

---

### 9. `evidence_hash` field is never populated — **LOW** — OPEN

`Finding.evidence_hash` exists in the model and in the SQLite schema, but no scanner sets it. It is stored as NULL in every row.

**Recommendation:** Either populate it (SHA-256 of fetched raw file content) in scanners that fetch raw files, or remove the field and column until it has a defined use case.

---

### 10. DuckDuckGo HTML scraping is fragile — **LOW** — OPEN

`dorks.py` parses DuckDuckGo's HTML response with a hardcoded CSS class regex (`result__a`). A DDG markup change silently breaks hit extraction with no error signal.

**Recommendation:** Add a sanity-check assertion on parsed hit count; emit a warning log when zero hits are extracted on a query that returned HTTP 200 (possible markup change). Consider a fallback to another search endpoint.

---

## Prioritized roadmap

1. **Resilience (done):** per-scanner timeouts added; backoff formula fixed.
2. **Performance:** batched DB writes per scanner run.
3. **Operator UX:** typed config validation + `credscan doctor` command.
4. **Observability:** per-scanner run metrics in DB, CLI, and web UI.
5. **Robustness:** DDG scraper health checks; `evidence_hash` resolution.
