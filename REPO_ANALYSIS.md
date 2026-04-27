# Repository Analysis and Recommendations

## Executive summary

The project has a good architecture baseline for a lightweight OSINT scanner: target normalization is centralized, scanners are modular, and persistence has deterministic dedup behavior. The most impactful next step is improving operational resilience (timeouts/retries/transaction boundaries), then tightening documentation/config UX so contributors and operators can run it safely at scale.

## What is already strong

- **Clear execution pipeline** (`normalize` → scanner registry → `Runner` → `Store`).
- **Robust scanner isolation**: scanner exceptions are swallowed per scanner so one failure does not break the whole scan.
- **Deterministic dedup and ordering** in SQLite (`dedup_key` PK + `severity_rank` sorting).
- **Healthy baseline tests** in the repo for runner, models, normalization, scanners, and store.

## Findings from code review (high signal)

### 1) Per-finding DB commits reduce throughput under concurrency (**High**)

`Runner._run_one()` calls `self.store.upsert()` for every finding, and `Store.upsert()` commits on every call. This can create unnecessary lock churn and significantly slow scans when scanner output is large.

**Where observed**
- `src/credscan/runner.py` (`_run_one` inserts each finding one-by-one)
- `src/credscan/store.py` (`upsert` ends with `self.conn.commit()`)

**Recommendation**
- Add batched writes per scanner run (`upsert_many(findings)`), committing once per batch.
- Optionally keep per-finding commit behavior behind a "safe mode" config switch for debugging.

---

### 2) No scanner-level timeout/retry policy in runner contract (**High**)

Runner catches exceptions but has no timeout envelope, so a scanner can hang indefinitely. There is also no standardized retry/backoff policy for transient HTTP failures.

**Where observed**
- `src/credscan/runner.py` (`asyncio.gather` with per-scanner tasks, no timeout wrapper)

**Recommendation**
- Add per-scanner timeout config (e.g., `asyncio.timeout(...)`).
- Introduce shared retry helper (exponential backoff + jitter) for scanner HTTP clients.
- Record scanner execution metrics (`duration_ms`, `status`, `error_type`) in scan history.

---

### 3) Config loading is intentionally minimal but not validated (**Medium-High**)

`load_config()` returns raw TOML dict. This is simple, but malformed values can fail later or be silently ignored.

**Where observed**
- `src/credscan/config.py`

**Recommendation**
- Add typed config validation (Pydantic/dataclass validators) for common keys.
- Fail fast with clear diagnostics for invalid types/ranges (timeouts, limits, booleans).
- Add `credscan doctor` to validate config and external connectivity safely.

---

### 4) README structure section is stale relative to codebase (**Medium**)

The README includes paths/modules that are not present and omits actual current files.

**Where observed**
- `README.md` repository layout section

**Recommendation**
- Keep layout section synchronized with current package tree.
- Add a short “scanner dependency matrix” showing required APIs/keys and rate-limit expectations.

---

### 5) Scan history schema is useful but limited for observability (**Medium**)

Current `scans` table tracks only top-level scan start/finish/status/finding_count. There is no per-scanner telemetry, which makes performance tuning and incident debugging harder.

**Where observed**
- `src/credscan/store.py` (`scans` schema and write paths)

**Recommendation**
- Add a `scan_runs` table: `(scan_id, scanner, started_at, finished_at, status, finding_count, error)`.
- Surface these details in CLI and web UI for faster troubleshooting.

---

## Prioritized roadmap

1. **Resilience first (week 1):** scanner timeouts + retry helper + richer scanner status logging.
2. **Performance next (week 2):** batched DB writes + optional SQLite WAL tuning.
3. **Operator UX (week 3):** typed config validation + `credscan doctor` command.
4. **Observability (week 4):** per-scanner run metrics persisted and exposed in API/CLI.
5. **Docs hardening (continuous):** keep README structure/dependency sections aligned with implementation.

## Low-effort, high-value quick wins

- Add a default timeout value in config and apply it in runner immediately.
- Add a `--fail-fast` CLI option to stop scan when critical scanners fail.
- Emit one summary log per scanner (`scanner`, `count`, `duration`, `status`).
- Add a short architecture flow block to README for new contributors.
