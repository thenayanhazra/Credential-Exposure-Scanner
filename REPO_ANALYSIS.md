# Repository Analysis and Recommendations

## Executive summary

Credential Exposure Scanner has a clean baseline: tests and lint pass, the scanner abstraction is simple, and core data handling already avoids storing raw credentials directly. The next maturity step is to tighten operational hardening, make scanner quality easier to maintain at scale, and align docs with the real code layout.

## What is already working well

- Strong modular split (`normalize` → `runner` → scanner registry → `store`) keeps concerns clear.
- Deduped storage with stable keys and severity rank provides deterministic listing/order.
- Clear target normalization and typed models reduce malformed input risk.
- Good test baseline with broad unit coverage and passing checks.

## Priority recommendations

### 1) Documentation fidelity and onboarding (High)

The README "Repository layout" references modules that are not present in the current tree (for example: `evidence.py`, `scoring.py`, `taxonomy.py`, `verification.py`, `web/` package path), while implementation lives in files like `web.py`, `store.py`, and `scanners/`.

**Recommendation**
- Update the README layout to reflect the actual package structure.
- Add a short "Production readiness" section that calls out network/API dependencies and expected rate limits.
- Add an architecture diagram (or a short request flow section) for contributors.

### 2) Persistence performance and resilience (High)

`Store.upsert()` commits every individual finding. This is simple but becomes a throughput bottleneck under larger scans and increases lock churn in SQLite.

**Recommendation**
- Batch scanner writes per scan (or per scanner) and commit once per batch.
- Add optional SQLite pragmas for local single-writer workloads (`journal_mode=WAL`, `synchronous=NORMAL`) behind a config toggle.
- Add migration/version handling so schema evolution is explicit and safer over time.

### 3) Scanner execution controls (Medium-High)

Runner handles scanner failures safely, but there is no per-scanner timeout/circuit-break policy and no first-class retry/backoff policy in the runner contract.

**Recommendation**
- Add configurable timeout per scanner (e.g., `asyncio.timeout`).
- Introduce a common retry/backoff helper (with jitter) for transient HTTP failures.
- Persist per-scanner execution metrics (duration, success/fail, timeout) with each scan to support tuning.

### 4) Configuration and secret hygiene UX (Medium)

Configuration loading is intentionally lightweight, but validation is minimal. This increases risk of silent misconfiguration.

**Recommendation**
- Define a typed config model (Pydantic) for scanner settings and credentials.
- Fail fast with clear messages for invalid values (timeouts, limits, API keys expected format).
- Add a `credscan doctor` command to validate config and external connectivity non-destructively.

### 5) API/web hardening for local-to-team use (Medium)

Current FastAPI endpoints are intentionally simple and suitable for local use. For shared/internal deployments, controls are thin.

**Recommendation**
- Add optional API token auth for `/scan` and `/findings`.
- Add request rate limits and max body size safeguards.
- Add structured audit logs for scan requests (target hash, scanner set, duration, status).

### 6) Test strategy expansion (Medium)

Current tests are strong for unit behavior. Remaining risk is integration behavior with external providers and long-running scanner concurrency scenarios.

**Recommendation**
- Add integration tests for scanner registry wiring with mocked HTTP responses across all scanners.
- Add concurrency stress tests for `Runner` + `Store` to detect lock/contention regressions.
- Add snapshot-style API contract tests for web and CLI JSON output.

## Suggested phased roadmap

1. **Week 1 (quick wins):** README fixes, config model validation, timeout defaults.
2. **Week 2:** batched store writes + optional WAL mode + scanner execution metrics.
3. **Week 3:** auth/rate limiting for web mode + `doctor` command.
4. **Week 4:** integration and stress-test expansion + CI gates for coverage threshold.

## Optional longer-term improvements

- Introduce plugin entry points to support out-of-tree scanners.
- Add an event stream or queue backend abstraction for high-volume scans.
- Add finding suppression/triage state for analyst workflows.
