"""SQLite-backed findings and scan-history store.

Schema notes
------------
- `findings` carries a `severity_rank` denormalized integer column. The app
  supplies it from `Severity.rank` at write time, so sorting is a plain
  ORDER BY — no SQL `CASE` duplicating the enum ordering.
- Upsert is a single `INSERT ... ON CONFLICT(dedup_key) DO UPDATE`, which
  refreshes all mutable fields (title, severity, raw) while preserving
  `first_seen` via the table default.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import Finding, Severity

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    dedup_key      TEXT PRIMARY KEY,
    source         TEXT NOT NULL,
    target         TEXT NOT NULL,
    kind           TEXT NOT NULL,
    severity       TEXT NOT NULL,
    severity_rank  INTEGER NOT NULL,
    title          TEXT NOT NULL,
    evidence_url   TEXT,
    evidence_hash  TEXT,
    raw_json       TEXT,
    first_seen     TEXT NOT NULL,
    last_seen      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_target   ON findings(target);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity_rank);

CREATE TABLE IF NOT EXISTS scans (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    target         TEXT NOT NULL,
    started_at     TEXT NOT NULL,
    finished_at    TEXT,
    status         TEXT NOT NULL,
    finding_count  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
"""

# INSERT; on conflict, do nothing. rowcount tells us whether we inserted.
_INSERT_SQL = """
INSERT INTO findings
    (dedup_key, source, target, kind, severity, severity_rank, title,
     evidence_url, evidence_hash, raw_json, first_seen, last_seen)
VALUES
    (:dedup_key, :source, :target, :kind, :severity, :severity_rank, :title,
     :evidence_url, :evidence_hash, :raw_json, :first_seen, :last_seen)
ON CONFLICT(dedup_key) DO NOTHING
"""

# Refresh mutable fields when the row already existed. first_seen is never
# overwritten.
_UPDATE_SQL = """
UPDATE findings
SET severity      = :severity,
    severity_rank = :severity_rank,
    title         = :title,
    evidence_url  = :evidence_url,
    evidence_hash = :evidence_hash,
    raw_json      = :raw_json,
    last_seen     = :last_seen
WHERE dedup_key = :dedup_key
"""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class Store:
    """Thin SQLite wrapper. One instance per connection."""

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    # --- findings ---

    def upsert(self, f: Finding) -> bool:
        """Insert or refresh a finding. Returns True if this is a new row.

        Attempts INSERT; on conflict, falls through to UPDATE. In the
        inserted-fresh case that's one statement; in the refresh case it's
        two. first_seen is never overwritten.
        """
        sev = Severity(f.severity)
        params = {
            "dedup_key": f.dedup_key(),
            "source": f.source,
            "target": f.target,
            "kind": f.kind,
            "severity": sev.value,
            "severity_rank": sev.rank,
            "title": f.title,
            "evidence_url": f.evidence_url,
            "evidence_hash": f.evidence_hash,
            "raw_json": json.dumps(f.raw, default=str),
            "first_seen": f.first_seen.isoformat(),
            "last_seen": f.last_seen.isoformat(),
        }
        cur = self.conn.execute(_INSERT_SQL, params)
        inserted = cur.rowcount > 0
        if not inserted:
            self.conn.execute(_UPDATE_SQL, params)
        self.conn.commit()
        return inserted

    def findings_for(self, target: str) -> list[dict[str, Any]]:
        cur = self.conn.execute(
            "SELECT * FROM findings WHERE target = ? "
            "ORDER BY severity_rank ASC, last_seen DESC",
            (target,),
        )
        return [self._row_to_dict(r) for r in cur.fetchall()]

    # --- scan history ---

    def start_scan(self, target: str) -> int:
        cur = self.conn.execute(
            "INSERT INTO scans (target, started_at, status) VALUES (?, ?, 'running')",
            (target, _now_iso()),
        )
        self.conn.commit()
        return cur.lastrowid or 0

    def finish_scan(self, scan_id: int, finding_count: int, status: str = "done") -> None:
        self.conn.execute(
            "UPDATE scans SET finished_at = ?, status = ?, finding_count = ? WHERE id = ?",
            (_now_iso(), status, finding_count, scan_id),
        )
        self.conn.commit()

    def recent_scans(self, limit: int = 20) -> list[dict[str, Any]]:
        cur = self.conn.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
        )
        return [dict(r) for r in cur.fetchall()]

    # --- helpers ---

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        if d.get("raw_json"):
            try:
                d["raw"] = json.loads(d["raw_json"])
            except json.JSONDecodeError:
                d["raw"] = {}
        else:
            d["raw"] = {}
        d.pop("raw_json", None)
        return d

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> Store:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
