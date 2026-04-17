"""SQLite-backed findings and scan-history store."""
from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .models import Finding

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    dedup_key     TEXT PRIMARY KEY,
    source        TEXT NOT NULL,
    target        TEXT NOT NULL,
    kind          TEXT NOT NULL,
    severity      TEXT NOT NULL,
    title         TEXT NOT NULL,
    evidence_url  TEXT,
    evidence_hash TEXT,
    raw_json      TEXT,
    first_seen    TEXT NOT NULL,
    last_seen     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_target   ON findings(target);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);

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


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


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
        """Insert or refresh a finding. Returns True if this is a new row."""
        key = f.dedup_key()
        row = self.conn.execute(
            "SELECT dedup_key FROM findings WHERE dedup_key = ?", (key,)
        ).fetchone()
        is_new = row is None

        if is_new:
            self.conn.execute(
                """INSERT INTO findings
                   (dedup_key, source, target, kind, severity, title,
                    evidence_url, evidence_hash, raw_json, first_seen, last_seen)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    key,
                    f.source,
                    f.target,
                    f.kind,
                    f.severity.value,
                    f.title,
                    f.evidence_url,
                    f.evidence_hash,
                    json.dumps(f.raw, default=str),
                    f.first_seen.isoformat(),
                    f.last_seen.isoformat(),
                ),
            )
        else:
            self.conn.execute(
                "UPDATE findings SET last_seen = ?, raw_json = ? WHERE dedup_key = ?",
                (f.last_seen.isoformat(), json.dumps(f.raw, default=str), key),
            )
        self.conn.commit()
        return is_new

    def findings_for(self, target: str) -> list[dict[str, Any]]:
        cur = self.conn.execute(
            "SELECT * FROM findings WHERE target = ? "
            "ORDER BY CASE severity "
            "  WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
            "  WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, "
            "last_seen DESC",
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
