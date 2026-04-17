"""Tests for the SQLite findings store."""
from __future__ import annotations

from datetime import UTC, datetime

import pytest

from credscan.models import Finding, Severity
from credscan.store import Store


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / "findings.db")
    yield s
    s.close()


def _mk_finding(**kwargs) -> Finding:
    defaults = dict(
        source="test",
        target="domain:example.com",
        kind="breach",
        severity=Severity.HIGH,
        title="test finding",
        evidence_url="https://example.com/leak",
    )
    defaults.update(kwargs)
    return Finding(**defaults)


class TestUpsert:
    def test_insert_new_returns_true(self, store):
        f = _mk_finding()
        assert store.upsert(f) is True

    def test_reinsert_same_returns_false(self, store):
        f = _mk_finding()
        store.upsert(f)
        assert store.upsert(f) is False

    def test_different_evidence_url_is_new(self, store):
        store.upsert(_mk_finding(evidence_url="https://a.com"))
        assert store.upsert(_mk_finding(evidence_url="https://b.com")) is True

    def test_different_source_is_new(self, store):
        store.upsert(_mk_finding(source="hibp"))
        assert store.upsert(_mk_finding(source="github_search")) is True

    def test_different_kind_is_new(self, store):
        store.upsert(_mk_finding(kind="breach"))
        assert store.upsert(_mk_finding(kind="password_literal")) is True

    def test_reinsert_updates_last_seen(self, store):
        f1 = _mk_finding(last_seen=datetime(2024, 1, 1, tzinfo=UTC))
        store.upsert(f1)
        f2 = _mk_finding(last_seen=datetime(2025, 6, 1, tzinfo=UTC))
        store.upsert(f2)
        rows = store.findings_for("domain:example.com")
        assert len(rows) == 1
        assert "2025" in rows[0]["last_seen"]

    def test_reinsert_refreshes_mutable_fields(self, store):
        """title, severity, and raw should update on reinsert; first_seen should not."""
        original_first_seen = datetime(2024, 1, 1, tzinfo=UTC)
        store.upsert(_mk_finding(
            first_seen=original_first_seen,
            severity=Severity.LOW,
            title="original title",
            raw={"v": 1},
        ))
        store.upsert(_mk_finding(
            first_seen=datetime(2025, 1, 1, tzinfo=UTC),  # should be ignored
            severity=Severity.CRITICAL,
            title="updated title",
            raw={"v": 2},
        ))
        rows = store.findings_for("domain:example.com")
        assert len(rows) == 1
        row = rows[0]
        assert row["severity"] == "critical"
        assert row["title"] == "updated title"
        assert row["raw"] == {"v": 2}
        # first_seen preserved from the original insert
        assert row["first_seen"].startswith("2024-01-01")


class TestFindingsFor:
    def test_empty_store(self, store):
        assert store.findings_for("domain:nothing.com") == []

    def test_sorted_by_severity(self, store):
        store.upsert(_mk_finding(kind="a", severity=Severity.LOW, evidence_url="a"))
        store.upsert(_mk_finding(kind="b", severity=Severity.CRITICAL, evidence_url="b"))
        store.upsert(_mk_finding(kind="c", severity=Severity.MEDIUM, evidence_url="c"))
        rows = store.findings_for("domain:example.com")
        assert [r["severity"] for r in rows] == ["critical", "medium", "low"]

    def test_filters_by_target(self, store):
        store.upsert(_mk_finding(target="domain:a.com", evidence_url="a"))
        store.upsert(_mk_finding(target="domain:b.com", evidence_url="b"))
        assert len(store.findings_for("domain:a.com")) == 1
        assert len(store.findings_for("domain:b.com")) == 1


class TestScanHistory:
    def test_start_finish(self, store):
        scan_id = store.start_scan("domain:example.com")
        assert scan_id > 0
        store.finish_scan(scan_id, finding_count=3)
        scans = store.recent_scans()
        assert len(scans) == 1
        assert scans[0]["status"] == "done"
        assert scans[0]["finding_count"] == 3
        assert scans[0]["finished_at"] is not None

    def test_recent_scans_ordered_desc(self, store):
        ids = [store.start_scan(f"domain:ex{i}.com") for i in range(3)]
        for sid in ids:
            store.finish_scan(sid, 0)
        scans = store.recent_scans()
        assert [s["id"] for s in scans] == list(reversed(ids))

    def test_finish_scan_with_status(self, store):
        sid = store.start_scan("domain:example.com")
        store.finish_scan(sid, 0, status="error")
        assert store.recent_scans()[0]["status"] == "error"
