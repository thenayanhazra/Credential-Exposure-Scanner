"""Tests for the model layer: severity rank, ScanResult serialization."""
from __future__ import annotations

from credscan.models import Finding, ScanResult, Severity


def test_severity_rank_ordering():
    assert Severity.CRITICAL.rank < Severity.HIGH.rank
    assert Severity.HIGH.rank < Severity.MEDIUM.rank
    assert Severity.MEDIUM.rank < Severity.LOW.rank
    assert Severity.LOW.rank < Severity.INFO.rank


def test_severity_rank_values_unique():
    ranks = [s.rank for s in Severity]
    assert len(set(ranks)) == len(ranks)


def test_finding_dedup_key_stable():
    f1 = Finding(
        source="test",
        target="domain:example.com",
        kind="breach",
        severity=Severity.HIGH,
        title="a",
        evidence_url="https://a.test",
    )
    f2 = Finding(
        source="test",
        target="domain:example.com",
        kind="breach",
        severity=Severity.HIGH,
        title="b (different title, same identity)",
        evidence_url="https://a.test",
    )
    assert f1.dedup_key() == f2.dedup_key()


def test_finding_dedup_key_differs_on_identity_fields():
    base = dict(
        source="test",
        target="domain:example.com",
        kind="breach",
        severity=Severity.HIGH,
        title="t",
        evidence_url="https://a.test",
    )
    base_key = Finding(**base).dedup_key()
    assert Finding(**{**base, "source": "other"}).dedup_key() != base_key
    assert Finding(**{**base, "kind": "other"}).dedup_key() != base_key
    assert Finding(**{**base, "evidence_url": "https://b.test"}).dedup_key() != base_key


def test_scan_result_to_public_dict():
    findings = [
        Finding(
            source="s1",
            target="domain:example.com",
            kind="breach",
            severity=Severity.HIGH,
            title="t1",
        )
    ]
    result = ScanResult(
        target="example.com",
        scan_id=42,
        scanners_run=["s1"],
        findings=findings,
    )
    d = result.to_public_dict()
    assert d["target"] == "example.com"
    assert d["scan_id"] == 42
    assert d["scanners_run"] == ["s1"]
    assert len(d["findings"]) == 1
    # findings should be JSON-ready dicts, not Finding instances
    assert isinstance(d["findings"][0], dict)
    assert d["findings"][0]["severity"] == "high"
