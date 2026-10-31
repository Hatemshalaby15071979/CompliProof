"""Tests for the CompliProof report generator."""
import csv
import hashlib
import io
import json
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from compliproof.audit import AuditLog
from compliproof.report import (
    ReportGenerator,
    load_reconciliation_result,
    save_reconciliation_result,
)


def test_generate_reconciliation_report():
    with tempfile.TemporaryDirectory() as tmp:
        audit = AuditLog(Path(tmp) / "audit.jsonl")
        gen = ReportGenerator(audit)
        result = {
            "task_id": "r-test-001",
            "correlation_id": "c-test-001",
            "source_a": "a.csv",
            "source_b": "b.csv",
            "key_column": "id",
            "total_a": 2,
            "total_b": 2,
            "matched": 1,
            "only_in_a": 1,
            "only_in_b": 1,
            "mismatched": 0,
            "matched_rows": [],
            "only_in_a_rows": [],
            "only_in_b_rows": [],
            "mismatched_rows": [],
            "evidence_pack": {
                "task_id": "r-test-001",
                "correlation_id": "c-test-001",
                "actor_id": "BA",
                "final_state": "reconciled",
                "steps": [],
                "evidence_summary": {"match_rate": 0.5},
                "kpi_summary": {"match_rate": 0.5, "discrepancy_rate": 0.5},
                "sealed_hash": "abc123",
                "timestamp": "2026-10-21T00:00:00+00:00",
            },
        }
        html = gen.generate_reconciliation_report(result)
        assert "CompliProof" in html
        assert "r-test-001" in html
        assert "abc123" in html
        assert "Matched Rows" in html
        assert "Only in Source A" in html
        assert "Only in Source B" in html
        assert "Mismatched Rows" in html
        assert "Evidence Pack (prototype)" in html
        assert "Task Audit Events" in html
        assert "not audit-grade" in html


def test_report_saves_to_file():
    with tempfile.TemporaryDirectory() as tmp:
        audit = AuditLog(Path(tmp) / "audit.jsonl")
        gen = ReportGenerator(audit)
        result = {
            "task_id": "r-test-002",
            "correlation_id": "c-test-002",
            "source_a": "a.csv",
            "source_b": "b.csv",
            "key_column": "id",
            "total_a": 1,
            "total_b": 1,
            "matched": 1,
            "only_in_a": 0,
            "only_in_b": 0,
            "mismatched": 0,
            "matched_rows": [],
            "only_in_a_rows": [],
            "only_in_b_rows": [],
            "mismatched_rows": [],
            "evidence_pack": {
                "task_id": "r-test-002",
                "correlation_id": "c-test-002",
                "actor_id": "BA",
                "final_state": "reconciled",
                "steps": [],
                "evidence_summary": {},
                "kpi_summary": {},
                "sealed_hash": "def456",
                "timestamp": "2026-10-21T00:00:00+00:00",
            },
        }
        html = gen.generate_reconciliation_report(result)
        out = Path(tmp) / "report.html"
        gen.save(html, out)
        assert out.exists()
        content = out.read_text(encoding="utf-8")
        assert "r-test-002" in content
        assert "def456" in content


def test_audit_chain_status_in_report():
    with tempfile.TemporaryDirectory() as tmp:
        audit = AuditLog(Path(tmp) / "audit.jsonl")
        gen = ReportGenerator(audit)
        result = {
            "task_id": "r-test-003",
            "correlation_id": "c-test-003",
            "source_a": "a.csv",
            "source_b": "b.csv",
            "key_column": "id",
            "total_a": 1,
            "total_b": 1,
            "matched": 1,
            "only_in_a": 0,
            "only_in_b": 0,
            "mismatched": 0,
            "matched_rows": [],
            "only_in_a_rows": [],
            "only_in_b_rows": [],
            "mismatched_rows": [],
            "evidence_pack": {
                "task_id": "r-test-003",
                "correlation_id": "c-test-003",
                "actor_id": "BA",
                "final_state": "reconciled",
                "steps": [],
                "evidence_summary": {},
                "kpi_summary": {},
                "sealed_hash": "ghi789",
                "timestamp": "2026-10-21T00:00:00+00:00",
            },
        }
        html = gen.generate_reconciliation_report(result)
        assert "OK" in html  # audit chain OK
        assert "ghi789" in html


def test_report_is_task_scoped_reproducible_and_audited_for_each_format(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    audit.append("task.created", "operator", {
        "task_id": "r-report-scope", "note": "belongs to this task"
    })
    audit.append("task.created", "operator", {
        "task_id": "r-other-task", "note": "must not leak"
    })
    generator = ReportGenerator(audit)
    result = {
        "task_id": "r-report-scope",
        "correlation_id": "c-report-scope",
        "source_a": "SYNTHETIC_a.csv",
        "source_b": "SYNTHETIC_b.csv",
        "key_column": "id",
        "timestamp": "2026-10-31T00:00:00+00:00",
        "total_a": 1,
        "total_b": 1,
        "matched": 1,
        "only_in_a": 0,
        "only_in_b": 0,
        "mismatched": 0,
        "match_rate": 1.0,
        "discrepancy_rate": 0.0,
        "matched_rows": [{
            "key": "SYN-001",
            "row_a": {"id": "SYN-001", "value": "synthetic-only"},
            "row_b": {"id": "SYN-001", "value": "synthetic-only"},
        }],
        "only_in_a_rows": [],
        "only_in_b_rows": [],
        "mismatched_rows": [],
        "evidence_pack": {"task_id": "r-report-scope", "sealed_hash": "local-hash"},
    }

    html_one = generator.generate_reconciliation_report(result).encode()
    html_two = generator.generate_reconciliation_report(result).encode()
    pdf = generator.to_pdf(result)
    csv_bytes = generator.to_csv(result).encode()
    assert html_one == html_two
    assert b"Task Audit Events (1 events, task-specific)" in html_one
    assert b"task.created" in html_one
    assert b"r-other-task" not in html_one
    assert b"100.0%" in html_one
    assert b"SYN-001" in html_one and b"synthetic-only" in html_one

    generated = [event for event in audit.tail(100) if event["type"] == "report.generated"]
    assert [event["payload"]["format"] for event in generated] == ["html", "html", "pdf", "csv"]
    for event, content in zip(generated, (html_one, html_two, pdf, csv_bytes), strict=True):
        assert event["payload"]["task_id"] == "r-report-scope"
        assert event["payload"]["report_sha256"] == hashlib.sha256(content).hexdigest()


def test_persisted_result_is_private_and_expires_after_30_days(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    result = {
        "task_id": "r-retention",
        "source_a": "input-a.csv",
        "source_b": "input-b.csv",
        "key_column": "id",
        "total_a": 1,
        "total_b": 1,
        "matched": 1,
        "only_in_a": 0,
        "only_in_b": 0,
        "mismatched": 0,
        "matched_rows": [{"row_a": {"id": "1", "value": "customer-data"}}],
        "only_in_a_rows": [],
        "only_in_b_rows": [],
        "mismatched_rows": [],
        "evidence_pack": {},
    }
    path = save_reconciliation_result(tmp_path, result, audit=audit, actor_id="operator-1")
    assert path.stat().st_mode & 0o777 == 0o600
    assert load_reconciliation_result(tmp_path, "r-retention", audit=audit) == result

    record = json.loads(path.read_text(encoding="utf-8"))
    record["created_at"] = "2020-01-01T00:00:00+00:00"
    path.write_text(json.dumps(record), encoding="utf-8")
    assert load_reconciliation_result(tmp_path, "r-retention", audit=audit) is None
    assert not path.exists()


def test_persisted_result_rejects_unsafe_task_ids(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    with pytest.raises(ValueError, match="task_id"):
        save_reconciliation_result(
            tmp_path, {"task_id": "../outside"}, audit=audit, actor_id="operator-1"
        )


def test_persisted_result_detects_file_tampering(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    result = {
        "task_id": "r-tamper",
        "source_a": "a.csv",
        "source_b": "b.csv",
        "key_column": "id",
        "total_a": 1,
        "total_b": 1,
        "matched": 1,
        "only_in_a": 0,
        "only_in_b": 0,
        "mismatched": 0,
        "matched_rows": [],
        "only_in_a_rows": [],
        "only_in_b_rows": [],
        "mismatched_rows": [],
        "evidence_pack": {},
    }
    path = save_reconciliation_result(
        tmp_path, result, audit=audit, actor_id="operator-1"
    )
    record = json.loads(path.read_text(encoding="utf-8"))
    record["result"]["matched"] = 0
    path.write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(RuntimeError, match="integrity check failed"):
        load_reconciliation_result(tmp_path, "r-tamper", audit=audit)


def test_csv_export_escapes_spreadsheet_formulas():
    with tempfile.TemporaryDirectory() as tmp:
        generator = ReportGenerator(AuditLog(Path(tmp) / "audit.jsonl"))
        csv_text = generator.to_csv({
            "task_id": "r-formula",
            "total_a": 1,
            "total_b": 1,
            "matched": 1,
            "only_in_a": 0,
            "only_in_b": 0,
            "mismatched": 0,
            "matched_rows": [{
                "key": "=1+1",
                "row_a": {"id": "1", "comment": "  @SUM(1,1)"},
                "row_b": {"id": "1", "comment": "safe"},
            }],
            "only_in_a_rows": [],
            "only_in_b_rows": [],
            "mismatched_rows": [],
        })
    rows = list(csv.DictReader(io.StringIO(csv_text)))
    assert rows[0]["key"] == "'=1+1"
    assert rows[0]["a_comment"] == "'  @SUM(1,1)"
