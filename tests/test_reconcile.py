"""Tests for the CompliProof reconciliation engine."""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from compliproof.audit import AuditLog
from compliproof.reconcile import ReconciliationEngine


def _write_csv(tmp_path, name, rows, header="id,name,status"):
    p = Path(tmp_path) / name
    with open(p, "w", encoding="utf-8", newline="") as f:
        f.write(header + "\n")
        for r in rows:
            f.write(",".join(str(r.get(h, "")) for h in header.split(",")) + "\n")
    return str(p)


def test_reconcile_basic_match():
    with tempfile.TemporaryDirectory() as tmp:
        audit = AuditLog(Path(tmp) / "audit.jsonl")
        engine = ReconciliationEngine(audit)
        path_a = _write_csv(tmp, "a.csv", [{"id": "1", "name": "Alice", "status": "active"}, {"id": "2", "name": "Bob", "status": "active"}])
        path_b = _write_csv(tmp, "b.csv", [{"id": "1", "name": "Alice", "status": "active"}, {"id": "3", "name": "Carol", "status": "active"}])
        result = engine.reconcile(path_a, path_b, "id", task_id="r-test-001", actor_id="BA")
        assert result.total_a == 2
        assert result.total_b == 2
        assert result.matched == 1
        assert result.only_in_a == 1
        assert result.only_in_b == 1
        assert result.mismatched == 0
        assert result.match_rate == 0.5
        assert result.discrepancy_rate == 0.5
        assert result.to_dict()["match_rate"] == result.evidence_pack["kpi_summary"]["match_rate"]
        assert (
            result.to_dict()["discrepancy_rate"]
            == result.evidence_pack["kpi_summary"]["discrepancy_rate"]
        )
        assert result.evidence_pack is not None
        assert result.evidence_pack["sealed_hash"] != ""
        assert result.evidence_pack["task_id"] == "r-test-001"


def test_reconcile_mismatch():
    with tempfile.TemporaryDirectory() as tmp:
        audit = AuditLog(Path(tmp) / "audit.jsonl")
        engine = ReconciliationEngine(audit)
        path_a = _write_csv(tmp, "a.csv", [{"id": "1", "name": "Alice", "status": "active"}])
        path_b = _write_csv(tmp, "b.csv", [{"id": "1", "name": "Alice", "status": "inactive"}])
        result = engine.reconcile(path_a, path_b, "id", task_id="r-test-002", actor_id="BA")
        assert result.matched == 0
        assert result.mismatched == 1
        assert len(result.mismatched_rows) == 1
        assert result.mismatched_rows[0]["hash_a"] != result.mismatched_rows[0]["hash_b"]


def test_reconcile_evidence_pack_sealed():
    with tempfile.TemporaryDirectory() as tmp:
        audit = AuditLog(Path(tmp) / "audit.jsonl")
        engine = ReconciliationEngine(audit)
        path_a = _write_csv(tmp, "a.csv", [{"id": "1", "name": "Alice", "status": "active"}])
        path_b = _write_csv(tmp, "b.csv", [{"id": "1", "name": "Alice", "status": "active"}])
        result = engine.reconcile(path_a, path_b, "id", task_id="r-test-003", actor_id="BA")
        pack = result.evidence_pack
        assert result.match_rate == 1.0
        assert result.discrepancy_rate == 0.0
        assert pack["kpi_summary"]["match_rate"] == result.match_rate
        assert pack["kpi_summary"]["discrepancy_rate"] == result.discrepancy_rate
        assert pack["sealed_hash"] != ""
        assert pack["task_id"] == "r-test-003"
        assert pack["actor_id"] == "BA"
        assert len(pack["steps"]) == 3


def test_reconcile_empty_inputs_have_zero_metrics():
    with tempfile.TemporaryDirectory() as tmp:
        audit = AuditLog(Path(tmp) / "audit.jsonl")
        engine = ReconciliationEngine(audit)
        path_a = _write_csv(tmp, "a.csv", [])
        path_b = _write_csv(tmp, "b.csv", [])

        result = engine.reconcile(path_a, path_b, "id", task_id="r-empty")

        assert result.total_a == 0
        assert result.total_b == 0
        assert result.match_rate == 0.0
        assert result.discrepancy_rate == 0.0
        assert result.evidence_pack["kpi_summary"]["match_rate"] == 0.0
        assert result.evidence_pack["kpi_summary"]["discrepancy_rate"] == 0.0


def test_audit_log_records_reconciliation():
    with tempfile.TemporaryDirectory() as tmp:
        audit = AuditLog(Path(tmp) / "audit.jsonl")
        engine = ReconciliationEngine(audit)
        path_a = _write_csv(tmp, "a.csv", [{"id": "1", "name": "Alice", "status": "active"}])
        path_b = _write_csv(tmp, "b.csv", [{"id": "1", "name": "Alice", "status": "active"}])
        result = engine.reconcile(path_a, path_b, "id", task_id="r-test-004", actor_id="BA")
        assert audit.verify() is True
        assert audit.count() == 1
        event = audit.tail(1)[0]
        assert event["type"] == "reconciliation.completed"
        assert event["payload"]["task_id"] == "r-test-004"
        assert event["payload"]["evidence_pack_sealed"] == result.evidence_pack["sealed_hash"]


def test_verify_evidence():
    with tempfile.TemporaryDirectory() as tmp:
        audit = AuditLog(Path(tmp) / "audit.jsonl")
        engine = ReconciliationEngine(audit)
        path_a = _write_csv(tmp, "a.csv", [{"id": "1", "name": "Alice", "status": "active"}])
        path_b = _write_csv(tmp, "b.csv", [{"id": "1", "name": "Alice", "status": "active"}])
        result = engine.reconcile(path_a, path_b, "id", task_id="r-test-005", actor_id="BA")
        assert engine.verify_evidence("r-test-005") is True
