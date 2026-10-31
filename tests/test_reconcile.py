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
        assert audit.count() == 2
        intent, event = audit.tail(2)
        assert intent["type"] == "action.intent"
        assert intent["payload"]["intent_for"] == "reconciliation"
        assert event["type"] == "reconciliation.completed"
        assert event["payload"]["task_id"] == "r-test-004"
        assert event["payload"]["intent_seq"] == intent["seq"]
        assert event["payload"]["intent_hash"] == intent["hash"]
        assert event["payload"]["evidence_pack_sealed"] == result.evidence_pack["sealed_hash"]


def test_reconcile_rejects_duplicate_keys_instead_of_silently_dropping_rows(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    engine = ReconciliationEngine(audit)
    path_a = Path(_write_csv(tmp_path, "duplicate.csv", [
        {"id": "1", "name": "Alice", "status": "active"},
        {"id": "1", "name": "Alicia", "status": "active"},
    ]))
    path_b = Path(_write_csv(tmp_path, "clean.csv", [
        {"id": "1", "name": "Alice", "status": "active"},
    ]))

    import pytest
    with pytest.raises(ValueError, match="duplicate reconciliation key"):
        engine.reconcile(path_a, path_b, "id", task_id="r-duplicate")

    pending = audit.pending_intents()
    assert len(pending) == 1
    assert pending[0]["payload"]["details"]["task_id"] == "r-duplicate"


def test_reconcile_rejects_empty_keys_and_trims_key_whitespace(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    engine = ReconciliationEngine(audit)
    blank_a = Path(_write_csv(tmp_path, "blank.csv", [
        {"id": " ", "name": "Alice", "status": "active"},
    ]))
    clean_b = Path(_write_csv(tmp_path, "clean.csv", [
        {"id": "1", "name": "Alice", "status": "active"},
    ]))
    import pytest
    with pytest.raises(ValueError, match="empty reconciliation key"):
        engine.reconcile(blank_a, clean_b, "id", task_id="r-blank")

    spaced_a = Path(_write_csv(tmp_path, "spaced.csv", [
        {"id": " 1 ", "name": "Alice", "status": "active"},
    ]))
    result = engine.reconcile(spaced_a, clean_b, "id", task_id="r-trim")
    assert result.mismatched == 1
    assert result.only_in_a == result.only_in_b == 0


def test_interrupted_reconciliation_leaves_only_a_pending_intent(tmp_path, monkeypatch):
    import pytest

    import compliproof.reconcile as reconcile_module

    audit = AuditLog(tmp_path / "audit.jsonl")
    engine = ReconciliationEngine(audit)
    original_load = reconcile_module._load_csv
    load_count = 0

    def interrupt_second_input(path):
        nonlocal load_count
        load_count += 1
        if load_count == 2:
            raise OSError("synthetic input interruption")
        return original_load(path)

    source_a = Path(_write_csv(tmp_path, "a.csv", [
        {"id": "1", "name": "Synthetic", "status": "active"},
    ]))
    source_b = Path(_write_csv(tmp_path, "b.csv", [
        {"id": "1", "name": "Synthetic", "status": "active"},
    ]))
    monkeypatch.setattr(reconcile_module, "_load_csv", interrupt_second_input)

    with pytest.raises(OSError, match="synthetic input interruption"):
        engine.reconcile(source_a, source_b, "id", task_id="r-interrupted")

    events = audit.tail(10)
    assert audit.verify()
    assert len(events) == 1
    assert events[0]["type"] == "action.intent"
    assert events[0]["payload"]["details"]["task_id"] == "r-interrupted"
    assert [event["seq"] for event in audit.pending_intents()] == [events[0]["seq"]]


def test_verify_evidence():
    with tempfile.TemporaryDirectory() as tmp:
        audit = AuditLog(Path(tmp) / "audit.jsonl")
        engine = ReconciliationEngine(audit)
        path_a = _write_csv(tmp, "a.csv", [{"id": "1", "name": "Alice", "status": "active"}])
        path_b = _write_csv(tmp, "b.csv", [{"id": "1", "name": "Alice", "status": "active"}])
        result = engine.reconcile(path_a, path_b, "id", task_id="r-test-005", actor_id="BA")
        assert engine.verify_evidence("r-test-005") is True
