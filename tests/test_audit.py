"""Tests for the CompliProof audit ledger."""
import json
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from compliproof.audit import AuditLog, DEFAULT_LOG, ProductionLedgerError


def test_append_and_verify_chain():
    with tempfile.TemporaryDirectory() as tmp:
        log = AuditLog(Path(tmp) / "audit.jsonl")
        e1 = log.append("task.created", "BA", {"id": "t1", "title": "Test task"})
        e2 = log.append("task.completed", "BA", {"id": "t1"})
        assert log.verify() is True
        assert e1["prev_hash"] == "GENESIS"
        assert e2["prev_hash"] == e1["hash"]
        assert e1["actor"] == "BA"
        assert e1["type"] == "task.created"


def test_chain_break_detected():
    with tempfile.TemporaryDirectory() as tmp:
        log = AuditLog(Path(tmp) / "audit.jsonl")
        log.append("task.created", "BA", {"id": "t1"})
        # Tamper with the file directly
        lines = log.path.read_text().strip().split("\n")
        tampered = json.loads(lines[0])
        tampered["payload"]["title"] = "Tampered"
        lines[0] = json.dumps(tampered)
        log.path.write_text("\n".join(lines) + "\n")
        assert log.verify() is False


def test_tail_and_count():
    with tempfile.TemporaryDirectory() as tmp:
        log = AuditLog(Path(tmp) / "audit.jsonl")
        for i in range(5):
            log.append("task.event", "BA", {"i": i})
        assert log.count() == 5
        tail = log.tail(3)
        assert len(tail) == 3
        assert tail[0]["payload"]["i"] == 2
        assert tail[2]["payload"]["i"] == 4


def test_empty_log_verify():
    with tempfile.TemporaryDirectory() as tmp:
        log = AuditLog(Path(tmp) / "audit.jsonl")
        assert log.verify() is True
        assert log.count() == 0
        assert log.get_chain_tip() == "GENESIS"


def test_cli_append_verify():
    import subprocess
    with tempfile.TemporaryDirectory() as tmp:
        log_path = Path(tmp) / "audit.jsonl"
        # We can't easily test CLI without changing DEFAULT_LOG, so just test the module directly
        log = AuditLog(log_path)
        e = log.append("test.event", "tester", {"key": "val"})
        assert e["hash"] is not None
        assert log.verify() is True


def test_default_log_requires_explicit_production_opt_in():
    """A test or library must not open the production ledger by accident."""
    with pytest.raises(ProductionLedgerError):
        AuditLog()


def test_temp_ledger_does_not_touch_production():
    """Writing to a temporary ledger leaves the production ledger byte-for-byte unchanged.

    On a fresh clone the production ledger may not exist yet; the essential
    assertion is that a temp-ledger write neither creates nor modifies it.
    """
    production_existed_before = DEFAULT_LOG.exists()
    before = DEFAULT_LOG.read_bytes() if production_existed_before else None
    with tempfile.TemporaryDirectory() as tmp:
        log = AuditLog(Path(tmp) / "audit.jsonl")
        log.append("test.event", "tester", {"key": "val"})
    # The temp-ledger write must not create or modify the production ledger.
    assert DEFAULT_LOG.exists() == production_existed_before
    if production_existed_before:
        after = DEFAULT_LOG.read_bytes()
        assert after == before
