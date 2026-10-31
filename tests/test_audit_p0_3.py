"""P0-3 acceptance tests for the remediated audit ledger.

Covers:
- intent event durable before execution
- mid-action process kill leaves recoverable intent
- concurrent appends produce a valid, ordered chain with unique seq numbers
- truncation, rewrite, and reorder detected by anchor comparison
- tests cannot write to the production ledger (byte-for-byte unchanged)
- an independent verifier validates the chain
- anchors themselves are tamper-evident
"""
import json
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from compliproof.audit import (
    CANONICAL_LEDGER,
    INTENT_TYPE,
    LEGACY_DEFAULT_LEDGER,
    AuditLog,
    ProductionLedgerError,
    verify_ledger,
)


def _tmp_log(tmp_path: Path) -> AuditLog:
    return AuditLog(tmp_path / "audit.jsonl")


# ── intent before action ────────────────────────────────────────────────────


def test_intent_event_durable_before_execution(tmp_path):
    """The intent event is written and fsynced to disk before the action runs."""
    log = _tmp_log(tmp_path)
    intent = log.append_intent("reconciliation", "BA", {"task_id": "r-001"})

    # Intent is on disk before any result exists.
    disk_lines = (tmp_path / "audit.jsonl").read_text().strip().split("\n")
    assert len(disk_lines) == 1
    disk_entry = json.loads(disk_lines[0])
    assert disk_entry["type"] == INTENT_TYPE
    assert disk_entry["hash"] == intent["hash"]

    # Now the "action" runs and the result links back.
    result = log.append_result(intent, "reconciliation.completed", "BA", {"result": "matched"})
    assert result["payload"]["intent_seq"] == intent["seq"]
    assert result["payload"]["intent_hash"] == intent["hash"]
    assert log.verify() is True
    assert log.pending_intents() == []


def test_append_result_rejects_non_intent(tmp_path):
    log = _tmp_log(tmp_path)
    normal = log.append("task.created", "BA", {"id": "t1"})
    with pytest.raises(ValueError):
        log.append_result(normal, "task.completed", "BA", {})


def test_mid_action_process_kill_leaves_recoverable_intent(tmp_path):
    """Simulate a kill between intent and result: reopening shows the intent."""
    log = _tmp_log(tmp_path)
    log.append_intent("deployment", "BA", {"target": "staging"})
    # Simulate crash: no append_result, no cleanup. Open a fresh instance
    # (as a restarted process would) and recover.
    recovered = AuditLog(tmp_path / "audit.jsonl")
    pending = recovered.pending_intents()
    assert len(pending) == 1
    assert pending[0]["type"] == INTENT_TYPE
    assert pending[0]["payload"]["intent_for"] == "deployment"
    # Recovery path: complete the action with append_result.
    recovered.append_result(pending[0], "deployment.completed", "BA", {"ok": True})
    assert recovered.pending_intents() == []
    assert recovered.verify() is True


# ── concurrency ─────────────────────────────────────────────────────────────


def test_concurrent_appends_produce_valid_ordered_chain(tmp_path):
    """50 concurrent appends produce exactly 50 events, seq 1..50, valid chain."""
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    N = 50

    def _append(i: int):
        return log.append("worker.event", f"w-{i % 5}", {"i": i})

    with ThreadPoolExecutor(max_workers=10) as ex:
        list(ex.map(_append, range(N)))

    res = verify_ledger(path)
    assert res["ok"] is True, res
    assert res["count"] == N
    seqs = [e["seq"] for e in log.tail(10**9)]
    assert seqs == list(range(1, N + 1)), "sequence numbers must be unique and ordered"


def test_multiple_instance_concurrent_appends(tmp_path):
    """Separate AuditLog instances writing the same file do not corrupt it."""
    path = tmp_path / "audit.jsonl"

    def _writer(j: int):
        w = AuditLog(path)
        for i in range(5):
            w.append("writer.event", f"proc-{j}", {"i": i})

    threads = [threading.Thread(target=_writer, args=(j,)) for j in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    res = verify_ledger(path)
    assert res["ok"] is True, res
    assert res["count"] == 25
    seqs = sorted(e["seq"] for e in AuditLog(path).tail(10**9))
    assert len(set(seqs)) == 25, "no duplicate sequence numbers"


# ── anchoring: truncation, rewrite, reorder ────────────────────────────────


def test_anchor_ok_when_untampered(tmp_path):
    log = _tmp_log(tmp_path)
    for i in range(3):
        log.append("t", "BA", {"i": i})
    log.anchor(provider="local")
    assert log.check_anchor() == {"ok": True, "reason": "ok", "anchored_seq": 3, "current_seq": 3}


def test_no_anchors_is_not_failure(tmp_path):
    log = _tmp_log(tmp_path)
    log.append("t", "BA", {})
    res = log.check_anchor()
    assert res["ok"] is True and res["reason"] == "no_anchors"


def test_truncation_detected_by_anchor(tmp_path):
    log = _tmp_log(tmp_path)
    for i in range(5):
        log.append("t", "BA", {"i": i})
    log.anchor(provider="local")
    # Truncate: remove the last two events.
    lines = (tmp_path / "audit.jsonl").read_text().strip().split("\n")
    (tmp_path / "audit.jsonl").write_text("\n".join(lines[:3]) + "\n")
    res = log.check_anchor()
    assert res["ok"] is False and res["reason"] == "truncated"


def test_rewrite_detected_by_anchor(tmp_path):
    """An attacker rewrites data and recomputes hashes: the anchor head differs."""
    import hashlib

    log = _tmp_log(tmp_path)
    for i in range(3):
        log.append("t", "BA", {"i": i})
    log.anchor(provider="local")

    # Rewrite with recomputed hashes from genesis (a competent rewrite).
    lines = (tmp_path / "audit.jsonl").read_text().strip().split("\n")
    rewritten = []
    prev = "GENESIS"
    for line in lines:
        entry = json.loads(line)
        entry["payload"] = {"i": 999}  # tampered payload
        entry.pop("hash", None)
        entry["prev_hash"] = prev
        entry["hash"] = hashlib.sha256(
            (json.dumps(entry, sort_keys=True, separators=(",", ":")) + prev).encode()
        ).hexdigest()
        rewritten.append(json.dumps(entry))
        prev = entry["hash"]
    (tmp_path / "audit.jsonl").write_text("\n".join(rewritten) + "\n")

    res = log.check_anchor()
    assert res["ok"] is False and res["reason"] == "rewritten", res


def test_reorder_detected_by_anchor(tmp_path):
    """Swapping two events breaks the chain (order change detected)."""
    log = _tmp_log(tmp_path)
    for i in range(4):
        log.append("t", "BA", {"i": i})
    log.anchor(provider="local")
    lines = (tmp_path / "audit.jsonl").read_text().strip().split("\n")
    lines[1], lines[2] = lines[2], lines[1]
    (tmp_path / "audit.jsonl").write_text("\n".join(lines) + "\n")
    res = log.check_anchor()
    assert res["ok"] is False, res


def test_append_refuses_to_extend_a_corrupt_chain(tmp_path):
    log = _tmp_log(tmp_path)
    log.append("event", "operator", {"value": "original"})
    path = tmp_path / "audit.jsonl"
    entry = json.loads(path.read_text().strip())
    entry["payload"]["value"] = "tampered"
    path.write_text(json.dumps(entry) + "\n")

    with pytest.raises(OSError, match="Audit chain is broken"):
        log.append("event", "operator", {"value": "must-not-append"})
    assert verify_ledger(path)["ok"] is False


def test_anchor_files_are_tamper_evident(tmp_path):
    log = _tmp_log(tmp_path)
    log.append("t", "BA", {})
    log.anchor(provider="local")
    log.append("t", "BA", {})
    log.anchor(provider="local")

    # Tamper with the FIRST anchor file (drop in anchor chain breaks).
    p = tmp_path / "anchors" / "anchor-00000001.json"
    rec = json.loads(p.read_text())
    rec["head_hash"] = "0" * 64
    p.write_text(json.dumps(rec, indent=2))

    res = log.check_anchor()
    assert res["ok"] is False and res["reason"] == "anchor_tampered", res


# ── production ledger isolation ─────────────────────────────────────────────


def test_default_open_of_production_ledger_refused():
    with pytest.raises(ProductionLedgerError):
        AuditLog()  # default = canonical production ledger


def test_legacy_path_also_refused():
    with pytest.raises(ProductionLedgerError):
        AuditLog(LEGACY_DEFAULT_LEDGER)


def test_tests_cannot_modify_production_ledger():
    """Running test-suite-like access leaves the production ledger byte-identical."""
    assert CANONICAL_LEDGER.exists(), "canonical ledger expected to exist"
    before = CANONICAL_LEDGER.read_bytes()
    try:
        AuditLog(CANONICAL_LEDGER)
    except ProductionLedgerError:
        pass
    else:
        raise AssertionError("AuditLog opened the production ledger without allow_production")
    assert CANONICAL_LEDGER.read_bytes() == before


def test_independent_verifier_validates_chain_and_detects_corruption(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append("a", "BA", {"n": 1})
    log.append("b", "BA", {"n": 2})
    assert verify_ledger(path) == {"ok": True, "reason": "ok", "count": 2, "head": log.get_chain_tip()}

    # Corrupt the middle event's payload.
    lines = path.read_text().strip().split("\n")
    entry = json.loads(lines[0])
    entry["payload"]["n"] = 42
    lines[0] = json.dumps(entry)
    path.write_text("\n".join(lines) + "\n")

    res = verify_ledger(path)
    assert res["ok"] is False and res["reason"] == "bad_hash" and res["seq"] == 1


def test_independent_verifier_detects_sequence_gap(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append("a", "BA", {})
    log.append("b", "BA", {})
    lines = path.read_text().strip().split("\n")
    entry = json.loads(lines[1])
    entry["seq"] = 9
    lines[1] = json.dumps(entry)
    path.write_text("\n".join(lines) + "\n")
    res = verify_ledger(path)
    assert res["ok"] is False and res["reason"] == "sequence_gap"


def test_broken_json_detected_by_independent_verifier(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append("a", "BA", {})
    with path.open("a", encoding="utf-8") as f:
        f.write("{not json}\n")
    res = verify_ledger(path)
    assert res["ok"] is False and res["reason"] == "corrupt_json"
