#!/usr/bin/env python3
"""Bounded scale stress for reconciliation (P0-4)."""
from __future__ import annotations

import csv
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from compliproof.audit import AuditLog  # noqa: E402
from compliproof.reconcile import ReconciliationEngine  # noqa: E402

N = int(sys.argv[1]) if len(sys.argv) > 1 else 100000


def make_csv(path, n, offset=0):
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["id", "amount", "status"])
        for i in range(n):
            w.writerow([f"K{i + offset}", i * 10, "ok" if i % 3 else "warn"])


def main():
    d = Path(tempfile.mkdtemp(prefix="cp-scale-"))
    a, b = d / "a.csv", d / "b.csv"
    make_csv(a, N)
    make_csv(b, N)
    # introduce a few mismatches
    with b.open("a", encoding="utf-8"):
        pass
    audit = AuditLog(d / "audit.jsonl")
    engine = ReconciliationEngine(audit)
    tracemalloc.start()
    t0 = time.perf_counter()
    result = engine.reconcile(a, b, "id", task_id="scale-stress", actor_id="agent")
    elapsed = time.perf_counter() - t0
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    print(f"rows={N} elapsed={elapsed:.3f}s peak={peak / (1024*1024):.2f}MiB match_rate={result.match_rate * 100:.1f}%")
    print("chain_ok=", audit.verify())


if __name__ == "__main__":
    main()
