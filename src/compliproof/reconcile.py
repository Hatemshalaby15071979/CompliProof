#!/usr/bin/env python3
"""CSV-to-CSV reconciliation engine for the CompliProof prototype.

Matches two CSV exports by a key column on the happy path and returns counts,
row classifications, and a local evidence-pack hash. Duplicate keys, missing
keys, ordering, and large-file behavior are not production-safe. The report
and evidence pack are not audit-grade.

Usage:
    from compliproof.audit import AuditLog
    from compliproof.reconcile import ReconciliationEngine
    engine = ReconciliationEngine(AuditLog(allow_production=True))
    result = engine.reconcile("system_a.csv", "system_b.csv", key_column="id")
    print(result.to_dict())
"""
from __future__ import annotations

import csv
import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .audit import AuditLog
from .evidence import build_evidence_pack


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class ReconciliationResult:
    """Result of reconciling two CSV datasets."""

    task_id: str
    correlation_id: str
    source_a: str
    source_b: str
    key_column: str
    total_a: int
    total_b: int
    matched: int
    only_in_a: int
    only_in_b: int
    mismatched: int
    matched_rows: list[dict] = field(default_factory=list)
    only_in_a_rows: list[dict] = field(default_factory=list)
    only_in_b_rows: list[dict] = field(default_factory=list)
    mismatched_rows: list[dict] = field(default_factory=list)
    evidence_pack: dict | None = None
    match_rate: float = 0.0
    discrepancy_rate: float = 0.0
    timestamp: str = field(default_factory=_now)

    def to_dict(self) -> dict:
        return {
            "task_id": self.task_id,
            "correlation_id": self.correlation_id,
            "source_a": self.source_a,
            "source_b": self.source_b,
            "key_column": self.key_column,
            "total_a": self.total_a,
            "total_b": self.total_b,
            "matched": self.matched,
            "only_in_a": self.only_in_a,
            "only_in_b": self.only_in_b,
            "mismatched": self.mismatched,
            "matched_rows": self.matched_rows,
            "only_in_a_rows": self.only_in_a_rows,
            "only_in_b_rows": self.only_in_b_rows,
            "mismatched_rows": self.mismatched_rows,
            "evidence_pack": self.evidence_pack,
            "match_rate": self.match_rate,
            "discrepancy_rate": self.discrepancy_rate,
            "timestamp": self.timestamp,
        }


def _row_hash(row: dict) -> str:
    """Stable hash of a row's contents for mismatch detection."""
    payload = json.dumps(row, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def _load_csv(path: str | Path) -> list[dict]:
    """Load a CSV file into a list of dicts."""
    rows = []
    with open(path, encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(dict(row))
    return rows


class ReconciliationEngine:
    """Reconciles two CSV datasets and produces an auditable evidence report."""

    def __init__(self, audit_log: AuditLog | None = None):
        self.audit = audit_log or AuditLog()

    def reconcile(
        self,
        source_a: str | Path,
        source_b: str | Path,
        key_column: str,
        task_id: str | None = None,
        correlation_id: str | None = None,
        actor_id: str = "BA",
        source_a_label: str | None = None,
        source_b_label: str | None = None,
    ) -> ReconciliationResult:
        """Reconcile two CSV datasets by key column.

        Returns a ReconciliationResult with matched/only_in_a/only_in_b/
        mismatched rows and builds a locally hashed EvidencePack. The hash is
        not externally anchored and does not cover approval.
        """
        task_id = task_id or f"r-{uuid.uuid4().hex[:8]}"
        correlation_id = correlation_id or f"c-{uuid.uuid4().hex[:8]}"
        source_a_label = source_a_label or str(source_a)
        source_b_label = source_b_label or str(source_b)

        rows_a = _load_csv(source_a)
        rows_b = _load_csv(source_b)

        # Index by key column
        index_a: dict[str, dict] = {}
        for row in rows_a:
            key = row.get(key_column, "")
            index_a[key] = row

        index_b: dict[str, dict] = {}
        for row in rows_b:
            key = row.get(key_column, "")
            index_b[key] = row

        keys_a = set(index_a.keys())
        keys_b = set(index_b.keys())

        matched_keys = keys_a & keys_b
        only_a_keys = keys_a - keys_b
        only_b_keys = keys_b - keys_a

        matched_rows = []
        mismatched_rows = []
        for key in matched_keys:
            row_a = index_a[key]
            row_b = index_b[key]
            hash_a = _row_hash(row_a)
            hash_b = _row_hash(row_b)
            if hash_a == hash_b:
                matched_rows.append(
                    {
                        "key": key,
                        "row_a": row_a,
                        "row_b": row_b,
                        "row_hash": hash_a,
                    }
                )
            else:
                mismatched_rows.append(
                    {
                        "key": key,
                        "row_a": row_a,
                        "row_b": row_b,
                        "hash_a": hash_a,
                        "hash_b": hash_b,
                    }
                )

        only_in_a_rows = [
            {"key": key, "row": index_a[key], "row_hash": _row_hash(index_a[key])}
            for key in only_a_keys
        ]
        only_in_b_rows = [
            {"key": key, "row": index_b[key], "row_hash": _row_hash(index_b[key])}
            for key in only_b_keys
        ]
        match_rate = round(len(matched_rows) / max(len(rows_a), 1), 4)
        discrepancy_rate = round(
            (len(only_in_a_rows) + len(only_in_b_rows) + len(mismatched_rows))
            / max(len(rows_a) + len(rows_b), 1),
            4,
        )

        result = ReconciliationResult(
            task_id=task_id,
            correlation_id=correlation_id,
            source_a=source_a_label,
            source_b=source_b_label,
            key_column=key_column,
            total_a=len(rows_a),
            total_b=len(rows_b),
            matched=len(matched_rows),
            only_in_a=len(only_in_a_rows),
            only_in_b=len(only_in_b_rows),
            mismatched=len(mismatched_rows),
            matched_rows=matched_rows,
            only_in_a_rows=only_in_a_rows,
            only_in_b_rows=only_in_b_rows,
            mismatched_rows=mismatched_rows,
            match_rate=match_rate,
            discrepancy_rate=discrepancy_rate,
        )

        # Build locally hashed evidence pack (not externally anchored)
        steps = [
            {
                "step": "load",
                "actor": actor_id,
                "source": source_a_label,
                "rows": len(rows_a),
                "timestamp": _now(),
            },
            {
                "step": "load",
                "actor": actor_id,
                "source": source_b_label,
                "rows": len(rows_b),
                "timestamp": _now(),
            },
            {
                "step": "reconcile",
                "actor": actor_id,
                "key_column": key_column,
                "matched": len(matched_rows),
                "only_in_a": len(only_in_a_rows),
                "only_in_b": len(only_in_b_rows),
                "mismatched": len(mismatched_rows),
                "timestamp": _now(),
            },
        ]

        pack = build_evidence_pack(
            task_id=task_id,
            correlation_id=correlation_id,
            actor_id=actor_id,
            final_state="reconciled",
            steps=steps,
            evidence_summary={
                "total_a": len(rows_a),
                "total_b": len(rows_b),
                "matched": len(matched_rows),
                "only_in_a": len(only_in_a_rows),
                "only_in_b": len(only_in_b_rows),
                "mismatched": len(mismatched_rows),
                "match_rate": match_rate,
            },
            kpi_summary={
                "match_rate": match_rate,
                "discrepancy_rate": discrepancy_rate,
            },
            approval={
                "status": "pending",
                "actor": actor_id,
                "timestamp": _now(),
            },
        )
        result.evidence_pack = pack.to_dict()

        # Log to audit chain
        self.audit.append(
            "reconciliation.completed",
            actor_id,
            {
                "task_id": task_id,
                "correlation_id": correlation_id,
                "source_a": source_a_label,
                "source_b": source_b_label,
                "key_column": key_column,
                "matched": len(matched_rows),
                "only_in_a": len(only_in_a_rows),
                "only_in_b": len(only_in_b_rows),
                "mismatched": len(mismatched_rows),
                "evidence_pack_sealed": pack.sealed_hash,
            },
        )

        result.evidence_pack = pack.to_dict()
        return result

    def verify_evidence(self, task_id: str) -> bool:
        """Verify the audit chain for a reconciliation task is intact."""
        return self.audit.verify()
