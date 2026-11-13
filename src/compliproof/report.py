#!/usr/bin/env python3
"""Report generator for CompliProof (remediated for P0-4).

v1 behavior (replaces the defective prototype reporter):

- Single canonical metric formula: match_rate = matched / max(total_a,
  total_b, 1); discrepancy_rate = (only_in_a + only_in_b + mismatched) /
  max(total_a + total_b, 1). A perfect 2-vs-2 reconciliation renders
  100.0% directly, in the PDF, and when served over HTTP because the engine
  stores the rate on the result and the report prefers the stored value.
- Task-specific audit trail: the report shows only events whose payload
  carries the report's task_id (never unrelated ledger events), and never
  includes ``report.*`` events so regeneration is stable.
- Reproducible: reports are a deterministic function of (result, task
  events). No wall-clock timestamps are rendered; the generation time shown
  is the reconciliation event time carried on the result.
- Audited: every HTML/PDF/CSV generation writes a ``report.generated``
  event containing the report SHA-256, the evidence-pack hash, and the
  audit head the report was generated against.
- Shared reconstruction: :func:`result_from_audit` rebuilds a full report
  result (totals, rows, pack) from the ledger, and is the single code path
  used by the CLI and the server, guaranteeing identical totals and content.
- CSV export parses with a standard reader and contains real source values.
  Every exported cell is sanitised against spreadsheet formula injection
  (leading ``=``, ``+``, ``-``, ``@``, TAB or CR).

The output is not buyer-ready and does not establish that the report matches
an externally anchored chain.
"""
from __future__ import annotations

import csv
import hashlib
import html
import io
import json
import os
import re
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path
from typing import Any

from reportlab.lib.colors import HexColor, black
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas

from .audit import AuditLog

RECON_EVENT = "reconciliation.completed"
REPORT_EVENT = "report.generated"
RESULT_RETENTION_DAYS = 30
_RESULT_STORE_LOCK = threading.RLock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _esc(s: Any) -> str:
    if s is None:
        return ""
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _pct(numerator: int, denominator: int) -> str:
    if denominator == 0:
        return "0.0%"
    return f"{(numerator / denominator) * 100:.1f}%"


_CSV_INJECTION_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value: Any) -> Any:
    """Neutralise spreadsheet formula injection in one CSV cell.

    A cell is escaped with a leading apostrophe when its first character is
    ``=``, ``+``, ``-``, ``@``, TAB or CR, or when leading whitespace is
    followed by one of ``= + - @``. This is the single cell sanitiser used by
    every CSV export path (:meth:`ReportGenerator.to_csv`).
    """
    if not isinstance(value, str) or not value:
        return value
    if value[0] in _CSV_INJECTION_PREFIXES:
        return "'" + value
    if value.lstrip(" \t\r\n")[:1] in ("=", "+", "-", "@"):
        return "'" + value
    return value


def _rates(result: dict) -> tuple[str, str]:
    """Return (match_rate_str, discrepancy_rate_str) for a result dict.

    Prefers the rates the engine stored on the result; falls back to the
    canonical formula so hand-built results and old ledger payloads render
    identically.
    """
    matched = result.get("matched", 0)
    only_a = result.get("only_in_a", 0)
    only_b = result.get("only_in_b", 0)
    mismatched = result.get("mismatched", 0)
    total_a = result.get("total_a", 0)
    total_b = result.get("total_b", 0)

    if result.get("match_rate") is not None:
        match_rate = f"{float(result['match_rate']) * 100:.1f}%"
    else:
        match_rate = _pct(matched, max(total_a, total_b, 1))
    if result.get("discrepancy_rate") is not None:
        discrepancy_rate = f"{float(result['discrepancy_rate']) * 100:.1f}%"
    else:
        discrepancy_rate = _pct(only_a + only_b + mismatched, max(total_a + total_b, 1))
    return match_rate, discrepancy_rate


def result_from_audit(audit: AuditLog, task_id: str) -> dict | None:
    """Rebuild a full report result from the ledger for a task.

    This is the single reconstruction path used by both the CLI and the HTTP
    server so they always serve identical content. Returns None when no
    reconciliation event exists for the task.
    """
    for e in reversed(audit.tail(10**9)):
        if e.get("_corrupt"):
            continue
        payload = e.get("payload") or {}
        if e.get("type") == RECON_EVENT and payload.get("task_id") == task_id:
            required = {
                "source_a", "source_b", "key_column", "total_a", "total_b",
                "matched", "only_in_a", "only_in_b", "mismatched",
                "matched_rows", "only_in_a_rows", "only_in_b_rows",
                "mismatched_rows", "evidence_pack",
            }
            if not required.issubset(payload):
                return None
            return _result_from_payload(payload, e)
    return None


def _result_path(workspace: Path, task_id: str) -> Path | None:
    if not isinstance(task_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", task_id):
        return None
    digest = hashlib.sha256(task_id.encode("utf-8")).hexdigest()
    return workspace / "results" / f"{digest}.json"


def _read_stored_result(path: Path) -> dict:
    if path.is_symlink():
        raise RuntimeError(f"Result store entry must not be a symlink: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Cannot safely read stored reconciliation result: {path}") from exc
    if (
        not isinstance(data, dict)
        or data.get("schema") != "compliproof.result.v1"
        or not isinstance(data.get("task_id"), str)
        or not isinstance(data.get("created_at"), str)
        or not isinstance(data.get("result"), dict)
        or data["result"].get("task_id") != data["task_id"]
        or not {
            "source_a", "source_b", "key_column", "total_a", "total_b",
            "matched", "only_in_a", "only_in_b", "mismatched",
            "matched_rows", "only_in_a_rows", "only_in_b_rows",
            "mismatched_rows", "evidence_pack",
        }.issubset(data["result"])
    ):
        raise RuntimeError(f"Stored reconciliation result is invalid: {path}")
    try:
        created_at = datetime.fromisoformat(data["created_at"])
        if created_at.tzinfo is None:
            raise ValueError("stored timestamp has no timezone")
    except ValueError as exc:
        raise RuntimeError(f"Stored reconciliation timestamp is invalid: {path}") from exc
    data["_created_at"] = created_at
    return data


def prune_expired_results(
    workspace: str | Path,
    *,
    audit: AuditLog,
    actor_id: str = "system",
    now: datetime | None = None,
) -> int:
    """Delete valid row-level report records older than the 30-day retention."""
    directory = Path(workspace) / "results"
    if not directory.exists():
        return 0
    if directory.is_symlink():
        raise RuntimeError("Result store directory must not be a symlink")
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    cutoff = current - timedelta(days=RESULT_RETENTION_DAYS)
    deleted = 0
    with _RESULT_STORE_LOCK:
        for path in directory.glob("*.json"):
            record = _read_stored_result(path)
            if record["_created_at"] < cutoff:
                path.unlink()
                audit.append(
                    "reconciliation.result.expired",
                    actor_id,
                    {"task_id": record["task_id"]},
                )
                deleted += 1
    return deleted


def save_reconciliation_result(
    workspace: str | Path,
    result: dict,
    *,
    audit: AuditLog,
    actor_id: str,
) -> Path:
    """Persist a result for later reports with private permissions and retention."""
    task_id = result.get("task_id") if isinstance(result, dict) else None
    path = _result_path(Path(workspace), task_id)
    if path is None or result.get("task_id") is None:
        raise ValueError("task_id must contain 1-128 safe filename characters")
    required = {
        "source_a", "source_b", "key_column", "total_a", "total_b",
        "matched", "only_in_a", "only_in_b", "mismatched",
        "matched_rows", "only_in_a_rows", "only_in_b_rows",
        "mismatched_rows", "evidence_pack",
    }
    if not required.issubset(result):
        raise ValueError("result is missing required report fields")
    with _RESULT_STORE_LOCK:
        root = path.parent.parent
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(root, 0o700)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(path.parent, 0o700)
        prune_expired_results(root, audit=audit, actor_id=actor_id)
        envelope = {
            "schema": "compliproof.result.v1",
            "task_id": task_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "result": result,
        }
        fd, temporary = tempfile.mkstemp(prefix=".result.", dir=path.parent)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(envelope, handle, ensure_ascii=False)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        audit.append(
            "reconciliation.result.persisted",
            actor_id,
            {"task_id": task_id, "sha256": digest},
        )
    return path


def load_reconciliation_result(
    workspace: str | Path, task_id: str, *, audit: AuditLog
) -> dict | None:
    """Load a persisted result unless invalid or beyond the 30-day retention."""
    path = _result_path(Path(workspace), task_id)
    if path is None or not path.exists():
        return None
    with _RESULT_STORE_LOCK:
        record = _read_stored_result(path)
        if record["task_id"] != task_id:
            raise RuntimeError(f"Stored reconciliation result does not match task {task_id}")
        if record["_created_at"] < datetime.now(timezone.utc) - timedelta(days=RESULT_RETENTION_DAYS):
            path.unlink()
            audit.append(
                "reconciliation.result.expired",
                "system",
                {"task_id": task_id},
            )
            return None
        if not audit.verify():
            raise RuntimeError("Cannot verify the audit ledger for stored report")
        persisted_event = next(
            (
                event
                for event in reversed(audit.tail(10**9))
                if event.get("type") == "reconciliation.result.persisted"
                and event.get("payload", {}).get("task_id") == task_id
            ),
            None,
        )
        if (
            not persisted_event
            or persisted_event.get("payload", {}).get("sha256")
            != hashlib.sha256(path.read_bytes()).hexdigest()
        ):
            raise RuntimeError(f"Stored reconciliation result integrity check failed: {task_id}")
        return record["result"]


def _result_from_payload(payload: dict, event: dict) -> dict:
    return {
        "task_id": payload.get("task_id", event.get("payload", {}).get("task_id", "")),
        "correlation_id": payload.get("correlation_id", ""),
        "source_a": payload.get("source_a", ""),
        "source_b": payload.get("source_b", ""),
        "key_column": payload.get("key_column", ""),
        "total_a": payload.get("total_a", 0),
        "total_b": payload.get("total_b", 0),
        "matched": payload.get("matched", 0),
        "only_in_a": payload.get("only_in_a", 0),
        "only_in_b": payload.get("only_in_b", 0),
        "mismatched": payload.get("mismatched", 0),
        "match_rate": payload.get("match_rate"),
        "discrepancy_rate": payload.get("discrepancy_rate"),
        "matched_rows": payload.get("matched_rows", []),
        "only_in_a_rows": payload.get("only_in_a_rows", []),
        "only_in_b_rows": payload.get("only_in_b_rows", []),
        "mismatched_rows": payload.get("mismatched_rows", []),
        "evidence_pack": payload.get("evidence_pack", {}),
        # The reconciliation event time is the reproducible "generated" time.
        "timestamp": event.get("ts", ""),
    }


class ReportGenerator:
    """Generates single-file HTML and PDF reconciliation reports, plus CSV.

    Reports are task-specific, reproducible, and audited (report.generated).
    """

    def __init__(self, audit_log: AuditLog | None = None):
        self.audit = audit_log or AuditLog()

    # ── audit plumbing ────────────────────────────────────────────────────────

    def _task_events(self, task_id: str) -> list[dict]:
        """Only events belonging to this task. Excludes report.* events so
        regeneration is stable.
        """
        events = []
        for e in self.audit.tail(10**9):
            if e.get("_corrupt"):
                continue
            payload = e.get("payload") or {}
            if payload.get("task_id") != task_id:
                continue
            if str(e.get("type", "")).startswith("report."):
                continue
            events.append(e)
        return events

    def _audit_report_generation(self, result: dict, content: bytes, fmt: str) -> dict:
        """Write a report.generated event binding the report to the ledger."""
        report_sha = hashlib.sha256(content).hexdigest()
        pack = result.get("evidence_pack") or {}
        event = self.audit.append(
            REPORT_EVENT,
            result.get("actor_id", "compliproof-report"),
            {
                "task_id": result.get("task_id", ""),
                "correlation_id": result.get("correlation_id", ""),
                "format": fmt,
                "report_sha256": report_sha,
                "evidence_pack_sealed_hash": pack.get("sealed_hash", ""),
                "audit_head": self.audit.get_chain_tip(),
            },
        )
        return event

    # ── HTML ──────────────────────────────────────────────────────────────────

    def _css(self) -> str:
        return """
        :root {
          --bg: #f8fafc; --panel: #ffffff; --panel2: #f1f5f9;
          --fg: #0f172a; --muted: #64748b; --accent: #2563eb;
          --accent-hover: #1d4ed8; --ok: #059669; --warn: #d97706;
          --bad: #dc2626; --border: #e2e8f0; --radius: 10px;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
          background: var(--bg); color: var(--fg); line-height: 1.6; padding: 32px;
        }
        .container { max-width: 900px; margin: 0 auto; }
        header { border-bottom: 2px solid var(--border); padding-bottom: 24px; margin-bottom: 32px; }
        .brand { font-size: 24px; font-weight: 700; color: var(--accent); letter-spacing: -0.5px; }
        .brand-sub { font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }
        h1 { font-size: 28px; font-weight: 700; margin-bottom: 8px; color: var(--fg); }
        .subtitle { color: var(--muted); font-size: 16px; }
        .meta-grid { display: flex; gap: 16px; flex-wrap: wrap; margin-top: 16px; }
        .meta-item { background: var(--panel2); border: 1px solid var(--border); border-radius: var(--radius); padding: 10px 14px; font-size: 13px; }
        .meta-item .label { color: var(--muted); font-size: 11px; text-transform: uppercase; }
        .meta-item .value { color: var(--fg); font-weight: 600; }
        .exec-summary { background: var(--panel); border: 1px solid var(--border); border-radius: var(--radius); padding: 24px; margin-bottom: 32px; }
        .exec-summary h2 { font-size: 16px; color: var(--fg); margin-bottom: 16px; }
        .metrics-row { display: flex; gap: 16px; flex-wrap: wrap; }
        .metric { flex: 1; min-width: 140px; background: var(--panel2); border-radius: 8px; padding: 16px; }
        .metric .label { font-size: 11px; color: var(--muted); text-transform: uppercase; }
        .metric .value { font-size: 28px; font-weight: 700; color: var(--fg); margin-top: 4px; }
        .metric .delta { font-size: 12px; margin-top: 2px; }
        .delta.ok { color: var(--ok); }
        .delta.warn { color: var(--warn); }
        .delta.bad { color: var(--bad); }
        .card { background: var(--panel); border: 1px solid var(--border); border-radius: var(--radius); padding: 20px; margin-bottom: 24px; }
        .card h2 { font-size: 16px; color: var(--fg); margin-bottom: 16px; display: flex; align-items: center; gap: 8px; }
        .card h2 .icon { font-size: 14px; }
        .row { background: var(--panel2); border: 1px solid var(--border); border-radius: 8px; padding: 14px 16px; margin-bottom: 12px; display: flex; justify-content: space-between; align-items: flex-start; }
        .row .info { flex: 1; }
        .row .title { font-weight: 600; font-size: 14px; color: var(--fg); }
        .row .meta { color: var(--muted); font-size: 12px; margin-top: 4px; }
        .row .actions { display: flex; gap: 8px; align-items: center; }
        .badge { font-size: 10px; padding: 3px 8px; border-radius: 999px; font-weight: 600; letter-spacing: 0.5px; }
        .badge.ok { background: #ecfdf5; color: var(--ok); }
        .badge.warn { background: #fef3c7; color: var(--warn); }
        .badge.bad { background: #fef2f2; color: var(--bad); }
        .badge.neutral { background: var(--panel); color: var(--muted); }
        pre { background: #0f172a; color: #e2e8f0; border-radius: 8px; padding: 16px; font-size: 11px; overflow-x: auto; margin-top: 12px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
        .hash-display { background: #0f172a; border: 1px solid var(--border); border-radius: 8px; padding: 16px; margin-top: 16px; }
        .hash-label { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; }
        .hash-value { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; color: var(--accent); word-break: break-all; }
        footer { margin-top: 40px; padding-top: 24px; border-top: 1px solid var(--border); color: var(--muted); font-size: 11px; text-align: center; }
        .no-results { color: var(--muted); font-style: italic; padding: 16px; }
        @media print {
          body { background: #ffffff; padding: 0; }
          .card { border: 1px solid #e2e8f0; break-inside: avoid; }
          .row { break-inside: avoid; }
        }
        """

    def _stats_html(self, result: dict) -> str:
        total_a = result.get("total_a", 0)
        total_b = result.get("total_b", 0)
        total = total_a + total_b
        matched = result.get("matched", 0)
        mismatch = result.get("only_in_a", 0) + result.get("only_in_b", 0) + result.get("mismatched", 0)
        match_rate, discrepancy_rate = _rates(result)
        return f"""
        <div class="exec-summary">
          <h2>Executive Summary</h2>
          <div class="metrics-row">
            <div class="metric">
              <div class="label">Match Rate</div>
              <div class="value">{match_rate}</div>
              <div class="delta ok">{matched:,} of {max(total_a, total_b, 1):,} comparable rows</div>
            </div>
            <div class="metric">
              <div class="label">Total Rows Compared</div>
              <div class="value">{total:,}</div>
              <div class="delta">A: {total_a:,} · B: {total_b:,}</div>
            </div>
            <div class="metric">
              <div class="label">Matched</div>
              <div class="value">{matched:,}</div>
              <div class="delta ok">match rate {match_rate}</div>
            </div>
            <div class="metric">
              <div class="label">Discrepancies</div>
              <div class="value">{mismatch:,}</div>
              <div class="delta {'ok' if mismatch == 0 else 'warn'}">{discrepancy_rate} discrepancy rate</div>
            </div>
            <div class="metric">
              <div class="label">Pack Hash Present</div>
              <div class="value">{'✓' if result.get('evidence_pack', {}).get('sealed_hash') else '✗'}</div>
              <div class="delta ok">Local hash only; not externally anchored</div>
            </div>
          </div>
        </div>
        """

    def _rows_html(self, title: str, icon: str, rows: list[dict], row_type: str, badge_class: str, badge_label: str) -> str:
        if not rows:
            return f'<div class="card"><h2><span class="icon">{icon}</span>{title}</h2><div class="no-results">No {badge_label.lower()} found.</div></div>'
        items = ""
        for r in rows:
            key = _esc(r.get("key", ""))
            if row_type == "matched":
                ra = _esc(json.dumps(r.get("row_a", {}), ensure_ascii=False))
                rb = _esc(json.dumps(r.get("row_b", {}), ensure_ascii=False))
                items += f"""
                <div class="row">
                  <div class="info">
                    <div class="title">Key: {key}</div>
                    <div class="meta">Row hash: {_esc(r.get('row_hash', ''))}</div>
                    <div class="meta">A: {ra}</div>
                    <div class="meta">B: {rb}</div>
                  </div>
                  <div class="actions"><span class="badge ok">{badge_label}</span></div>
                </div>
                """
            elif row_type == "only_in_a":
                content = _esc(json.dumps(r.get("row", {}), ensure_ascii=False))
                items += f"""
                <div class="row">
                  <div class="info">
                    <div class="title">Key: {key}</div>
                    <div class="meta">Present in source A only · hash: {_esc(r.get('row_hash', ''))}</div>
                    <div class="meta">A: {content}</div>
                  </div>
                  <div class="actions"><span class="badge warn">{badge_label}</span></div>
                </div>
                """
            elif row_type == "only_in_b":
                content = _esc(json.dumps(r.get("row", {}), ensure_ascii=False))
                items += f"""
                <div class="row">
                  <div class="info">
                    <div class="title">Key: {key}</div>
                    <div class="meta">Present in source B only · hash: {_esc(r.get('row_hash', ''))}</div>
                    <div class="meta">B: {content}</div>
                  </div>
                  <div class="actions"><span class="badge warn">{badge_label}</span></div>
                </div>
                """
            elif row_type == "mismatched":
                ra = _esc(json.dumps(r.get("row_a", {}), ensure_ascii=False))
                rb = _esc(json.dumps(r.get("row_b", {}), ensure_ascii=False))
                items += f"""
                <div class="row">
                  <div class="info">
                    <div class="title">Key: {key}</div>
                    <div class="meta">Hash A: {_esc(r.get('hash_a', ''))} · Hash B: {_esc(r.get('hash_b', ''))}</div>
                    <div class="meta">A: {ra}</div>
                    <div class="meta">B: {rb}</div>
                  </div>
                  <div class="actions"><span class="badge bad">{badge_label}</span></div>
                </div>
                """
        return f'<div class="card"><h2><span class="icon">{icon}</span>{title} ({len(rows)})</h2>{items}</div>'

    def _evidence_html(self, pack: dict) -> str:
        return f"""
        <div class="card">
          <h2><span class="icon">🔐</span>Evidence Pack (prototype)</h2>
          <div class="meta-grid" style="margin-bottom: 16px;">
            <div class="meta-item"><div class="label">Task ID</div><div class="value">{_esc(pack.get('task_id', ''))}</div></div>
            <div class="meta-item"><div class="label">Correlation ID</div><div class="value">{_esc(pack.get('correlation_id', ''))}</div></div>
            <div class="meta-item"><div class="label">Actor</div><div class="value">{_esc(pack.get('actor_id', ''))}</div></div>
            <div class="meta-item"><div class="label">Final State</div><div class="value badge ok">{_esc(pack.get('final_state', ''))}</div></div>
            <div class="meta-item"><div class="label">Approval</div><div class="value">{_esc(json.dumps(pack.get('approval', {}), ensure_ascii=False))}</div></div>
          </div>
          <div class="hash-display">
            <div class="hash-label">Evidence Pack Hash (SHA-256; covers approval; local only)</div>
            <div class="hash-value">{_esc(pack.get('sealed_hash', ''))}</div>
          </div>
          <div style="margin-top: 16px;">
            <details>
              <summary style="cursor: pointer; font-weight: 600; color: var(--accent);">Show full evidence pack JSON</summary>
              <pre>{html.escape(json.dumps(pack, indent=2))}</pre>
            </details>
          </div>
        </div>
        """

    def _audit_trail_html(self, events: list[dict]) -> str:
        items = ""
        for e in events:
            items += f"""
            <div class="row">
              <div class="info">
                <div class="title">{_esc(e.get('type', ''))}</div>
                <div class="meta">Seq #{e.get('seq', '')} · Actor: {_esc(e.get('actor', ''))} · {_esc(e.get('ts', ''))[:16]}</div>
              </div>
              <div class="actions"><span class="badge neutral">{_esc((e.get('payload') or {}).get('decision', '—'))}</span></div>
            </div>
            """
        label = "Task Audit Events" if events else "Task Audit Events (none for this task)"
        return f'<div class="card"><h2><span class="icon">📋</span>{label} ({len(events)} events, task-specific)</h2>{items}</div>'

    def generate_reconciliation_report(self, result: dict) -> str:
        """Generate a deterministic, task-specific HTML report and audit it."""
        pack = result.get("evidence_pack", {})
        audit_events = self._task_events(result.get("task_id", ""))
        generated_ts = result.get("timestamp") or pack.get("timestamp") or _now()
        body = f"""<div class="container">
<div style="background:#fef3c7;border:1px solid #d97706;color:#92400e;padding:10px 14px;border-radius:8px;margin-bottom:18px;font-size:13px;font-weight:600;">
  Prototype report — not audit-grade. The local hash chain is not externally anchored. Do not use this report as compliance evidence.
</div>
<header>
  <div>
    <div class="brand">CompliProof</div>
    <div class="brand-sub">Prototype local reconciliation and evidence-pack tool</div>
  </div>
  <div>
    <h1>Reconciliation Report (prototype)</h1>
    <div class="subtitle">Task {_esc(result.get('task_id', ''))} · Correlation {_esc(result.get('correlation_id', ''))}</div>
    <div class="meta-grid">
      <div class="meta-item"><div class="label">Generated</div><div class="value">{_esc(generated_ts)}</div></div>
      <div class="meta-item"><div class="label">Source A</div><div class="value">{_esc(result.get('source_a', ''))}</div></div>
      <div class="meta-item"><div class="label">Source B</div><div class="value">{_esc(result.get('source_b', ''))}</div></div>
      <div class="meta-item"><div class="label">Key Column</div><div class="value">{_esc(result.get('key_column', ''))}</div></div>
    </div>
  </div>
</header>

{self._stats_html(result)}

{self._rows_html("Matched Rows", "✅", result.get("matched_rows", []), "matched", "ok", "Matched")}
{self._rows_html("Only in Source A", "⚠️", result.get("only_in_a_rows", []), "only_in_a", "warn", "Only in A")}
{self._rows_html("Only in Source B", "⚠️", result.get("only_in_b_rows", []), "only_in_b", "warn", "Only in B")}
{self._rows_html("Mismatched Rows", "❌", result.get("mismatched_rows", []), "mismatched", "bad", "Mismatched")}

{self._evidence_html(pack)}
{self._audit_trail_html(audit_events)}

<footer>
  CompliProof · Prototype reconciliation report · {_esc(generated_ts)} · Evidence pack hash (local): <span style="font-family: ui-monospace; font-size: 11px;">{_esc(pack.get('sealed_hash', ''))}</span> · Local chain: {'OK (not anchored) ⚠️' if self.audit.verify() else 'BROKEN ❌'}
  <div style="margin-top: 12px;">
    <a href="/api/report/{_esc(result.get('task_id', ''))}/pdf" style="display: inline-block; background: var(--accent); color: white; padding: 8px 16px; border-radius: 6px; text-decoration: none; font-size: 13px; font-weight: 600;">Download PDF</a>
  </div>
</footer>
</div>"""
        html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CompliProof — Prototype Reconciliation Report {_esc(result.get('task_id', ''))}</title>
<style>{self._css()}</style>
</head>
<body>
{body}
</body>
</html>"""
        self._audit_report_generation(result, html_doc.encode("utf-8"), "html")
        return html_doc

    # ── PDF ───────────────────────────────────────────────────────────────────

    def to_pdf(self, result: dict) -> bytes:
        """Generate a single-file PDF reconciliation report (task-specific, audited)."""
        pack = result.get("evidence_pack", {})
        audit_events = self._task_events(result.get("task_id", ""))
        total = result.get("total_a", 0) + result.get("total_b", 0)
        matched = result.get("matched", 0)
        mismatch = result.get("only_in_a", 0) + result.get("only_in_b", 0) + result.get("mismatched", 0)
        match_rate, discrepancy_rate = _rates(result)
        generated_ts = result.get("timestamp") or pack.get("timestamp") or _now()

        buf = BytesIO()
        c = canvas.Canvas(buf, pagesize=letter)
        width, height = letter
        margin = 0.75 * inch
        y = height - margin

        # Header
        c.setFont("Helvetica-Bold", 20)
        c.setFillColor(HexColor("#2563eb"))
        c.drawString(margin, y, "CompliProof")
        y -= 24
        c.setFont("Helvetica", 12)
        c.setFillColor(HexColor("#64748b"))
        c.drawString(margin, y, "Prototype local reconciliation and evidence-pack tool")
        y -= 12
        c.setFont("Helvetica-Bold", 16)
        c.setFillColor(black)
        c.drawString(margin, y, "Reconciliation Report (prototype)")
        y -= 14
        c.setFont("Helvetica-Bold", 9)
        c.setFillColor(HexColor("#b45309"))
        c.drawString(margin, y, "PROTOTYPE — not audit-grade; local hash only; not externally anchored.")
        y -= 14
        c.setFont("Helvetica", 11)
        c.setFillColor(black)
        c.drawString(margin, y, f"Task {result.get('task_id', '')} · Correlation {result.get('correlation_id', '')}")
        y -= 10
        c.setFont("Helvetica", 9)
        c.drawString(margin, y, f"Generated {generated_ts}")
        y -= 20

        # Executive Summary
        c.setFont("Helvetica-Bold", 13)
        c.setFillColor(black)
        c.drawString(margin, y, "Executive Summary")
        y -= 8
        c.setFillColor(HexColor("#059669") if mismatch == 0 else HexColor("#d97706"))
        c.drawString(margin, y, f"Match rate: {match_rate}   Discrepancy rate: {discrepancy_rate}")
        y -= 8
        c.setFillColor(black)
        c.drawString(margin, y, f"Total rows compared: {total:,}")
        y -= 8
        c.drawString(
            margin,
            y,
            f"Matched: {matched:,} · Only in A: {result.get('only_in_a', 0):,} · "
            f"Only in B: {result.get('only_in_b', 0):,} · Mismatched: {result.get('mismatched', 0):,}",
        )
        y -= 16

        # Matched Rows
        result_rows = result.get("matched_rows", [])
        c.setFont("Helvetica-Bold", 12)
        c.drawString(margin, y, "Matched Rows")
        y -= 12
        for row in result_rows:
            c.setFillColor(black)
            c.drawString(margin + 12, y, f"Key: {row.get('key', '')}")
            y -= 10
            c.setFillColor(HexColor("#059669"))
            c.drawString(margin + 24, y, f"Hash: {row.get('row_hash', '')}")
            y -= 10
        y -= 6

        # Only in Source A
        result_only_a = result.get("only_in_a_rows", [])
        c.setFont("Helvetica-Bold", 12)
        c.drawString(margin, y, "Only in Source A")
        y -= 12
        for row in result_only_a:
            c.setFillColor(black)
            c.drawString(margin + 12, y, f"Key: {row.get('key', '')}")
            y -= 10
            c.setFillColor(HexColor("#d97706"))
            c.drawString(margin + 24, y, f"Hash: {row.get('row_hash', '')}")
            y -= 10
        y -= 6

        # Only in Source B
        result_only_b = result.get("only_in_b_rows", [])
        c.setFont("Helvetica-Bold", 12)
        c.drawString(margin, y, "Only in Source B")
        y -= 12
        for row in result_only_b:
            c.setFillColor(black)
            c.drawString(margin + 12, y, f"Key: {row.get('key', '')}")
            y -= 10
            c.setFillColor(HexColor("#d97706"))
            c.drawString(margin + 24, y, f"Hash: {row.get('row_hash', '')}")
            y -= 10
        y -= 6

        # Mismatched Rows
        result_mismatched = result.get("mismatched_rows", [])
        c.setFont("Helvetica-Bold", 12)
        c.drawString(margin, y, "Mismatched Rows")
        y -= 12
        for row in result_mismatched:
            c.setFillColor(black)
            c.drawString(margin + 12, y, f"Key: {row.get('key', '')}")
            y -= 10
            c.setFillColor(HexColor("#dc2626"))
            c.drawString(margin + 24, y, f"Hash A: {row.get('hash_a', '')}")
            y -= 10
            c.drawString(margin + 24, y, f"Hash B: {row.get('hash_b', '')}")
            y -= 14
        y -= 6

        # Evidence pack
        c.setFont("Helvetica-Bold", 12)
        c.drawString(margin, y, "Evidence Pack (prototype)")
        y -= 12
        c.setFillColor(black)
        c.drawString(margin + 12, y, f"Task ID: {pack.get('task_id', '')}")
        y -= 10
        c.drawString(margin + 12, y, f"Actor: {pack.get('actor_id', '')}")
        y -= 10
        c.drawString(margin + 12, y, f"Final State: {pack.get('final_state', '')}")
        y -= 10
        c.drawString(margin + 12, y, f"Evidence Pack Hash (local): {pack.get('sealed_hash', '')}")
        y -= 16

        # Task audit events
        c.setFont("Helvetica-Bold", 12)
        c.drawString(margin, y, "Task Audit Events (prototype)")
        y -= 12
        for e in audit_events[:10]:
            c.setFillColor(black)
            c.drawString(margin + 12, y, f"#{e.get('seq', '')}  {e.get('type', '')}  {e.get('actor', '')}  {str(e.get('ts', ''))[:16]}")
            y -= 10
        y -= 8

        c.showPage()
        c.save()
        pdf_bytes = buf.getvalue()
        self._audit_report_generation(result, pdf_bytes, "pdf")
        return pdf_bytes

    # ── CSV ───────────────────────────────────────────────────────────────────

    def to_csv(self, result: dict) -> str:
        """CSV export: data rows (real source values) + a summary section.

        Parses with a standard csv reader.
        """
        cols_a: set[str] = set()
        cols_b: set[str] = set()
        for r in result.get("matched_rows", []) + result.get("mismatched_rows", []):
            cols_a |= set((r.get("row_a") or {}).keys())
            cols_b |= set((r.get("row_b") or {}).keys())
        for r in result.get("only_in_a_rows", []):
            cols_a |= set((r.get("row") or {}).keys())
        for r in result.get("only_in_b_rows", []):
            cols_b |= set((r.get("row") or {}).keys())
        cols_a.discard(None)
        cols_b.discard(None)

        fieldnames = (
            ["key", "status"]
            + [f"a_{c}" for c in sorted(cols_a)]
            + [f"b_{c}" for c in sorted(cols_b)]
            + ["summary_value"]
        )
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()

        def emit(status: str, key: str, row_a: dict | None, row_b: dict | None):
            out = {"key": _csv_safe(key), "status": status}
            if row_a:
                for c in cols_a:
                    if c in row_a:
                        out[f"a_{c}"] = _csv_safe(row_a[c])
            if row_b:
                for c in cols_b:
                    if c in row_b:
                        out[f"b_{c}"] = _csv_safe(row_b[c])
            w.writerow(out)

        for r in result.get("matched_rows", []):
            emit("matched", r.get("key", ""), r.get("row_a"), r.get("row_b"))
        for r in result.get("only_in_a_rows", []):
            emit("only_in_a", r.get("key", ""), r.get("row"), None)
        for r in result.get("only_in_b_rows", []):
            emit("only_in_b", r.get("key", ""), None, r.get("row"))
        for r in result.get("mismatched_rows", []):
            emit("mismatched", r.get("key", ""), r.get("row_a"), r.get("row_b"))

        total_a = result.get("total_a", 0)
        total_b = result.get("total_b", 0)
        match_rate, discrepancy_rate = _rates(result)
        pack = result.get("evidence_pack") or {}
        summary = {
            "total_a": total_a,
            "total_b": total_b,
            "matched": result.get("matched", 0),
            "only_in_a": result.get("only_in_a", 0),
            "only_in_b": result.get("only_in_b", 0),
            "mismatched": result.get("mismatched", 0),
            "match_rate": match_rate,
            "discrepancy_rate": discrepancy_rate,
            "key_column": result.get("key_column", ""),
            "evidence_pack_sealed_hash": pack.get("sealed_hash", ""),
            "protocol": "prototype, not audit-grade; local hash only",
        }
        for name, val in summary.items():
            w.writerow({"key": name, "status": "summary", "summary_value": _csv_safe(val)})

        csv_text = buf.getvalue()
        self._audit_report_generation(result, csv_text.encode("utf-8"), "csv")
        return csv_text

    def save(self, html: str, path: str | Path) -> Path:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(html, encoding="utf-8")
        return p
