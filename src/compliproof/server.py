#!/usr/bin/env python3
"""CompliProof standard-library HTTP dashboard.

The service is intended to run as one customer-hosted instance behind a
TLS-terminating reverse proxy. It is not a multi-tenant SaaS service.

Endpoints:
    GET  /                    serve dashboard HTML
    GET  /api/status          system state JSON
    GET  /api/tasks           reconciliation tasks
    GET  /api/audit           audit trail tail
    GET  /api/reports         generated reports
    POST /api/reconcile       reconcile two CSVs (multipart upload)
    POST /api/tasks/done      mark a task as done
    POST /api/tasks/add       add a new task
    GET  /api/report/{task_id} HTML reconciliation report (prototype)
    GET  /api/daily-card      daily card summary (tasks + audit)
    GET  /api/models          Ollama models available
    POST /api/chat            chat with Ollama (SSE stream)
    GET  /daily-card          daily card HTML page

Usage:
    python -m compliproof.server          # start on 127.0.0.1:8200
    python -m compliproof.server --port 9000
    python -m compliproof.server --allow-registration  # loopback bootstrap only

Registration is disabled by default.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import ssl
import sys
import sysconfig
import tempfile
import threading
import time
import urllib.request
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional

BASE = Path(__file__).resolve().parent.parent.parent
WORKSPACE = Path(os.environ.get("COMPLIPROOF_WORKSPACE", str(BASE / "workspace")))
DASHBOARD = BASE / "dashboard" / "home.html"
if not DASHBOARD.is_file():
    DASHBOARD = (
        Path(sysconfig.get_path("data"))
        / "share"
        / "compliproof"
        / "dashboard"
        / "home.html"
    )
TASKS_FILE = WORKSPACE / "tasks.json"
AUDIT_FILE = WORKSPACE / "audit_events.jsonl"
REPORTS_DIR = WORKSPACE / "reports"
OLLAMA_URL = "http://localhost:11434"
PORT = 8200

sys.path.insert(0, str(BASE / "src"))
from compliproof.audit import AuditLog  # noqa: E402
from compliproof.auth import AuthManager  # noqa: E402
from compliproof.reconcile import ReconciliationEngine  # noqa: E402
from compliproof.security import (  # noqa: E402
    is_loopback,
    open_http_url,
    registration_enabled,
    session_cookie,
)

log = AuditLog(AUDIT_FILE, allow_production=True)
engine = ReconciliationEngine(log)
auth = AuthManager(str(WORKSPACE))
_state_lock = threading.RLock()
_LOGIN_LIMIT = 5
_LOGIN_WINDOW_SECONDS = 900
_ROLE_PERMISSIONS = {
    "owner": {"read", "operate", "admin", "audit"},
    "approver": {"read", "operate", "approve", "audit"},
    "operator": {"read", "operate"},
    "auditor": {"read", "audit"},
    "viewer": {"read"},
}
_WRITE_PERMISSION = {
    "/api/reconcile": "operate",
    "/api/tasks/done": "operate",
    "/api/tasks/add": "operate",
    "/api/finance": "admin",
    "/api/pipeline": "admin",
    "/api/chat": "read",
    "/api/auth/logout": "read",
}


def _json_response(handler, data, status=200):
    body = json.dumps(data, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(body)


def _cookie_secure(handler) -> bool:
    """Return True when the request arrived over a direct TLS connection."""
    return isinstance(getattr(handler, "connection", None), ssl.SSLSocket)


def _set_session_cookie(handler, token: str, max_age: int = 43200) -> None:
    secure_override = os.environ.get("COMPLIPROOF_SECURE_COOKIES", "").strip().lower() in {
        "1", "true", "yes"
    }
    handler.send_header(
        "Set-Cookie",
        session_cookie(token, secure=_cookie_secure(handler) or secure_override, max_age=max_age),
    )


def _read_body(handler) -> dict:
    return getattr(handler, "_request_body", {})


def _parse_request_body(handler) -> dict:
    if handler.headers.get("Transfer-Encoding"):
        raise TypeError("Transfer-Encoding is not supported")
    try:
        length = int(handler.headers.get("Content-Length", "0"))
    except ValueError as exc:
        raise ValueError("invalid Content-Length") from exc
    if length < 0 or length > 5 * 1024 * 1024:
        raise OverflowError("request body exceeds 5 MiB")
    if length == 0:
        return {}
    if handler.headers.get_content_type() != "application/json":
        raise TypeError("Content-Type must be application/json")
    try:
        data = json.loads(handler.rfile.read(length).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("request body must be valid JSON") from exc
    if not isinstance(data, dict):
        raise ValueError("request body must be a JSON object")
    return data


def _state_summary() -> dict:
    tasks = _load_tasks()
    open_n = len([t for t in tasks if t.get("status") != "done"])
    done_n = len([t for t in tasks if t.get("status") == "done"])
    return {
        "open": open_n,
        "done": done_n,
        "audit_events": log.count(),
        "audit_chain_ok": log.verify(),
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def _write_json_state(path: Path, data: dict | list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, ensure_ascii=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _daily_card() -> dict:
    """Build the daily card: tasks + audit events grouped by status."""
    tasks = _load_tasks()
    open_tasks = [t for t in tasks if t.get("status") != "done"]
    done_tasks = [t for t in tasks if t.get("status") == "done"]

    # Today's wins: tasks completed today
    today = datetime.now(timezone.utc).date().isoformat()
    today_wins = [
        t for t in done_tasks
        if t.get("completed", "").startswith(today)
    ]

    # Recent audit events (last 10)
    audit_events = log.tail(10)

    # Finance summary
    mrr = 0
    leads = 0
    finance_file = WORKSPACE / "finance" / "finance.json"
    if finance_file.exists():
        try:
            finance = json.loads(finance_file.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Finance summary is unavailable or invalid") from exc
        if not isinstance(finance, dict):
            raise ValueError("Finance summary must be a JSON object")
        mrr = finance.get("mrr", 0)

    pipeline_file = WORKSPACE / "pipeline" / "pipeline.json"
    if pipeline_file.exists():
        try:
            pipeline = json.loads(pipeline_file.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Pipeline summary is unavailable or invalid") from exc
        if not isinstance(pipeline, list):
            raise ValueError("Pipeline summary must be a JSON array")
        leads = len(pipeline)

    return {
        "date": today,
        "open_tasks": open_tasks,
        "done_tasks": done_tasks,
        "today_wins": today_wins,
        "audit_events": audit_events,
        "audit_chain_ok": log.verify(),
        "mrr": mrr,
        "leads": leads,
    }


def _render_daily_card_html(card: dict) -> str:
    """Render the daily card as a single-file HTML page."""
    def esc(value):
        return (
            str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            if value
            else ""
        )

    open_tasks_html = ""
    for t in card["open_tasks"]:
        open_tasks_html += f"""
        <div class="task">
          <div class="task-title">{esc(t.get('title', ''))}</div>
          <div class="task-meta">
            <span class="badge owner">{esc(t.get('owner', 'NONE'))}</span>
            <span class="badge due">{esc(t.get('due', ''))}</span>
            <span class="badge est">{esc(f"~{t.get('estimate_min', '?')}min") if t.get('estimate_min') else ''}</span>
          </div>
          {f'<div class="task-next">→ {esc(t.get("next_step", ""))}</div>' if t.get('next_step') else ''}
        </div>
        """

    wins_html = ""
    for t in card["today_wins"]:
        wins_html += f'<div class="win">+ {esc(t.get("title", ""))}</div>'

    audit_html = ""
    for e in card["audit_events"]:
        audit_html += f"""
        <div class="event">
          <span class="badge seq">#{e.get('seq', '')}</span>
          <span class="badge actor">{esc(e.get('actor', ''))}</span>
          <span class="time">{esc(e.get('ts', ''))[:16]}</span>
          <span class="type">{esc(e.get('type', ''))}</span>
        </div>
        """

    css = """
    :root { --bg: #0f1115; --panel: #181b22; --panel2: #1f232c; --fg: #e6e8ec; --muted: #8a90a0; --accent: #5b8def; --ok: #3dd68c; --warn: #f5a623; --bad: #ff5c5c; --border: #2a2f3a; --radius: 12px; }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--fg); line-height: 1.5; padding: 24px; }
    header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
    h1 { font-size: 20px; }
    .sub { color: var(--muted); font-size: 12px; }
    .stats { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 20px; }
    .stat { background: var(--panel2); border-radius: 8px; padding: 6px 12px; font-size: 12px; }
    .stat b { color: var(--accent); }
    .card { background: var(--panel); border: 1px solid var(--border); border-radius: var(--radius); padding: 16px; margin-bottom: 16px; }
    .card h2 { font-size: 12px; text-transform: uppercase; letter-spacing: 1px; color: var(--muted); margin: 0 0 12px; }
    .task { background: var(--panel2); border: 1px solid var(--border); border-radius: 8px; padding: 10px 12px; margin-bottom: 8px; }
    .task-title { font-weight: 600; font-size: 14px; }
    .task-meta { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 4px; font-size: 11px; color: var(--muted); }
    .badge { font-size: 10px; padding: 1px 6px; border-radius: 999px; background: var(--panel); color: var(--muted); }
    .badge.owner { color: var(--accent); }
    .badge.due { color: var(--warn); }
    .badge.seq { color: var(--muted); }
    .badge.actor { color: var(--accent2); }
    .task-next { font-size: 12px; color: var(--muted); margin-top: 4px; }
    .win { color: var(--ok); font-size: 12px; padding: 2px 0; }
    .event { background: var(--panel2); border: 1px solid var(--border); border-radius: 8px; padding: 8px 12px; margin-bottom: 6px; font-size: 12px; }
    .empty { color: var(--muted); font-size: 12px; font-style: italic; padding: 6px 0; }
    footer { color: var(--muted); font-size: 11px; margin-top: 24px; text-align: center; }
    .nav { margin-bottom: 16px; }
    .nav a { color: var(--accent); text-decoration: none; margin-right: 16px; font-size: 13px; }
    .nav a:hover { text-decoration: underline; }
    """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CompliProof — Daily Card {card['date']}</title>
<style>{css}</style>
</head>
<body>
<header>
  <div class="nav">
    <a href="/">Dashboard</a>
    <a href="/api/tasks">Tasks</a>
    <a href="/api/audit">Audit</a>
  </div>
  <div>
    <h1>Daily Card — {esc(card['date'])}</h1>
    <div class="sub">CompliProof · solo software OS · audit chain {'OK ✅' if card['audit_chain_ok'] else 'BROKEN ❌'}</div>
  </div>
</header>

<div class="stats">
  <div class="stat"><b>{len(card['open_tasks'])}</b> open tasks</div>
  <div class="stat"><b>{len(card['done_tasks'])}</b> done</div>
  <div class="stat"><b>{len(card['today_wins'])}</b> wins today</div>
  <div class="stat"><b>${card['mrr']:,}</b> MRR</div>
  <div class="stat"><b>{card['leads']}</b> leads</div>
</div>

<div class="card">
  <h2>Next Action</h2>
  {open_tasks_html if open_tasks_html else '<div class="empty">No open tasks. Nice work!</div>'}
</div>

<div class="card">
  <h2>Wins Today</h2>
  {wins_html if wins_html else '<div class="empty">No wins yet. Ship something!</div>'}
</div>

<div class="card">
  <h2>Recent Audit Events</h2>
  {audit_html if audit_html else '<div class="empty">No audit events.</div>'}
</div>

<footer>
  CompliProof · {card['date']} · Audit chain: {'OK' if card['audit_chain_ok'] else 'BROKEN'}
</footer>
</body>
</html>"""


def _load_tasks() -> list[dict]:
    if not TASKS_FILE.exists():
        return []
    try:
        data = json.loads(TASKS_FILE.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Tasks are unavailable or invalid") from exc
    if not isinstance(data, dict) or not isinstance(data.get("tasks"), list):
        raise ValueError("Tasks store must contain a tasks array")
    if not all(isinstance(task, dict) for task in data["tasks"]):
        raise ValueError("Tasks store contains an invalid task")
    return data["tasks"]


def _save_tasks(tasks: list[dict]) -> None:
    data = {"schema": "tasks.v1", "updated": datetime.now(timezone.utc).isoformat(timespec="seconds"), "tasks": tasks}
    _write_json_state(TASKS_FILE, data)


def _get_current_user(handler) -> Optional[dict]:
    """Get the current authenticated user from session cookie."""
    cookie_header = handler.headers.get("Cookie", "")
    for cookie in cookie_header.split(";"):
        cookie = cookie.strip()
        if cookie.startswith("session="):
            token = cookie.split("=", 1)[1]
            return auth.get_current_user(token)
    return None


def _require_auth(handler) -> Optional[dict]:
    """Check authentication, send 401 if not authenticated."""
    user = _get_current_user(handler)
    if not user:
        _json_response(handler, {"error": "authentication required"}, status=401)
    return user


def _require_permission(handler, user: dict, permission: str) -> bool:
    if permission in _ROLE_PERMISSIONS.get(user.get("role"), set()):
        return True
    _json_response(handler, {"error": "forbidden"}, status=403)
    return False


def _session_token(handler) -> str:
    for cookie in handler.headers.get("Cookie", "").split(";"):
        name, separator, value = cookie.strip().partition("=")
        if separator and name == "session":
            return value
    return ""


def _valid_login_rate(key: str) -> bool:
    """Persist login throttling across requests and worker processes.

    Only a digest of the IP/username key is stored. SQLite's immediate write
    transaction serializes concurrent workers and the file is mode-restricted.
    """
    now = time.time()
    key_hash = hashlib.sha256(key.encode("utf-8")).hexdigest()
    rate_file = WORKSPACE / "login_attempts.sqlite3"
    rate_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with sqlite3.connect(rate_file, timeout=10, isolation_level=None) as db:
        db.execute("PRAGMA busy_timeout=10000")
        db.execute(
            "CREATE TABLE IF NOT EXISTS attempts ("
            "key_hash TEXT PRIMARY KEY, attempts INTEGER NOT NULL, started REAL NOT NULL)"
        )
        db.execute("BEGIN IMMEDIATE")
        db.execute("DELETE FROM attempts WHERE started <= ?", (now - _LOGIN_WINDOW_SECONDS,))
        row = db.execute(
            "SELECT attempts FROM attempts WHERE key_hash = ?", (key_hash,)
        ).fetchone()
        attempts = row[0] if row else 0
        if attempts >= _LOGIN_LIMIT:
            db.execute("COMMIT")
            os.chmod(rate_file, 0o600)
            return False
        if row:
            db.execute(
                "UPDATE attempts SET attempts = attempts + 1 WHERE key_hash = ?",
                (key_hash,),
            )
        else:
            db.execute(
                "INSERT INTO attempts(key_hash, attempts, started) VALUES (?, 1, ?)",
                (key_hash, now),
            )
        db.execute("COMMIT")
    os.chmod(rate_file, 0o600)
    return True


def _clear_login_rate(key: str) -> None:
    rate_file = WORKSPACE / "login_attempts.sqlite3"
    if not rate_file.exists():
        return
    key_hash = hashlib.sha256(key.encode("utf-8")).hexdigest()
    with sqlite3.connect(rate_file, timeout=10, isolation_level=None) as db:
        db.execute("BEGIN IMMEDIATE")
        db.execute("DELETE FROM attempts WHERE key_hash = ?", (key_hash,))
        db.execute("COMMIT")


def _report_result(task_id: str) -> dict | None:
    from compliproof.report import load_reconciliation_result, result_from_audit

    return load_reconciliation_result(WORKSPACE, task_id, audit=log) or result_from_audit(log, task_id)


def _result_retention_worker() -> None:
    from compliproof.report import prune_expired_results

    while True:
        try:
            prune_expired_results(WORKSPACE, audit=log)
        except (OSError, RuntimeError, ValueError) as exc:
            print(f"ERROR: result retention cleanup failed: {exc}", file=sys.stderr)
        time.sleep(3600)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, _fmt, *_args):
        pass

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; connect-src 'self'; "
            "img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'",
        )
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(405)
        self.send_header("Allow", "GET, POST")
        self.end_headers()

    def do_GET(self):
        path = self.path.split("?")[0]
        user = None
        if path not in {"/", "/api/healthz"}:
            user = _require_auth(self)
            if not user:
                return
            permission = "read"
            if path == "/api/audit":
                permission = "audit"
            elif path in {"/api/finance", "/api/pipeline", "/api/daily-card", "/daily-card"}:
                permission = "admin"
            if not _require_permission(self, user, permission):
                return
        if path == "/":
            if DASHBOARD.exists():
                body = DASHBOARD.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_response(404)
                self.end_headers()
        elif path == "/api/healthz":
            _json_response(self, {"ok": True})
        elif path == "/api/status":
            try:
                _json_response(self, _state_summary())
            except ValueError:
                _json_response(self, {"error": "status unavailable"}, status=503)
        elif path == "/api/tasks":
            try:
                _json_response(self, {"tasks": _load_tasks()})
            except ValueError:
                _json_response(self, {"error": "tasks unavailable"}, status=503)
        elif path == "/api/audit":
            _json_response(self, {"events": log.tail(20), "chain_ok": log.verify(), "count": log.count()})
        elif path == "/api/reports":
            reports = []
            if REPORTS_DIR.exists():
                for f in sorted(REPORTS_DIR.glob("*.html"), reverse=True)[:20]:
                    reports.append({"name": f.name})
            _json_response(self, {"reports": reports})
        elif path == "/api/pipeline":
            PIPELINE_FILE = WORKSPACE / "pipeline" / "pipeline.json"
            if PIPELINE_FILE.exists():
                try:
                    data = json.loads(PIPELINE_FILE.read_text(encoding="utf-8"))
                except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                    _json_response(self, {"error": "pipeline unavailable"}, status=503)
                    return
                if not isinstance(data, list) or not all(isinstance(item, dict) for item in data):
                    _json_response(self, {"error": "pipeline data is invalid"}, status=503)
                    return
            else:
                data = []
            _json_response(self, {"leads": data})
        elif path == "/api/daily-card":
            try:
                _json_response(self, _daily_card())
            except (OSError, ValueError):
                _json_response(self, {"error": "daily summary unavailable"}, status=503)
        elif path == "/daily-card":
            try:
                card = _daily_card()
            except (OSError, ValueError):
                self.send_response(503)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"<h1>Daily summary unavailable</h1>")
                return
            html = _render_daily_card_html(card)
            body = html.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/api/models":
            try:
                req = open_http_url(f"{OLLAMA_URL}/api/tags", timeout=5)
                data = json.loads(req.read())
                models = data.get("models")
                if not isinstance(models, list) or not all(
                    isinstance(model, dict) and isinstance(model.get("name"), str)
                    for model in models
                ):
                    raise ValueError("invalid model response")
            except (OSError, ValueError, json.JSONDecodeError):
                _json_response(self, {"error": "model service unavailable"}, status=503)
            else:
                _json_response(self, {"models": [model["name"] for model in models]})
        elif path == "/api/finance":
            FINANCE_FILE = WORKSPACE / "finance" / "finance.json"
            if FINANCE_FILE.exists():
                try:
                    data = json.loads(FINANCE_FILE.read_text(encoding="utf-8"))
                except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                    _json_response(self, {"error": "finance data unavailable"}, status=503)
                    return
                if not isinstance(data, dict):
                    _json_response(self, {"error": "finance data is invalid"}, status=503)
                    return
            else:
                data = {}
            _json_response(self, data)
        elif path == "/api/auth/me":
            token = _session_token(self)
            _json_response(
                self,
                {"user": AuthManager.public_user(user), "csrf_token": auth.session_csrf(token)},
            )
        elif path.startswith("/api/report/") and path.endswith("/pdf"):
            task_id = path.split("/")[-2]
            try:
                result = _report_result(task_id)
            except RuntimeError:
                _json_response(self, {"error": "stored report is unavailable"}, status=503)
                return
            if result is None:
                self.send_response(404)
                self.end_headers()
                return
            from compliproof.report import ReportGenerator
            gen = ReportGenerator(log)
            pdf_bytes = gen.to_pdf(result)
            body = pdf_bytes
            self.send_response(200)
            self.send_header("Content-Type", "application/pdf")
            self.send_header("Content-Disposition", f'attachment; filename="compliproof_{task_id}.pdf"')
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path.startswith("/api/report/") and path.endswith("/csv"):
            task_id = path.split("/")[-2]
            try:
                result = _report_result(task_id)
            except RuntimeError:
                _json_response(self, {"error": "stored report is unavailable"}, status=503)
                return
            if result is None:
                self.send_response(404)
                self.end_headers()
                return
            from compliproof.report import ReportGenerator
            gen = ReportGenerator(log)
            csv_data = gen.to_csv(result)
            body = csv_data.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/csv; charset=utf-8")
            self.send_header("Content-Disposition", f'attachment; filename="compliproof_{task_id}.csv"')
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path.startswith("/api/report/"):
            task_id = path.removeprefix("/api/report/")
            if not task_id or "/" in task_id:
                self.send_response(404)
                self.end_headers()
                return
            from compliproof.report import ReportGenerator
            try:
                result = _report_result(task_id)
            except RuntimeError:
                _json_response(self, {"error": "stored report is unavailable"}, status=503)
                return
            if result is None:
                self.send_response(404)
                self.end_headers()
                return
            gen = ReportGenerator(log)
            html = gen.generate_reconciliation_report(result)
            body = html.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        path = self.path.split("?")[0]
        user = None
        if path not in {"/api/auth/login", "/api/auth/register"}:
            user = _require_auth(self)
            if not user:
                return
            permission = _WRITE_PERMISSION.get(path, "operate")
            if not _require_permission(self, user, permission):
                return
            if not auth.csrf_valid(_session_token(self), self.headers.get("X-CSRF-Token", "")):
                _json_response(self, {"error": "CSRF token missing or invalid"}, status=403)
                return
        try:
            self._request_body = _parse_request_body(self)
        except OverflowError as exc:
            _json_response(self, {"error": str(exc)}, status=413)
            return
        except (TypeError, ValueError) as exc:
            _json_response(self, {"error": str(exc)}, status=400)
            return
        if path == "/api/reconcile":
            body = _read_body(self)
            content_a = body.get("file_a_content", "")
            content_b = body.get("file_b_content", "")
            key_column = body.get("key_column", "id")
            task_id = body.get("task_id", None)
            source_a_name = body.get("source_a_name", "Source A")
            source_b_name = body.get("source_b_name", "Source B")
            actor_id = user["id"]
            if task_id is not None and (
                not isinstance(task_id, str)
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", task_id)
            ):
                _json_response(self, {"error": "invalid task_id"}, status=400)
                return

            if (
                not isinstance(content_a, str) or not content_a
                or not isinstance(content_b, str) or not content_b
                or not isinstance(key_column, str) or not key_column
                or not isinstance(source_a_name, str) or len(source_a_name) > 255
                or not isinstance(source_b_name, str) or len(source_b_name) > 255
            ):
                _json_response(self, {"error": "invalid reconciliation input"}, 400)
                return
            source_a_name = Path(source_a_name.replace("\\", "/")).name or "Source A"
            source_b_name = Path(source_b_name.replace("\\", "/")).name or "Source B"

            WORKSPACE.mkdir(parents=True, exist_ok=True, mode=0o700)
            with tempfile.TemporaryDirectory(prefix=".reconcile-", dir=WORKSPACE) as temp_dir:
                path_a = Path(temp_dir) / "source_a.csv"
                path_b = Path(temp_dir) / "source_b.csv"
                path_a.write_text(content_a, encoding="utf-8")
                path_b.write_text(content_b, encoding="utf-8")
                result = engine.reconcile(
                    path_a,
                    path_b,
                    key_column,
                    task_id=task_id,
                    actor_id=actor_id,
                    source_a_label=source_a_name,
                    source_b_label=source_b_name,
                )
            from compliproof.report import save_reconciliation_result
            try:
                save_reconciliation_result(
                    WORKSPACE, result.to_dict(), audit=log, actor_id=actor_id
                )
            except (OSError, RuntimeError, ValueError):
                log.append(
                    "reconciliation.result_persistence_failed",
                    actor_id,
                    {"task_id": result.task_id},
                )
                _json_response(self, {"error": "reconciliation result could not be stored"}, 503)
                return
            _json_response(self, {"ok": True, "result": result.to_dict()})
        elif path == "/api/tasks/done":
            body = _read_body(self)
            task_id = body.get("id")
            with _state_lock:
                try:
                    tasks = _load_tasks()
                except ValueError:
                    _json_response(self, {"error": "tasks unavailable"}, status=503)
                    return
                found = False
                for t in tasks:
                    if t.get("id") == task_id:
                        t["status"] = "done"
                        t["completed"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
                        found = True
                        break
                if found:
                    _save_tasks(tasks)
            if not found:
                _json_response(self, {"error": "task not found"}, 404)
                return
            log.append("task.completed", user["id"], {"id": task_id})
            _json_response(self, {"ok": True, "id": task_id})
        elif path == "/api/tasks/add":
            body = _read_body(self)
            with _state_lock:
                try:
                    tasks = _load_tasks()
                except ValueError:
                    _json_response(self, {"error": "tasks unavailable"}, status=503)
                    return
                new_id = f"t-{uuid.uuid4().hex[:8]}"
                new_task = {
                    "id": new_id,
                    "title": body.get("title", "Untitled"),
                    "owner": body.get("owner", "BA"),
                    "due": body.get("due") or datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                    "estimate_min": body.get("estimate_min", 30),
                    "status": "todo",
                    "next_step": body.get("next_step", ""),
                    "blocker": body.get("blocker", None),
                    "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "completed": None,
                    "tags": body.get("tags", []),
                }
                tasks.append(new_task)
                _save_tasks(tasks)
            log.append("task.created", user["id"], {"id": new_id, "title": new_task["title"]})
            _json_response(self, {"ok": True, "task": new_task})
        elif path == "/api/finance":
            body = _read_body(self)
            FINANCE_FILE = WORKSPACE / "finance" / "finance.json"
            with _state_lock:
                data = {}
                if FINANCE_FILE.exists():
                    try:
                        data = json.loads(FINANCE_FILE.read_text(encoding="utf-8"))
                    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                        _json_response(self, {"error": "finance data unavailable"}, status=503)
                        return
                    if not isinstance(data, dict):
                        _json_response(self, {"error": "finance data is invalid"}, status=503)
                        return
                data.update(body)
                data["updated"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
                _write_json_state(FINANCE_FILE, data)
            log.append("finance.updated", user["id"], {k: v for k, v in body.items() if k in ("mrr", "burn", "runway", "customers")})
            _json_response(self, {"ok": True, "finance": data})
        elif path == "/api/pipeline":
            body = _read_body(self)
            PIPELINE_FILE = WORKSPACE / "pipeline" / "pipeline.json"
            with _state_lock:
                leads = []
                if PIPELINE_FILE.exists():
                    try:
                        leads = json.loads(PIPELINE_FILE.read_text(encoding="utf-8"))
                    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                        _json_response(self, {"error": "pipeline unavailable"}, status=503)
                        return
                    if not isinstance(leads, list) or not all(
                        isinstance(item, dict) for item in leads
                    ):
                        _json_response(self, {"error": "pipeline data is invalid"}, status=503)
                        return
                lead = {
                    "id": body.get("id", f"L-{uuid.uuid4().hex[:8]}"),
                    "name": body.get("name", ""),
                    "company": body.get("company", ""),
                    "stage": body.get("stage", "prospect"),
                    "value": body.get("value", 0),
                    "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "notes": body.get("notes", ""),
                }
                found = False
                for i, existing_lead in enumerate(leads):
                    if existing_lead.get("id") == lead["id"]:
                        leads[i] = lead
                        found = True
                        break
                if not found:
                    leads.append(lead)
                _write_json_state(PIPELINE_FILE, leads)
            log.append("pipeline.updated", user["id"], {"id": lead["id"], "name": lead["name"], "stage": lead["stage"]})
            _json_response(self, {"ok": True, "lead": lead})
        elif path == "/api/auth/login":
            body = _read_body(self)
            username = body.get("username", "")
            password = body.get("password", "")
            otp = body.get("otp", "")
            if (
                not isinstance(username, str) or len(username) > 64
                or not isinstance(password, str) or len(password.encode("utf-8")) > 72
                or not isinstance(otp, str) or len(otp) > 6
            ):
                _json_response(self, {"error": "invalid credentials"}, status=401)
                return
            remote = self.client_address[0] if self.client_address else "unknown"
            rate_key = f"{remote}:{username.casefold()}"
            if not _valid_login_rate(rate_key):
                _json_response(self, {"error": "too many login attempts; try again later"}, status=429)
                return
            user = auth.authenticate(username, password, otp)
            if not user:
                _json_response(self, {"error": "invalid credentials"}, status=401)
                return
            _clear_login_rate(rate_key)
            token = auth.create_session(user["id"])
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            _set_session_cookie(self, token, max_age=43200)
            self.end_headers()
            self.wfile.write(json.dumps({
                "ok": True,
                "user": AuthManager.public_user(user),
                "csrf_token": auth.session_csrf(token),
            }).encode())
        elif path == "/api/auth/register":
            if not registration_enabled():
                _json_response(self, {
                    "error": "registration is disabled; provision accounts with the local admin CLI"
                }, 403)
                return
            if not is_loopback(self.server.server_address[0]):
                _json_response(self, {"error": "self-registration is limited to loopback bootstrap"}, status=403)
                return
            body = _read_body(self)
            username = body.get("username", "")
            email = body.get("email", "")
            password = body.get("password", "")
            if not username or not password:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "username and password required"}).encode())
                return
            try:
                user_id = auth.register(username, email, password, allow_registration=True)
            except (ValueError, PermissionError) as exc:
                _json_response(self, {"error": str(exc)}, status=400)
                return
            if not user_id:
                _json_response(self, {"error": "username already exists"}, status=400)
                return
            token = auth.create_session(user_id)
            user = auth._users[user_id]
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            _set_session_cookie(self, token, max_age=43200)
            self.end_headers()
            self.wfile.write(json.dumps({
                "ok": True,
                "user": AuthManager.public_user(user),
                "csrf_token": auth.session_csrf(token),
            }).encode())
        elif path == "/api/auth/logout":
            token = _session_token(self)
            if token:
                auth.logout(token)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            _set_session_cookie(self, "", max_age=0)
            self.end_headers()
            self.wfile.write(json.dumps({"ok": True}).encode())
        elif path == "/api/chat":
            self._handle_chat(user)
        else:
            self.send_response(404)
            self.end_headers()

    def _handle_chat(self, user: dict) -> None:
        body = _read_body(self)
        message = body.get("message", "")
        history = body.get("history", [])
        model = body.get("model", "qwen3.5:9b")
        if (
            not isinstance(message, str) or not message or len(message) > 10_000
            or not isinstance(history, list) or len(history) > 10
            or not isinstance(model, str) or not model or len(model) > 100
        ):
            _json_response(self, {"error": "invalid chat request"}, status=400)
            return
        safe_history = []
        for item in history:
            if (
                not isinstance(item, dict)
                or item.get("role") not in {"user", "assistant"}
                or not isinstance(item.get("content"), str)
                or len(item["content"]) > 10_000
            ):
                _json_response(self, {"error": "invalid chat history"}, status=400)
                return
            safe_history.append({"role": item["role"], "content": item["content"]})

        try:
            current_state = _state_summary()
        except ValueError:
            _json_response(self, {"error": "chat context unavailable"}, status=503)
            return
        system_prompt = (
            "You are the CompliProof Business OS assistant — a personal AI assistant for a solo software founder. "
            "You help with reconciliation tasks, prototype reconciliation reports, task triage, and status reporting. "
            "Be concise and action-first: lead with the action, number steps, and give time estimates. "
            "Never send/publish/deploy/charge/delete without explicit approval. "
            "Current state: " + json.dumps(current_state)
        )
        messages = [{"role": "system", "content": system_prompt}]
        messages.extend(safe_history)
        messages.append({"role": "user", "content": message})

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()

        try:
            req = urllib.request.Request(  # noqa: S310
                f"{OLLAMA_URL}/api/chat",
                data=json.dumps({
                    "model": model, "messages": messages, "stream": True,
                    "think": False, "options": {"num_predict": 512, "temperature": 0.7}
                }).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with open_http_url(req, timeout=120) as resp:
                for line in resp:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        chunk = json.loads(line)
                        msg = chunk.get("message", {})
                        if msg.get("content"):
                            sse = f"data: {json.dumps({'content': msg['content']})}\n\n"
                            self.wfile.write(sse.encode("utf-8"))
                            self.wfile.flush()
                        if chunk.get("done"):
                            self.wfile.write(b"data: [DONE]\n\n")
                            self.wfile.flush()
                    except json.JSONDecodeError:
                        self.wfile.write(
                            b'data: {"error":"invalid response from model service"}\n\n'
                        )
                        break
        except (OSError, TimeoutError, ValueError):
            try:
                self.wfile.write(
                    b'data: {"error":"model service unavailable"}\n\n'
                )
                self.wfile.flush()
            except BrokenPipeError:
                pass
        log.append(
            "chat.message",
            user["id"],
            {"message_length": len(message), "model": model},
        )
        self.close_connection = True


def main():
    global PORT
    parser = argparse.ArgumentParser(description="CompliProof Business OS backend")
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument(
        "--allow-registration",
        action="store_true",
        help="explicitly allow public account registration (local bootstrap only)",
    )
    args = parser.parse_args()
    PORT = args.port
    if args.allow_registration:
        os.environ["COMPLIPROOF_ALLOW_REGISTRATION"] = "1"

    if not is_loopback(args.host):
        secure_cookies = os.environ.get(
            "COMPLIPROOF_SECURE_COOKIES", ""
        ).strip().lower() in {"1", "true", "yes"}
        if not secure_cookies:
            print(
                "ERROR: non-loopback binding requires COMPLIPROOF_SECURE_COOKIES=1 "
                "and a TLS-terminating reverse proxy."
            )
            return 2
        print("WARNING: terminate TLS at a trusted reverse proxy before exposing this service.")
        if registration_enabled():
            print("WARNING: registration is enabled on a non-loopback binding.")

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    threading.Thread(
        target=_result_retention_worker,
        name="result-retention",
        daemon=True,
    ).start()
    print(f"CompliProof backend running on http://{args.host}:{args.port}")
    print(f"Dashboard: http://{args.host}:{args.port}/")
    print(f"Registration: {'ENABLED' if registration_enabled() else 'disabled'}")
    print("Press Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
        httpd.server_close()


if __name__ == "__main__":
    raise SystemExit(main())
