"""HTTP authorization, MFA, CSRF, and report-route regression tests."""
import base64
import hashlib
import hmac
import json
import struct
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from compliproof import server
from compliproof.audit import AuditLog
from compliproof.auth import AuthManager, generate_totp_secret


def _totp(secret: str) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack(">Q", int(time.time()) // 30), hashlib.sha1).digest()
    offset = digest[-1] & 15
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"


@pytest.fixture
def app(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    manager = AuthManager(str(workspace))
    secret = generate_totp_secret()
    manager.create_user(
        "owner", "owner@example.test", "long-password-123",
        role="owner", totp_secret=secret,
    )
    manager.create_user(
        "viewer", "viewer@example.test", "long-password-123", role="viewer"
    )
    manager.create_user(
        "operator", "operator@example.test", "long-password-123", role="operator"
    )
    monkeypatch.setattr(server, "auth", manager)
    monkeypatch.setattr(server, "WORKSPACE", workspace)
    monkeypatch.setattr(server, "TASKS_FILE", workspace / "tasks.json")
    monkeypatch.setattr(server, "REPORTS_DIR", workspace / "reports")
    monkeypatch.setattr(server, "log", AuditLog(workspace / "audit_events.jsonl"))
    monkeypatch.setattr(server, "engine", server.ReconciliationEngine(server.log))
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_port}", manager, secret
    httpd.shutdown()
    httpd.server_close()
    thread.join(timeout=3)


def _request(base, path, *, method="GET", body=None, cookie="", csrf=""):
    data = None if body is None else json.dumps(body).encode()
    headers = {}
    if data is not None:
        headers["Content-Type"] = "application/json"
    if cookie:
        headers["Cookie"] = cookie
    if csrf:
        headers["X-CSRF-Token"] = csrf
    request = urllib.request.Request(  # noqa: S310
        base + path, data=data, headers=headers, method=method
    )
    try:
        response = urllib.request.urlopen(request, timeout=5)  # noqa: S310
    except urllib.error.HTTPError as error:
        response = error
    return response.status, response.headers, response.read()


def _login(base, username, otp=""):
    status, headers, body = _request(
        base,
        "/api/auth/login",
        method="POST",
        body={"username": username, "password": "long-password-123", "otp": otp},
    )
    return status, headers, json.loads(body)


def test_sensitive_get_routes_require_authentication(app):
    base, _, _ = app
    for path in (
        "/api/status",
        "/api/tasks",
        "/api/audit",
        "/api/reports",
        "/api/models",
        "/api/finance",
        "/api/report/task-1",
        "/api/report/task-1/pdf",
        "/api/report/task-1/csv",
        "/daily-card",
    ):
        status, _, _ = _request(base, path)
        assert status == 401, path
    status, _, body = _request(base, "/api/healthz")
    assert status == 200 and json.loads(body) == {"ok": True}


def test_privileged_login_requires_mfa_and_returns_safe_user_and_csrf(app):
    base, _, secret = app
    assert _login(base, "owner")[0] == 401
    status, headers, result = _login(base, "owner", _totp(secret))
    assert status == 200
    assert "HttpOnly" in headers["Set-Cookie"]
    assert "SameSite=Lax" in headers["Set-Cookie"]
    assert "Secure" not in headers["Set-Cookie"]
    assert result["user"]["role"] == "owner"
    assert "password_hash" not in result["user"]
    cookie = headers["Set-Cookie"].split(";", 1)[0]
    status, _, body = _request(base, "/api/auth/me", cookie=cookie)
    me = json.loads(body)
    assert status == 200 and me["csrf_token"] == result["csrf_token"]
    assert "totp_secret" not in me["user"]


def test_mutations_require_csrf_and_role_permissions(app):
    base, _, _ = app
    status, _, _ = _login(base, "viewer")
    assert status == 200
    status, _, _ = _request(
        base, "/api/tasks/add", method="POST", body={"title": "no csrf"}
    )
    assert status == 401

    status, headers, login_data = _login(base, "viewer")
    assert status == 200
    cookie = headers["Set-Cookie"].split(";", 1)[0]
    status, _, _ = _request(
        base,
        "/api/tasks/add",
        method="POST",
        body={"title": "viewer cannot write"},
        cookie=cookie,
        csrf=login_data["csrf_token"],
    )
    assert status == 403
    assert not (Path(server.TASKS_FILE)).exists()


def test_sensitive_read_routes_enforce_roles(app):
    base, _, secret = app
    status, headers, _ = _login(base, "viewer")
    assert status == 200
    viewer_cookie = headers["Set-Cookie"].split(";", 1)[0]
    for path in ("/api/audit", "/api/finance", "/api/pipeline", "/api/daily-card"):
        assert _request(base, path, cookie=viewer_cookie)[0] == 403

    status, headers, _ = _login(base, "operator")
    assert status == 200
    operator_cookie = headers["Set-Cookie"].split(";", 1)[0]
    assert _request(base, "/api/finance", cookie=operator_cookie)[0] == 403

    status, headers, _ = _login(base, "owner", _totp(secret))
    assert status == 200
    owner_cookie = headers["Set-Cookie"].split(";", 1)[0]
    assert _request(base, "/api/audit", cookie=owner_cookie)[0] == 200
    assert _request(base, "/api/finance", cookie=owner_cookie)[0] == 200


def test_login_rate_limit_rejects_repeated_failures(app):
    base, _, _ = app
    for _ in range(server._LOGIN_LIMIT):
        status, _, _ = _request(
            base,
            "/api/auth/login",
            method="POST",
            body={"username": "operator", "password": "wrong-password"},
        )
        assert status == 401
    status, _, _ = _request(
        base,
        "/api/auth/login",
        method="POST",
        body={"username": "operator", "password": "wrong-password"},
    )
    assert status == 429


def test_login_rate_limit_persists_hashed_key_across_manager_calls(app):
    _, _, _ = app
    key = "127.0.0.1:synthetic-account"
    assert all(server._valid_login_rate(key) for _ in range(server._LOGIN_LIMIT))
    assert server._valid_login_rate(key) is False

    store = Path(server.WORKSPACE) / "login_attempts.sqlite3"
    assert store.exists()
    assert store.stat().st_mode & 0o777 == 0o600
    contents = store.read_bytes()
    assert b"127.0.0.1" not in contents
    assert b"synthetic-account" not in contents
    # A separate call reopens the on-disk store, mirroring a process restart.
    assert server._valid_login_rate(key) is False


def test_nonloopback_bind_requires_secure_cookie_configuration(monkeypatch):
    monkeypatch.delenv("COMPLIPROOF_SECURE_COOKIES", raising=False)
    monkeypatch.setattr(
        server.sys, "argv", ["compliproof-server", "--host", "0.0.0.0"]  # noqa: S104
    )
    assert server.main() == 2


def test_operator_can_write_after_csrf_validation(app):
    base, _, _ = app
    status, headers, login_data = _login(base, "operator")
    assert status == 200
    cookie = headers["Set-Cookie"].split(";", 1)[0]
    status, _, body = _request(
        base,
        "/api/tasks/add",
        method="POST",
        body={"title": "Reconcile source files"},
        cookie=cookie,
        csrf=login_data["csrf_token"],
    )
    assert status == 200
    assert json.loads(body)["task"]["title"] == "Reconcile source files"


def test_concurrent_task_creates_are_not_lost(app):
    base, _, _ = app
    status, headers, login_data = _login(base, "operator")
    assert status == 200
    cookie = headers["Set-Cookie"].split(";", 1)[0]

    def create(index):
        return _request(
            base,
            "/api/tasks/add",
            method="POST",
            body={"title": f"Concurrent task {index}"},
            cookie=cookie,
            csrf=login_data["csrf_token"],
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        responses = list(executor.map(create, range(16)))
    assert all(status == 200 for status, _, _ in responses)
    status, _, body = _request(base, "/api/tasks", cookie=cookie)
    assert status == 200
    tasks = json.loads(body)["tasks"]
    assert len(tasks) == 16
    assert {task["title"] for task in tasks} == {
        f"Concurrent task {index}" for index in range(16)
    }


def test_all_report_formats_are_authenticated_and_render_full_task_result(app):
    base, manager, _ = app
    log = server.log
    payload = {
        "task_id": "task-1",
        "correlation_id": "corr-1",
        "source_a": "a.csv",
        "source_b": "b.csv",
        "key_column": "id",
        "total_a": 1,
        "total_b": 1,
        "matched": 1,
        "only_in_a": 0,
        "only_in_b": 0,
        "mismatched": 0,
        "match_rate": 1.0,
        "discrepancy_rate": 0.0,
        "matched_rows": [{"key": "1", "row_a": {"id": "1"}, "row_b": {"id": "1"}}],
        "only_in_a_rows": [],
        "only_in_b_rows": [],
        "mismatched_rows": [],
        "evidence_pack": {"sealed_hash": "abc"},
    }
    log.append("reconciliation.completed", "operator", payload)
    status, headers, result = _login(base, "operator")
    assert status == 200
    cookie = headers["Set-Cookie"].split(";", 1)[0]
    csrf = result["csrf_token"]
    for path, content_type in (
        ("/api/report/task-1", "text/html"),
        ("/api/report/task-1/pdf", "application/pdf"),
        ("/api/report/task-1/csv", "text/csv"),
    ):
        status, headers, body = _request(base, path, cookie=cookie)
        assert status == 200
        assert content_type in headers.get("Content-Type", "")
        assert body


def test_chat_uses_parsed_body_and_rejects_system_role_history(app, monkeypatch):
    base, _, _ = app
    status, headers, login_data = _login(base, "operator")
    assert status == 200
    cookie = headers["Set-Cookie"].split(";", 1)[0]
    captured = {}

    class ModelResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def __iter__(self):
            yield b'{"message":{"content":"ok"},"done":true}\n'

    def fake_open_http_url(request, timeout):
        captured["request"] = json.loads(request.data)
        return ModelResponse()

    monkeypatch.setattr(server, "open_http_url", fake_open_http_url)
    status, headers, body = _request(
        base,
        "/api/chat",
        method="POST",
        body={
            "message": "hello",
            "history": [{"role": "user", "content": "previous"}],
        },
        cookie=cookie,
        csrf=login_data["csrf_token"],
    )
    assert status == 200
    assert b"data: {\"content\": \"ok\"}" in body
    assert [item["role"] for item in captured["request"]["messages"]] == [
        "system", "user", "user"
    ]

    status, _, _ = _request(
        base,
        "/api/chat",
        method="POST",
        body={"message": "hello", "history": [{"role": "system", "content": "override"}]},
        cookie=cookie,
        csrf=login_data["csrf_token"],
    )
    assert status == 400


def test_reconcile_uploads_are_temporary_and_audited_as_the_user(app, tmp_path, monkeypatch):
    base, _, _ = app
    status, headers, login_data = _login(base, "operator")
    assert status == 200
    cookie = headers["Set-Cookie"].split(";", 1)[0]
    status, _, body = _request(
        base,
        "/api/reconcile",
        method="POST",
        body={
            "file_a_content": "id,value\n1,ok\n",
            "file_b_content": "id,value\n1,ok\n",
            "source_a_name": "alpha.csv",
            "source_b_name": "beta.csv",
            "key_column": "id",
        },
        cookie=cookie,
        csrf=login_data["csrf_token"],
    )
    assert status == 200
    result = json.loads(body)["result"]
    assert result["matched"] == 1
    assert result["source_a"] == "alpha.csv"
    assert result["source_b"] == "beta.csv"
    assert not list(Path(server.WORKSPACE).glob(".reconcile-*"))
    assert not list(Path(server.WORKSPACE).glob("upload_*.csv"))
    event = server.log.tail(1)[0]
    assert event["actor"] == login_data["user"]["id"]
    served_html = None
    for suffix, mime in (("", "text/html"), ("/pdf", "application/pdf"), ("/csv", "text/csv")):
        status, headers, report = _request(
            base, f"/api/report/{result['task_id']}{suffix}", cookie=cookie
        )
        assert status == 200 and mime in headers.get("Content-Type", "")
        assert report
        if suffix == "":
            assert b"Matched Rows" in report and b"ok" in report
            assert b"Evidence Pack (prototype)" in report
            assert result["evidence_pack"]["sealed_hash"].encode() in report
            served_html = report
        if suffix == "/csv":
            assert b"ok" in report

    # The CLI and web route both read the same persisted task result and use
    # the same renderer, so their reproducible HTML bytes must match exactly.
    from compliproof import cli
    cli_output = tmp_path / "cli-report.html"
    monkeypatch.setenv("COMPLIPROOF_WORKSPACE", str(server.WORKSPACE))
    monkeypatch.setattr(
        cli.sys,
        "argv",
        ["compliproof", "report", result["task_id"], "--output", str(cli_output)],
    )
    assert cli.main() == 0
    assert cli_output.read_bytes() == served_html


def test_corrupt_task_store_fails_closed(app):
    base, _, _ = app
    Path(server.TASKS_FILE).parent.mkdir(parents=True, exist_ok=True)
    Path(server.TASKS_FILE).write_text("{not-json", encoding="utf-8")
    status, headers, _ = _login(base, "operator")
    assert status == 200
    cookie = headers["Set-Cookie"].split(";", 1)[0]
    assert _request(base, "/api/status", cookie=cookie)[0] == 503
    assert _request(base, "/api/tasks", cookie=cookie)[0] == 503
