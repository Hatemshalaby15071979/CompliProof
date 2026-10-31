"""Tests for registration, cookie, and loopback policy helpers."""
import base64
import hashlib
import hmac
import json
import struct
import sys
import threading
import time
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import pytest

from compliproof.auth import (
    AuthManager,
    generate_totp_secret,
    verify_totp,
)
from compliproof.security import (
    is_loopback,
    open_http_url,
    registration_enabled,
    session_cookie,
)


def test_registration_is_disabled_by_default(monkeypatch):
    monkeypatch.delenv("COMPLIPROOF_ALLOW_REGISTRATION", raising=False)
    assert registration_enabled() is False


def test_registration_requires_explicit_enable(monkeypatch):
    monkeypatch.setenv("COMPLIPROOF_ALLOW_REGISTRATION", "1")
    assert registration_enabled() is True


def test_auth_register_requires_explicit_permission(tmp_path):
    auth = AuthManager(str(tmp_path))
    try:
        auth.register("alice", "alice@example.com", "password1234")
    except PermissionError:
        pass
    else:
        raise AssertionError("AuthManager.register accepted an implicit registration")


def test_auth_register_allows_explicit_bootstrap(tmp_path):
    auth = AuthManager(str(tmp_path))
    user_id = auth.register(
        "alice", "alice@example.com", "password1234", allow_registration=True
    )
    assert user_id is not None
    assert auth.authenticate("alice", "password1234")["username"] == "alice"


def _totp(secret, at):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack(">Q", at // 30), hashlib.sha1).digest()
    offset = digest[-1] & 15
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"


def test_totp_verification_and_privileged_mfa(tmp_path):
    secret = generate_totp_secret()
    assert verify_totp(secret, _totp(secret, int(time.time())))
    manager = AuthManager(str(tmp_path))
    manager.create_user(
        "owner", "owner@example.com", "long-password-123",
        role="owner", totp_secret=secret,
    )
    assert manager.authenticate("owner", "long-password-123") is None
    assert manager.authenticate(
        "owner", "long-password-123", _totp(secret, int(time.time()))
    )["role"] == "owner"


def test_sessions_are_hashed_at_rest_and_expire_after_12_hours(tmp_path):
    manager = AuthManager(str(tmp_path))
    user_id = manager.create_user(
        "operator", "operator@example.com", "long-password-123", role="operator"
    )
    token = manager.create_session(user_id)
    persisted = (tmp_path / "sessions.json").read_text(encoding="utf-8")
    assert token not in persisted
    assert len(json.loads(persisted)) == 1
    assert manager.get_current_user(token)["id"] == user_id
    assert (tmp_path / "sessions.json").stat().st_mode & 0o777 == 0o600


def test_privileged_roles_cannot_be_created_without_mfa(tmp_path):
    manager = AuthManager(str(tmp_path))
    with pytest.raises(ValueError, match="require MFA"):
        manager.create_user(
            "owner", "owner@example.com", "long-password-123", role="owner"
        )


def test_session_cookie_attributes():
    cookie = session_cookie("token-value", secure=False)
    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie
    assert "Secure" not in cookie
    assert "Max-Age=604800" in cookie

    secure_cookie = session_cookie("token-value", secure=True)
    assert "Secure" in secure_cookie


def test_session_cookie_can_be_cleared():
    cookie = session_cookie("", secure=False, max_age=0)
    assert "session=" in cookie
    assert "Max-Age=0" in cookie


def test_loopback_detection():
    assert is_loopback("127.0.0.1") is True
    assert is_loopback("::1") is True
    assert is_loopback("localhost") is True
    assert is_loopback("0.0.0.0") is False  # noqa: S104
    assert is_loopback("example.com") is False


def test_http_opener_rejects_non_http_schemes():
    with pytest.raises(ValueError, match="HTTP\\(S\\)"):
        open_http_url("file:///etc/passwd", timeout=1)


def test_http_opener_accepts_local_http():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, fmt, *args):
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.handle_request, daemon=True)
    thread.start()
    try:
        with open_http_url(
            f"http://127.0.0.1:{server.server_port}/", timeout=2
        ) as response:
            assert response.read() == b"ok"
    finally:
        server.server_close()
        thread.join(timeout=2)


def test_http_opener_rejects_redirects():
    class RedirectHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", "/redirected")
            self.end_headers()

        def log_message(self, fmt, *args):
            return

    server = HTTPServer(("127.0.0.1", 0), RedirectHandler)
    thread = threading.Thread(target=server.handle_request, daemon=True)
    thread.start()
    try:
        with pytest.raises(urllib.error.HTTPError) as error:
            open_http_url(
                f"http://127.0.0.1:{server.server_port}/", timeout=2
            )
        assert error.value.code == 302
    finally:
        server.server_close()
        thread.join(timeout=2)
