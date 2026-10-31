"""Local user, password, MFA, and session management."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import tempfile
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import bcrypt

ROLES = {"owner", "approver", "operator", "auditor", "viewer"}
MFA_ROLES = {"owner", "approver"}
# Storage marker for a password hash, not a usable password.
PASSWORD_HASH_PREFIX = "bcrypt$"  # noqa: S105  # nosec B105


def generate_totp_secret() -> str:
    """Create a base32 secret for RFC 6238 authenticator apps."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def verify_totp(secret: str, code: str, *, at: int | None = None) -> bool:
    """Verify a six-digit TOTP code with a one-step clock-skew window."""
    if not isinstance(code, str) or len(code) != 6 or not code.isdigit():
        return False
    try:
        key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    except (ValueError, base64.binascii.Error):
        return False
    counter = int((time.time() if at is None else at) // 30)
    for offset in (-1, 0, 1):
        digest = hmac.new(key, struct.pack(">Q", counter + offset), hashlib.sha1).digest()
        index = digest[-1] & 0x0F
        value = struct.unpack(">I", digest[index:index + 4])[0] & 0x7FFFFFFF
        if hmac.compare_digest(f"{value % 1_000_000:06d}", code):
            return True
    return False


def _validate_totp_secret(secret: str) -> None:
    if not isinstance(secret, str) or not secret:
        raise ValueError("invalid TOTP secret")
    try:
        base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError("invalid TOTP secret") from exc


def _password_hash(password: str) -> str:
    if not isinstance(password, str) or len(password) < 12:
        raise ValueError("password must be at least 12 characters")
    if len(password.encode("utf-8")) > 72:
        raise ValueError("password must be no more than 72 UTF-8 bytes")
    return PASSWORD_HASH_PREFIX + bcrypt.hashpw(
        password.encode("utf-8"), bcrypt.gensalt(rounds=12)
    ).decode("ascii")


def _verify_password(password: str, stored: str) -> bool:
    if not isinstance(password, str):
        return False
    if stored.startswith(PASSWORD_HASH_PREFIX):
        try:
            return bcrypt.checkpw(
                password.encode("utf-8"), stored[len(PASSWORD_HASH_PREFIX):].encode("ascii")
            )
        except (ValueError, TypeError):
            return False

    # Upgrade legacy salted-SHA256 hashes after successful verification.
    try:
        salt, expected = stored.split(":", 1)
        actual = hashlib.sha256((password + salt).encode("utf-8")).hexdigest()
        return hmac.compare_digest(actual, expected)
    except (ValueError, AttributeError):
        return False


def _atomic_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class AuthManager:
    """File-backed local accounts and hashed, expiring bearer sessions."""

    def __init__(self, workspace_path: str):
        self.workspace = Path(workspace_path)
        self.users_file = self.workspace / "users.json"
        self.sessions_file = self.workspace / "sessions.json"
        self._users: dict[str, dict] = {}
        self._sessions: dict[str, dict] = {}
        self._lock = threading.RLock()
        self.workspace.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.workspace, 0o700)
        self._load()

    def _load_json(self, path: Path) -> dict:
        if not path.exists():
            return {}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"Cannot safely load authentication store: {path}") from exc
        if not isinstance(data, dict):
            raise RuntimeError(f"Authentication store must contain an object: {path}")
        return data

    def _load(self) -> None:
        self._users = self._load_json(self.users_file)
        sessions = self._load_json(self.sessions_file)
        # Revoke any bearer tokens written in plaintext by older versions.
        if any(len(key) != 64 for key in sessions):
            self._sessions = {}
            self._save_sessions()
        else:
            self._sessions = sessions
        for path in (self.users_file, self.sessions_file):
            if path.exists():
                os.chmod(path, 0o600)

    def _save_users(self) -> None:
        _atomic_json(self.users_file, self._users)

    def _save_sessions(self) -> None:
        _atomic_json(self.sessions_file, self._sessions)

    def create_user(
        self,
        username: str,
        email: str,
        password: str,
        *,
        role: str,
        totp_secret: str | None = None,
    ) -> str:
        if role not in ROLES:
            raise ValueError(f"role must be one of: {', '.join(sorted(ROLES))}")
        if not isinstance(username, str) or not username.strip() or len(username) > 64:
            raise ValueError("username must be between 1 and 64 characters")
        if role in MFA_ROLES and not totp_secret:
            raise ValueError(f"{role} accounts require MFA enrollment")
        if totp_secret:
            _validate_totp_secret(totp_secret)
        password_hash = _password_hash(password)
        with self._lock:
            if any(user.get("username", "").casefold() == username.casefold()
                   for user in self._users.values()):
                raise ValueError("username already exists")
            user_id = f"u-{uuid.uuid4().hex}"
            self._users[user_id] = {
                "id": user_id,
                "username": username.strip(),
                "email": email.strip() if isinstance(email, str) else "",
                "password_hash": password_hash,
                "created": datetime.now(timezone.utc).isoformat(),
                "role": role,
                "totp_secret": totp_secret,
            }
            self._save_users()
            return user_id

    def register(
        self,
        username: str,
        email: str,
        password: str,
        *,
        allow_registration: bool = False,
    ) -> Optional[str]:
        if not allow_registration:
            raise PermissionError("registration is disabled; provision accounts with the local admin CLI")
        return self.create_user(username, email, password, role="viewer")

    def authenticate(
        self, username: str, password: str, otp: str = ""
    ) -> Optional[dict]:
        if (
            not isinstance(username, str)
            or len(username) > 64
            or not isinstance(password, str)
            or len(password.encode("utf-8")) > 72
        ):
            return None
        with self._lock:
            user = next(
                (u for u in self._users.values()
                 if u.get("username", "").casefold() == username.casefold()),
                None,
            )
            if not user or not _verify_password(password, user.get("password_hash", "")):
                return None
            if user.get("role") in MFA_ROLES:
                secret = user.get("totp_secret")
                if not secret or not verify_totp(secret, otp):
                    return None
            if not user["password_hash"].startswith(PASSWORD_HASH_PREFIX):
                user["password_hash"] = _password_hash(password)
                self._save_users()
            return user

    def create_session(self, user_id: str) -> str:
        with self._lock:
            if user_id not in self._users:
                raise ValueError("unknown user")
            token = secrets.token_urlsafe(32)
            token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
            self._sessions[token_hash] = {
                "user_id": user_id,
                "csrf_token": secrets.token_urlsafe(32),
                "created": datetime.now(timezone.utc).isoformat(),
                "expires": (datetime.now(timezone.utc) + timedelta(hours=12)).isoformat(),
            }
            self._save_sessions()
            return token

    def session_csrf(self, token: str) -> Optional[str]:
        if not isinstance(token, str) or not token.isascii():
            return None
        with self._lock:
            record = self._sessions.get(hashlib.sha256(token.encode("ascii")).hexdigest())
            return record.get("csrf_token") if record else None

    def get_current_user(self, token: str) -> Optional[dict]:
        if not isinstance(token, str) or not token:
            return None
        token_hash = hashlib.sha256(token.encode("ascii", errors="ignore")).hexdigest()
        with self._lock:
            session = self._sessions.get(token_hash)
            if not session:
                return None
            try:
                expiry = datetime.fromisoformat(session["expires"])
                if datetime.now(timezone.utc) >= expiry:
                    del self._sessions[token_hash]
                    self._save_sessions()
                    return None
            except (ValueError, KeyError, TypeError):
                del self._sessions[token_hash]
                self._save_sessions()
                return None
            return self._users.get(session.get("user_id"))

    def csrf_valid(self, token: str, supplied: str) -> bool:
        expected = self.session_csrf(token)
        return bool(expected and supplied and hmac.compare_digest(expected, supplied))

    def logout(self, token: str) -> None:
        if not isinstance(token, str) or not token:
            return
        token_hash = hashlib.sha256(token.encode("ascii", errors="ignore")).hexdigest()
        with self._lock:
            if token_hash in self._sessions:
                del self._sessions[token_hash]
                self._save_sessions()

    @staticmethod
    def public_user(user: dict) -> dict:
        return {
            key: user[key]
            for key in ("id", "username", "email", "role", "created")
            if key in user
        }

    def list_users(self) -> list:
        with self._lock:
            return [self.public_user(user) for user in self._users.values()]
