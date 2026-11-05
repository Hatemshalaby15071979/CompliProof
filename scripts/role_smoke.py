#!/usr/bin/env python3
"""Role-by-role HTTP smoke for all 5 RBAC roles (P0-5/P0-7)."""
from __future__ import annotations

import http.cookiejar
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from compliproof.auth import AuthManager, generate_totp_secret  # noqa: E402

PASSWORD = "long-password-123"


def _req(base, path, method="GET", data=None, cookie=None, csrf=None, headers=None):
    url = base + path
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, method=method)
    if body is not None:
        req.add_header("Content-Type", "application/json")
    if cookie:
        req.add_header("Cookie", cookie)
    if csrf:
        req.add_header("X-CSRF-Token", csrf)
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read() or b"{}")
        except Exception:
            return exc.code, {}


def main():
    workspace = tempfile.mkdtemp(prefix="cp-role-smoke-")
    os.environ["COMPLIPROOF_WORKSPACE"] = workspace
    os.chmod(workspace, 0o700)
    auth = AuthManager(workspace)
    roles = ["owner", "approver", "operator", "auditor", "viewer"]
    users = {}
    for role in roles:
        secret = generate_totp_secret() if role in ("owner", "approver") else None
        uid = auth.create_user(role, f"{role}@example.com", PASSWORD, role=role, totp_secret=secret)
        users[role] = (uid, secret)
        if secret:
            # store secret for login
            pass

    port = 18299
    env = dict(os.environ)
    env["COMPLIPROOF_WORKSPACE"] = workspace
    env["COMPLIPROOF_SECURE_COOKIES"] = "0"
    proc = subprocess.Popen(
        [sys.executable, "-m", "compliproof.server", "--host", "127.0.0.1", "--port", str(port)],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        cwd=str(ROOT),
    )
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(30):
            try:
                urllib.request.urlopen(base + "/api/healthz", timeout=2)
                break
            except Exception:
                time.sleep(0.5)
        else:
            raise SystemExit("server did not start")

        for role in roles:
            uid, secret = users[role]
            otp = ""
            if secret:
                import hashlib
                import hmac
                import struct
                import time as _t
                key = __import__("base64").b32decode(secret + "=" * (-len(secret) % 8))
                counter = int(_t.time() // 30)
                digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
                idx = digest[-1] & 0x0F
                val = struct.unpack(">I", digest[idx:idx + 4])[0] & 0x7FFFFFFF
                otp = f"{val % 1_000_000:06d}"
            status, body = _req(base, "/api/auth/login", "POST", {"username": role, "password": PASSWORD, "otp": otp})
            assert status == 200, (role, status, body)
            # extract cookie
            # re-login not needed; use cookie jar manually by parsing Set-Cookie from a raw request
            # Simpler: use cookie jar
            cj = http.cookiejar.CookieJar()
            opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
            r = opener.open(urllib.request.Request(base + "/api/auth/login", data=json.dumps({"username": role, "password": PASSWORD, "otp": otp}).encode(), headers={"Content-Type": "application/json"}, method="POST"))
            r.read()
            cookie_str = "; ".join(f"{c.name}={c.value}" for c in cj)
            csrf = None
            for c in cj:
                pass
            # get csrf from me
            st, me = _req(base, "/api/auth/me", cookie=cookie_str)
            assert st == 200, (role, st, me)
            csrf = me.get("csrf_token")
            assert me["user"]["role"] == role

            # role-specific: finance admin-only
            st, _ = _req(base, "/api/finance", cookie=cookie_str)
            if role == "owner":
                assert st == 200, (role, "finance expected 200", st)
            else:
                assert st == 403, (role, "finance expected 403", st)

            # logout
            st, _ = _req(base, "/api/auth/logout", "POST", {}, cookie=cookie_str, csrf=csrf)
            assert st == 200
            st, _ = _req(base, "/api/auth/me", cookie=cookie_str)
            assert st == 401, (role, "post-logout expected 401", st)
            print(f"OK role={role}")

        # unauth healthz
        st, _ = _req(base, "/api/healthz")
        assert st == 200
        print("ALL ROLES PASSED")
    finally:
        proc.terminate()
        proc.wait(timeout=10)


if __name__ == "__main__":
    main()
