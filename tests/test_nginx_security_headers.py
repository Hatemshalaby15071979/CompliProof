"""The reference reverse proxy must ship the security headers (audit K-5).

This is a config assertion, not a runtime one: it fails the build when a
header is removed from docker/nginx.conf. It cannot prove the headers reach a
client; that needs a running nginx.
"""
from __future__ import annotations

from pathlib import Path

CONFIG = Path(__file__).resolve().parents[1] / "docker" / "nginx.conf"

REQUIRED = [
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Content-Security-Policy",
]


def test_every_security_header_is_present():
    text = CONFIG.read_text(encoding="utf-8")
    missing = [header for header in REQUIRED if f"add_header {header}" not in text]
    assert not missing, f"missing security headers: {missing}"


def test_no_unsafe_inline_in_the_content_security_policy():
    text = CONFIG.read_text(encoding="utf-8")
    csp_lines = [line for line in text.splitlines() if "Content-Security-Policy" in line]
    assert csp_lines, "no CSP directive found"
    assert all("unsafe-inline" not in line for line in csp_lines), "CSP re-allowed unsafe-inline"
