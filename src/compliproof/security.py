#!/usr/bin/env python3
"""Small security helpers for the local CompliProof prototype.

These helpers keep policy decisions in one place so the server does not
hand-roll registration gating, cookie attributes, or loopback checks.
"""
from __future__ import annotations

import ipaddress
import os
import urllib.request
from urllib.parse import urlsplit

REGISTRATION_ENV = "COMPLIPROOF_ALLOW_REGISTRATION"


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def open_http_url(request: urllib.request.Request | str, *, timeout: float):
    """Open an absolute HTTP(S) URL without file access or redirects."""
    url = request.full_url if isinstance(request, urllib.request.Request) else request
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Only absolute HTTP(S) URLs are supported")

    opener = urllib.request.OpenerDirector()
    for handler in (
        urllib.request.ProxyHandler(),
        urllib.request.HTTPHandler(),
        urllib.request.HTTPSHandler(),
        urllib.request.HTTPDefaultErrorHandler(),
        _NoRedirectHandler(),
        urllib.request.HTTPErrorProcessor(),
    ):
        opener.add_handler(handler)
    return opener.open(request, timeout=timeout)


def registration_enabled() -> bool:
    """Return True only when registration was explicitly enabled."""
    return os.environ.get(REGISTRATION_ENV, "").strip().lower() in {"1", "true", "yes"}


def is_loopback(host: str) -> bool:
    """Return True for localhost and loopback IP literals."""
    candidate = (host or "").strip().strip("[]").lower()
    if candidate == "localhost":
        return True
    try:
        return ipaddress.ip_address(candidate).is_loopback
    except ValueError:
        return False


def session_cookie(token: str, *, secure: bool, max_age: int = 604800) -> str:
    """Build a session cookie with HttpOnly, SameSite=Lax, and optional Secure."""
    attributes = [
        f"session={token}",
        "Path=/",
        "HttpOnly",
        "SameSite=Lax",
        f"Max-Age={max_age}",
    ]
    if secure:
        attributes.append("Secure")
    return "; ".join(attributes)
