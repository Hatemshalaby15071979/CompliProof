#!/usr/bin/env python3
"""Fail-closed secret scan over the full reachable git history.

Replaces the earlier 5-commit "final" scan, which reported ``hardCounts`` of
zero while the same report listed a password-assignment hit and 42 email
hits. This scanner:

* scans every reachable commit with ``git log --all -p -m`` (all refs, merge
  diffs expanded), not just ``HEAD``;
* counts every category it knows about and publishes the real counts,
  including the review categories the old report hid;
* fails closed: any hard-category match, or any review-category match that is
  not covered by an explicit, documented exception, fails the gate.

Exceptions live in ``history-scan-exceptions.json`` and are exact: a SHA-256
of the matched value (never the value itself) or of the whole added line, plus
a reason. Email matches are exempted by reserved domain (RFC 2606 example
domains and the synthetic ``.local`` tenant domain) with the domain named in
the report.

Usage:
    python3 tooling/security/scan_history_secrets.py --json scan.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

HARD_PATTERNS: dict[str, re.Pattern[str]] = {
    "private-key-block": re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"
    ),
    "aws-access-key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "github-token": re.compile(
        r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})\b"
    ),
    "slack-token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "stripe-key": re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b"),
    "openai-key": re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
    "supabase-service-role": re.compile(
        r"\bservice_role\b[=:\s]+eyJ[A-Za-z0-9._-]{20,}"
    ),
    "jwt-shape": re.compile(
        r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
    ),
    "credential-url": re.compile(
        r"\b[a-z][a-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@", re.IGNORECASE
    ),
    "secret-assignment": re.compile(
        r"(?:api[_-]?key|secret[_-]?key|access[_-]?token|client[_-]?secret)"
        r"\s*[=:]\s*[\"'][^\"']{12,}[\"']",
        re.IGNORECASE,
    ),
}

REVIEW_PATTERNS: dict[str, re.Pattern[str]] = {
    "password-assignment": re.compile(
        r"\b(?:password|passwd|pwd)\s*[=:]\s*[\"']([^\"']{6,})[\"']",
        re.IGNORECASE,
    ),
    "email-address": re.compile(
        r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b"
    ),
}

DEFAULT_EXCEPTIONS = Path(__file__).with_name("history-scan-exceptions.json")
DETAIL_LIMIT = 100


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _git(*args: str) -> str:
    return subprocess.run(
        ["git", *args],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    ).stdout


def _redact(category: str, match: re.Match[str], line: str) -> str:
    if category == "email-address":
        return f"<local-part>@{match.group(1)}"
    value = match.group(0)
    if len(value) <= 8:
        return value[:2] + "*" * (len(value) - 2)
    return value[:4] + "…" + "*" * min(len(value) - 4, 12)


def _load_exceptions(path: Path) -> dict:
    if not path.exists():
        raise SystemExit(f"exception registry not found: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("version") != 1:
        raise SystemExit(f"unsupported exception registry version: {data.get('version')}")
    return data


def scan(exceptions: dict) -> dict:
    line_exceptions = {
        (item["category"], item["line_sha256"]) for item in exceptions["line_exceptions"]
    }
    value_exceptions = {
        (item["category"], item["value_sha256"]) for item in exceptions["value_exceptions"]
    }
    email_domains = {k.lower(): v for k, v in exceptions["email_domains"].items()}

    expected_commits = int(_git("rev-list", "--all", "--count").strip())
    diff = _git("log", "--all", "-p", "-m", "--no-color", "--no-renames", "--format=commit %H")

    counts: Counter[str] = Counter()
    exceptions_applied: Counter[str] = Counter()
    hard_hits: list[dict] = []
    review_hits: list[dict] = []
    hard_total = 0
    review_total = 0
    commits_seen: set[str] = set()
    changed_lines = 0
    path = ""
    commit = ""

    for raw in diff.splitlines():
        if raw.startswith("commit "):
            commit = raw.split(" ", 1)[1].strip()
            commits_seen.add(commit)
            continue
        if raw.startswith("+++ "):
            target = raw[4:].strip()
            path = "" if target == "/dev/null" else target.removeprefix("b/")
            continue
        if not raw.startswith("+") or raw.startswith("+++ "):
            continue
        changed_lines += 1
        line = raw[1:]

        for category, pattern in HARD_PATTERNS.items():
            for match in pattern.finditer(line):
                hard_total += 1
                counts[category] += 1
                line_sha = _sha256(line.strip())
                if (category, line_sha) in line_exceptions:
                    exceptions_applied[category] += 1
                    continue
                if len(hard_hits) < DETAIL_LIMIT:
                    hard_hits.append(
                        {
                            "category": category,
                            "commit": commit[:12],
                            "path": path,
                            "preview": _redact(category, match, line),
                            "line_sha256": line_sha,
                        }
                    )

        for category, pattern in REVIEW_PATTERNS.items():
            for match in pattern.finditer(line):
                review_total += 1
                counts[category] += 1
                if category == "email-address":
                    if match.group(1).lower() in email_domains:
                        exceptions_applied[category] += 1
                        continue
                    value_sha = _sha256(match.group(0).lower())
                else:
                    value_sha = _sha256(match.group(1))
                if (category, value_sha) in value_exceptions:
                    exceptions_applied[category] += 1
                    continue
                if len(review_hits) < DETAIL_LIMIT:
                    review_hits.append(
                        {
                            "category": category,
                            "commit": commit[:12],
                            "path": path,
                            "preview": _redact(category, match, line),
                            "value_sha256": value_sha,
                        }
                    )

    gate_ok = not hard_hits and not review_hits and len(commits_seen) == expected_commits
    return {
        "tool": "tooling/security/scan_history_secrets.py",
        "scan_command": "git log --all -p -m --no-color --no-renames",
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "rev": "all",
        "commits_expected": expected_commits,
        "commits_seen": len(commits_seen),
        "changed_lines_inspected": changed_lines,
        "counts": dict(sorted(counts.items())),
        "hard_matches": hard_total,
        "review_matches": review_total,
        "exceptions_applied": dict(sorted(exceptions_applied.items())),
        "hard_hits": hard_hits,
        "review_hits": review_hits,
        "unresolved": len(hard_hits) + len(review_hits),
        "gate": "pass" if gate_ok else "fail",
        "email_domains_exempted": sorted(email_domains),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path, help="write the full report to this path")
    parser.add_argument(
        "--exceptions", type=Path, default=DEFAULT_EXCEPTIONS, help="exception registry"
    )
    args = parser.parse_args()

    report = scan(_load_exceptions(args.exceptions))
    text = json.dumps(report, indent=2, sort_keys=False)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(text + "\n", encoding="utf-8")

    print(
        f"commits {report['commits_seen']}/{report['commits_expected']} · "
        f"changed lines {report['changed_lines_inspected']} · "
        f"hard {report['hard_matches']} · review {report['review_matches']} · "
        f"unresolved {report['unresolved']} · gate {report['gate']}"
    )
    print("counts:", json.dumps(report["counts"], sort_keys=True))
    print("exceptions applied:", json.dumps(report["exceptions_applied"], sort_keys=True))
    for hit in report["hard_hits"] + report["review_hits"]:
        print(
            f"UNRESOLVED {hit['category']} {hit['commit']} {hit['path']} "
            f"{hit['preview']} sha={hit.get('line_sha256') or hit.get('value_sha256')}"
        )
    return 0 if report["gate"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
