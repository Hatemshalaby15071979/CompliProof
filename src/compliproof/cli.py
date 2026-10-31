#!/usr/bin/env python3
"""Prototype CLI for local CompliProof reconciliation and audit inspection.

This is not an audit-grade tool. It writes to the local development ledger by
default. Use it only in the local prototype workspace.

Usage:
    python -m compliproof.cli reconcile <csv_a> <csv_b> <key_column> [--task-id ID] [--actor ID]
    python -m compliproof.cli report <task_id> [--output report.html]
    python -m compliproof.cli audit verify
    python -m compliproof.cli audit tail [N]
    python -m compliproof.cli audit count
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path
from urllib.parse import quote

from .audit import AuditLog
from .auth import MFA_ROLES, AuthManager, generate_totp_secret, verify_totp
from .reconcile import ReconciliationEngine
from .report import (
    ReportGenerator,
    load_reconciliation_result,
    result_from_audit,
    save_reconciliation_result,
)


def _workspace_path() -> Path:
    workspace = os.environ.get("COMPLIPROOF_WORKSPACE")
    return Path(workspace) if workspace else Path(__file__).resolve().parents[2] / "workspace"


def _audit_log() -> AuditLog:
    return AuditLog(_workspace_path() / "audit_events.jsonl", allow_production=True)


def _cmd_reconcile(args: argparse.Namespace) -> int:
    audit = _audit_log()
    engine = ReconciliationEngine(audit)
    result = engine.reconcile(
        source_a=args.csv_a,
        source_b=args.csv_b,
        key_column=args.key_column,
        task_id=args.task_id,
        actor_id=args.actor,
    )
    result_data = result.to_dict()
    save_reconciliation_result(
        _workspace_path(), result_data, audit=audit, actor_id=args.actor
    )
    print(json.dumps(result_data, indent=2))
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    audit = _audit_log()
    result = load_reconciliation_result(_workspace_path(), args.task_id, audit=audit)
    if result is None:
        result = result_from_audit(audit, args.task_id)
    if result is None:
        print(f"ERROR: no reconciliation found for task_id {args.task_id}")
        return 1
    gen = ReportGenerator(audit)
    html = gen.generate_reconciliation_report(result)
    out = Path(args.output or f"compliproof_report_{args.task_id}.html")
    gen.save(html, out)
    print(f"Report saved: {out}")
    return 0


def _cmd_audit_verify() -> int:
    audit = _audit_log()
    print("OK" if audit.verify() else "BROKEN")
    return 0 if audit.verify() else 1


def _cmd_audit_tail(args: argparse.Namespace) -> int:
    audit = _audit_log()
    n = args.n or 20
    for e in audit.tail(n):
        print(json.dumps(e))
    return 0


def _cmd_audit_count() -> int:
    audit = _audit_log()
    print(audit.count())
    return 0


def _cmd_audit(args: argparse.Namespace) -> int:
    if args.sub == "verify":
        return _cmd_audit_verify()
    if args.sub == "tail":
        return _cmd_audit_tail(args)
    if args.sub == "count":
        return _cmd_audit_count()
    print("unknown audit subcommand:", args.sub)
    return 1


def _cmd_user_add(args: argparse.Namespace) -> int:
    workspace = _workspace_path()
    manager = AuthManager(str(workspace))
    password = getpass.getpass("Initial password (12+ characters): ")
    confirmation = getpass.getpass("Repeat password: ")
    if password != confirmation:
        print("Passwords do not match.", file=sys.stderr)
        return 2
    totp_secret = None
    if args.role in MFA_ROLES:
        totp_secret = generate_totp_secret()
        print(
            "Enroll this account in an authenticator app with this secret:\n"
            f"{totp_secret}"
        )
        code = getpass.getpass("Enter the current 6-digit authenticator code: ")
        if not verify_totp(totp_secret, code):
            print("MFA verification failed; account was not created.", file=sys.stderr)
            return 2
    try:
        user_id = manager.create_user(
            args.username,
            args.email,
            password,
            role=args.role,
            totp_secret=totp_secret,
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    if totp_secret:
        label = quote(f"CompliProof:{args.username}")
        print(
            "Authenticator URI:\n"
            f"otpauth://totp/{label}?secret={totp_secret}&issuer=CompliProof"
            "&algorithm=SHA1&digits=6&period=30"
        )
    print(f"Created {args.role} account {args.username} ({user_id}).")
    return 0


def _cmd_user_list(args: argparse.Namespace) -> int:
    workspace = _workspace_path()
    for user in AuthManager(str(workspace)).list_users():
        print(f"{user['username']}\t{user['role']}\t{user['id']}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="compliproof", description="CompliProof — prototype local reconciliation and evidence-pack tool")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("reconcile", help="Reconcile two CSV files")
    p.add_argument("csv_a")
    p.add_argument("csv_b")
    p.add_argument("key_column")
    p.add_argument("--task-id", default=None)
    p.add_argument("--actor", default="BA")
    p.set_defaults(func=_cmd_reconcile)

    p = sub.add_parser("report", help="Generate HTML reconciliation report for a task (prototype)")
    p.add_argument("task_id")
    p.add_argument("--output", default=None)
    p.set_defaults(func=_cmd_report)

    p = sub.add_parser("audit", help="Audit log operations")
    sp = p.add_subparsers(dest="sub", required=True)
    sp.add_parser("verify", help="Verify audit chain integrity")
    p_tail = sp.add_parser("tail", help="Show last N audit events")
    p_tail.add_argument("n", type=int, nargs="?", default=20)
    sp.add_parser("count", help="Count audit events")
    p.set_defaults(func=_cmd_audit)

    p = sub.add_parser("users", help="Provision local user accounts")
    user_sub = p.add_subparsers(dest="users_command", required=True)
    p_add = user_sub.add_parser("add", help="Create a local account")
    p_add.add_argument("username")
    p_add.add_argument("--email", default="")
    p_add.add_argument("--role", choices=("owner", "approver", "operator", "auditor", "viewer"), required=True)
    p_add.set_defaults(func=_cmd_user_add)
    p_list = user_sub.add_parser("list", help="List local account roles")
    p_list.set_defaults(func=_cmd_user_list)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
