#!/usr/bin/env python3
"""Email notifications for CompliProof.

Sends task reminders, overdue alerts, and weekly summaries via SMTP.
Configuration is read from environment variables:
    COMPLIPROOF_SMTP_HOST    - SMTP server host (default: localhost)
    COMPLIPROOF_SMTP_PORT    - SMTP server port (default: 587)
    COMPLIPROOF_SMTP_USER    - SMTP username
    COMPLIPROOF_SMTP_PASS    - SMTP password
    COMPLIPROOF_FROM_EMAIL   - From email address
    COMPLIPROOF_FROM_NAME    - From name (default: CompliProof)

Usage:
    from compliproof.email import send_email, send_task_reminder, send_overdue_alert

    send_email(to="user@example.com", subject="Test", body="Hello")
    send_task_reminder(to="user@example.com", task_title="Review QA report", due="2026-10-25")
    send_overdue_alert(to="user@example.com", overdue_tasks=[...])
"""
from __future__ import annotations

import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


def _get_env(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


def send_email(to: str, subject: str, body: str, html: bool = False) -> bool:
    """Send an email via SMTP.

    Returns True if sent successfully, False otherwise.
    """
    smtp_host = _get_env("COMPLIPROOF_SMTP_HOST", "localhost")
    smtp_port = int(_get_env("COMPLIPROOF_SMTP_PORT", "587"))
    smtp_user = _get_env("COMPLIPROOF_SMTP_USER", "")
    smtp_pass = _get_env("COMPLIPROOF_SMTP_PASS", "")
    from_email = _get_env("COMPLIPROOF_FROM_EMAIL", "compliproof@localhost")
    from_name = _get_env("COMPLIPROOF_FROM_NAME", "CompliProof")

    msg = MIMEMultipart()
    msg["From"] = f"{from_name} <{from_email}>"
    msg["To"] = to
    msg["Subject"] = subject

    msg.attach(MIMEText(body, "html" if html else "plain", "utf-8"))

    try:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            if smtp_user and smtp_pass:
                server.login(smtp_user, smtp_pass)
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"Email send failed: {e}")
        return False


def send_task_reminder(to: str, task_title: str, due: str, task_id: str = "") -> bool:
    """Send a task reminder email."""
    subject = f"[CompliProof] Task Due: {task_title}"
    body = f"""
    <html>
    <body>
        <h2>Task Reminder</h2>
        <p>You have a task due soon:</p>
        <ul>
            <li><strong>Task:</strong> {task_title}</li>
            <li><strong>Due:</strong> {due}</li>
            {f'<li><strong>Task ID:</strong> {task_id}</li>' if task_id else ""}
        </ul>
        <p>Log in to your Business OS to mark it complete.</p>
    </body>
    </html>
    """
    return send_email(to, subject, body, html=True)


def send_overdue_alert(to: str, overdue_tasks: list) -> bool:
    """Send an overdue task alert email."""
    subject = f"[CompliProof] {len(overdue_tasks)} Overdue Task(s)"
    items = ""
    for t in overdue_tasks:
        items += f"<li><strong>{t.get('title', '')}</strong> (due {t.get('due', '')})</li>"

    body = f"""
    <html>
    <body>
        <h2 style="color: #dc2626;">Overdue Tasks</h2>
        <p>You have {len(overdue_tasks)} overdue task(s):</p>
        <ul>{items}</ul>
        <p>Please log in to your Business OS to address these items.</p>
    </body>
    </html>
    """
    return send_email(to, subject, body, html=True)


def send_weekly_summary(to: str, open_tasks: int, done_tasks: int, wins: int) -> bool:
    """Send a weekly summary email."""
    subject = f"[CompliProof] Weekly Summary - {done_tasks} Tasks Complete"
    body = f"""
    <html>
    <body>
        <h2>Weekly Summary</h2>
        <ul>
            <li><strong>Open tasks:</strong> {open_tasks}</li>
            <li><strong>Completed:</strong> {done_tasks}</li>
            <li><strong>Wins:</strong> {wins}</li>
        </ul>
        <p>Keep up the great work!</p>
    </body>
    </html>
    """
    return send_email(to, subject, body, html=True)