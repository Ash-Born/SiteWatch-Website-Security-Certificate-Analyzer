"""Email and webhook delivery for persisted scan results."""
from __future__ import annotations

import os
import smtplib
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from urllib.parse import urlsplit

import requests

from app import database as db_ops


def validate_webhook_url(value: str | None) -> str | None:
    """Only accept HTTPS endpoints on official Slack/Discord webhook hosts."""
    if not value or not value.strip():
        return None
    value = value.strip()
    if len(value) > 2048:
        raise ValueError("Webhook URL must be at most 2048 characters")
    parts = urlsplit(value)
    host = (parts.hostname or "").lower()
    valid = (
        parts.scheme == "https" and parts.port in (None, 443)
        and not parts.username and not parts.password and not parts.fragment
        and ((host == "hooks.slack.com" and parts.path.startswith("/services/"))
             or (host in {"discord.com", "discordapp.com"} and parts.path.startswith("/api/webhooks/")))
    )
    if not valid:
        raise ValueError("Use an HTTPS Slack hooks.slack.com/services/... or Discord discord.com/api/webhooks/... URL")
    return value


def send_webhook_alert(user_id: int, finding_data: dict) -> bool:
    """Send one real alert containing the high/critical findings from a completed scan."""
    try:
        user = db_ops.get_user_by_id(user_id)
    except Exception as exc:
        print(f"[WEBHOOK LOOKUP ERROR] user_id={user_id}: {type(exc).__name__}", flush=True)
        return False
    try:
        webhook_url = validate_webhook_url(user.get("webhook_url") if user else None)
    except ValueError:
        print(f"[WEBHOOK CONFIGURATION ERROR] user_id={user_id}: stored webhook URL is invalid", flush=True)
        return False
    if not webhook_url:
        return False
    findings = finding_data.get("findings", []) if isinstance(finding_data, dict) else []
    findings = [item for item in findings if isinstance(item, dict)
                and str(item.get("severity", "")).upper() in {"HIGH", "CRITICAL"}]
    if not findings:
        return False
    target = str(finding_data.get("target") or "Unknown target")[:240]
    scan_id = finding_data.get("scan_id")
    lines = [f"[{str(item.get('severity', 'HIGH')).upper()}] {str(item.get('title') or item.get('check_id') or 'Security finding')[:240]}"
             for item in findings[:15]]
    summary = f"SiteWatch found {len(findings)} high/critical finding(s) for {target} (scan #{scan_id}).\n" + "\n".join(lines)
    host = (urlsplit(webhook_url).hostname or "").lower()
    if host == "hooks.slack.com":
        payload = {"text": summary[:3500], "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": summary[:3500]}}]}
    else:
        payload = {"content": summary[:1900], "embeds": [{
            "title": f"High-priority findings · {target}"[:256],
            "description": "\n".join(lines)[:3800],
            "color": 15158332 if any(str(item.get("severity", "")).upper() == "CRITICAL" for item in findings) else 15105570,
            "footer": {"text": f"SiteWatch scan #{scan_id}"[:200]},
        }]}
    try:
        response = requests.post(webhook_url, json=payload, timeout=(3.05, 8), allow_redirects=False)
        response.raise_for_status()
        return True
    except requests.RequestException:
        # Never log the webhook URL; it contains a delivery secret.
        print(f"[WEBHOOK DELIVERY ERROR] user_id={user_id} host={host}: {type(exc).__name__}", flush=True)
        return False


def send_scan_pdf_email(user_id: int, scan_id: int) -> bool:
    """Generate a PDF from the saved scan and deliver it to that account's email."""
    try:
        user = db_ops.get_user_by_id(user_id)
        recipient = user.get("email") if user else None
        if not recipient:
            raise ValueError("The account has no email address configured")

        # Generate from the persisted scan payload so the attachment matches the report.
        from app.services.scan_service import ScannerService
        saved_scan = db_ops.get_scan(scan_id, user_id=user_id)
        if not saved_scan:
            raise LookupError(f"Scan {scan_id} was not found for user {user_id}")
        pdf_bytes = ScannerService.generate_pdf_report(saved_scan)

        server = os.getenv("SMTP_SERVER")
        port = int(os.getenv("SMTP_PORT", "587"))
        smtp_user = os.getenv("SMTP_USER")
        smtp_password = os.getenv("SMTP_PASSWORD")
        sender = os.getenv("SMTP_FROM") or smtp_user
        if not all((server, smtp_user, smtp_password, sender)):
            raise RuntimeError("SMTP_SERVER, SMTP_USER, SMTP_PASSWORD, and sender are required")

        message = MIMEMultipart()
        message["Subject"] = f"Website security assessment report · {saved_scan.get('target') or 'target'}"
        message["From"] = sender
        message["To"] = recipient
        message.attach(MIMEText(
            f"Your website security assessment for {saved_scan.get('target') or 'the target'} is complete. "
            f"The PDF report for scan #{scan_id} is attached.", "plain", "utf-8"))
        attachment = MIMEApplication(pdf_bytes, _subtype="pdf")
        attachment.add_header("Content-Disposition", "attachment", filename=f"report_{scan_id}.pdf")
        message.attach(attachment)

        if port == 465:
            with smtplib.SMTP_SSL(server, port, timeout=20) as smtp:
                smtp.login(smtp_user, smtp_password)
                smtp.sendmail(sender, [recipient], message.as_string())
        else:
            with smtplib.SMTP(server, port, timeout=20) as smtp:
                smtp.ehlo()
                smtp.starttls()
                smtp.ehlo()
                smtp.login(smtp_user, smtp_password)
                smtp.sendmail(sender, [recipient], message.as_string())
        return True
    except Exception as exc:
        print(f"[SCAN REPORT EMAIL ERROR] user_id={user_id} scan_id={scan_id}: {type(exc).__name__}: {exc}", flush=True)
        return False


def dispatch_scan_notifications(user_id: int, scan_id: int, report: dict, email_report: bool = False) -> None:
    findings = report.get("findings", []) if isinstance(report, dict) else []
    high_priority = [item for item in findings if isinstance(item, dict)
                     and str(item.get("severity", "")).upper() in {"HIGH", "CRITICAL"}]
    if high_priority:
        try:
            send_webhook_alert(user_id, {"scan_id": scan_id, "target": report.get("target"), "findings": high_priority})
        except Exception as exc:
            print(f"[WEBHOOK DELIVERY ERROR] user_id={user_id} scan_id={scan_id}: {type(exc).__name__}", flush=True)
    if email_report:
        try:
            send_scan_pdf_email(user_id, scan_id)
        except Exception as exc:
            print(f"[SCAN REPORT EMAIL ERROR] user_id={user_id} scan_id={scan_id}: {type(exc).__name__}", flush=True)
