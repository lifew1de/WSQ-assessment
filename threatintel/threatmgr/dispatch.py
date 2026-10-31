"""Outbound alert dispatch: push high-severity alerts to a webhook (Slack-
compatible) and/or email. Stdlib only (urllib, smtplib, email).

Secrets come from the environment, never from flags/config on disk:
  THREATMGR_WEBHOOK            webhook URL (Slack incoming webhook or any JSON sink)
  THREATMGR_SMTP_PASSWORD      SMTP auth password

Everything degrades gracefully: a dispatch failure is logged and never stops
ingestion or scanning.
"""
from __future__ import annotations

import json
import os
import smtplib
import ssl
import time
import urllib.request
import urllib.error
from email.message import EmailMessage
from typing import Optional

SEV_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _fmt(alert: dict) -> str:
    return (f"[ThreatMgr] {str(alert.get('severity','')).upper()} alert\n"
            f"observable : {alert.get('observable')}\n"
            f"threat     : {alert.get('threat')}\n"
            f"source     : {alert.get('source')}\n"
            f"type       : {alert.get('ioc_type')}\n"
            f"context    : {alert.get('context','')}\n"
            f"time       : {time.strftime('%Y-%m-%d %H:%M:%S %Z')}")


class Notifier:
    def __init__(self, webhook_url: Optional[str] = None,
                 min_severity: str = "high",
                 smtp_host: Optional[str] = None, smtp_port: int = 587,
                 smtp_user: Optional[str] = None, smtp_password: Optional[str] = None,
                 smtp_ssl: bool = False, mail_from: Optional[str] = None,
                 mail_to: Optional[str] = None):
        self.webhook_url = webhook_url
        self.min = SEV_ORDER.get(min_severity, 3)
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.smtp_user = smtp_user
        self.smtp_password = smtp_password
        self.smtp_ssl = smtp_ssl
        self.mail_from = mail_from or (smtp_user or "threatmgr@localhost")
        self.mail_to = mail_to

    @property
    def enabled(self) -> bool:
        return bool(self.webhook_url or (self.smtp_host and self.mail_to))

    def _passes(self, severity: str) -> bool:
        return SEV_ORDER.get((severity or "").lower(), 0) >= self.min

    def notify(self, alert: dict):
        if not self._passes(alert.get("severity", "")):
            return
        if self.webhook_url:
            self._safe(self._webhook, alert, "webhook")
        if self.smtp_host and self.mail_to:
            self._safe(self._email, alert, "email")

    # -- transports -------------------------------------------------------
    def _webhook(self, alert: dict):
        # Slack incoming webhooks accept {"text": ...}; we also attach the raw alert
        payload = json.dumps({"text": _fmt(alert), "alert": alert}).encode()
        req = urllib.request.Request(
            self.webhook_url, data=payload,
            headers={"Content-Type": "application/json",
                     "User-Agent": "ThreatMgr/1.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            r.read()

    def _email(self, alert: dict):
        msg = EmailMessage()
        msg["Subject"] = (f"[ThreatMgr] {str(alert.get('severity','')).upper()} "
                          f"alert: {alert.get('observable')}")
        msg["From"] = self.mail_from
        msg["To"] = self.mail_to
        msg.set_content(_fmt(alert))
        if self.smtp_ssl:
            ctx = ssl.create_default_context()
            with smtplib.SMTP_SSL(self.smtp_host, self.smtp_port,
                                  context=ctx, timeout=15) as s:
                if self.smtp_user:
                    s.login(self.smtp_user, self.smtp_password or "")
                s.send_message(msg)
        else:
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=15) as s:
                s.starttls(context=ssl.create_default_context())
                if self.smtp_user:
                    s.login(self.smtp_user, self.smtp_password or "")
                s.send_message(msg)

    @staticmethod
    def _safe(fn, alert, label):
        try:
            fn(alert)
        except (urllib.error.URLError, OSError, smtplib.SMTPException) as e:
            print(f"[dispatch] {label} failed: {e}", flush=True)
        except Exception as e:  # never let dispatch crash the pipeline
            print(f"[dispatch] {label} error: {type(e).__name__}: {e}", flush=True)

    # -- construction from CLI args + env --------------------------------
    @classmethod
    def from_args(cls, args) -> "Notifier":
        return cls(
            webhook_url=getattr(args, "webhook", None) or os.environ.get("THREATMGR_WEBHOOK"),
            min_severity=getattr(args, "min_severity", "high"),
            smtp_host=getattr(args, "smtp_host", None),
            smtp_port=getattr(args, "smtp_port", 587),
            smtp_user=getattr(args, "smtp_user", None),
            smtp_password=os.environ.get("THREATMGR_SMTP_PASSWORD"),
            smtp_ssl=getattr(args, "smtp_ssl", False),
            mail_from=getattr(args, "mail_from", None),
            mail_to=getattr(args, "mail_to", None),
        )
