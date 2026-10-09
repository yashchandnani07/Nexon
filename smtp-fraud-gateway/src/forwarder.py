"""
Email forwarder — sends clean (accepted/tagged) emails downstream.
Supports both MailHog (local) and Gmail SMTP (production demo).

Env vars:
  FORWARD_SMTP_HOST  — "smtp.gmail.com" or "mailhog" (default: mailhog)
  FORWARD_SMTP_PORT  — 587 for Gmail, 1025 for MailHog
  FORWARD_SMTP_USER  — Gmail address (only needed for Gmail)
  FORWARD_SMTP_PASS  — Gmail App Password (only needed for Gmail)
  FORWARD_TO_EMAIL   — Override recipient; forward all clean mail here
"""
import os
import smtplib
import logging
from email import message_from_bytes, message_from_string
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

log = logging.getLogger(__name__)

FORWARD_HOST  = os.getenv("FORWARD_SMTP_HOST", "mailhog")
FORWARD_PORT  = int(os.getenv("FORWARD_SMTP_PORT", "1025"))
FORWARD_USER  = os.getenv("FORWARD_SMTP_USER", "")
FORWARD_PASS  = os.getenv("FORWARD_SMTP_PASS", "")
FORWARD_TO    = os.getenv("FORWARD_TO_EMAIL", "")   # override all recipients

USE_GMAIL = FORWARD_HOST == "smtp.gmail.com"


def forward_to_downstream(raw_email: str, sender: str, recipients: list):
    """Forward a raw email string to the downstream SMTP server."""
    if not recipients:
        return

    # If a fixed destination is set, always deliver there (demo mode)
    dest = [FORWARD_TO] if FORWARD_TO else recipients

    try:
        if USE_GMAIL:
            _forward_via_gmail(raw_email, sender, dest)
        else:
            _forward_via_plain(raw_email, sender, dest)
        log.info("Forwarded email from %s to %s", sender, dest)
    except Exception as e:
        log.error("Forward failed: %s", e)


def _forward_via_plain(raw_email: str, sender: str, recipients: list):
    """Forward via unauthenticated SMTP (MailHog / local relay)."""
    data = raw_email.encode("utf-8") if isinstance(raw_email, str) else raw_email
    with smtplib.SMTP(FORWARD_HOST, FORWARD_PORT, timeout=10) as smtp:
        smtp.sendmail(sender, recipients, data)


def _forward_via_gmail(raw_email: str, sender: str, recipients: list):
    """Forward via Gmail SMTP with STARTTLS + App Password auth."""
    # Parse the original message so we can rewrite From/To cleanly
    if isinstance(raw_email, bytes):
        orig = message_from_bytes(raw_email)
    else:
        orig = message_from_string(raw_email)

    # Build a clean wrapper so Gmail accepts it (From must be our auth'd address)
    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[AegisAI Forwarded] {orig.get('Subject', '(no subject)')}"
    msg["From"]    = FORWARD_USER          # must match authenticated Gmail account
    msg["To"]      = ", ".join(recipients)
    msg["Reply-To"] = orig.get("From", sender)

    # Extract body
    body_text = ""
    if orig.is_multipart():
        for part in orig.walk():
            if part.get_content_type() == "text/plain":
                body_text = part.get_payload(decode=True).decode("utf-8", errors="replace")
                break
    else:
        body_text = orig.get_payload(decode=True).decode("utf-8", errors="replace") if orig.get_payload() else ""

    # Add AegisAI header banner
    banner = (
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        "  ✅  AegisAI SMTP Gateway — EMAIL ACCEPTED\n"
        f"  Original From:    {orig.get('From', sender)}\n"
        f"  Original Subject: {orig.get('Subject', '')}\n"
        "  Fraud Score:      BELOW THRESHOLD — CLEAN\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
    )
    msg.attach(MIMEText(banner + body_text, "plain"))

    with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=15) as smtp:
        smtp.login(FORWARD_USER, FORWARD_PASS)
        smtp.sendmail(FORWARD_USER, recipients, msg.as_string())
