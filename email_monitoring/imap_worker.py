# email_monitoring/imap_worker.py
# Background IMAP polling thread — fetches emails every 10 seconds,
# parses full content (headers, body, attachments, URLs) and stores in DB.
#
# Supports:
#   1. IMAP_ENABLED=true  → connects to configured IMAP server (e.g. Gmail)
#   2. IMAP_ENABLED=false → polls MailHog HTTP API (for local dev/demo)

from __future__ import annotations

import email as email_lib
import imaplib
import json
import logging
import os
import re
import threading
import time
from email.header import decode_header
from pathlib import Path
from typing import Optional

import requests

from email_db import init_db, save_email, save_attachment

# Configure logging so worker messages appear in uvicorn output
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s — %(message)s")
logger = logging.getLogger("imap_worker")

# ── Config ────────────────────────────────────────────────────────────────────

IMAP_ENABLED   = os.getenv("IMAP_ENABLED",   "false").lower() == "true"
IMAP_SERVER    = os.getenv("IMAP_SERVER",    "imap.gmail.com")
IMAP_PORT      = int(os.getenv("IMAP_PORT",  "993"))
IMAP_USER      = os.getenv("IMAP_USER",      "")
IMAP_PASSWORD  = os.getenv("IMAP_PASSWORD",  "")
IMAP_USE_SSL   = os.getenv("IMAP_USE_SSL",   "true").lower() == "true"
IMAP_MAILBOX   = os.getenv("IMAP_MAILBOX",   "INBOX")
POLL_INTERVAL  = int(os.getenv("POLL_INTERVAL", "10"))

MAILHOG_URL    = os.getenv("MAILHOG_URL", "http://mailhog:8025")

# ── Helpers ───────────────────────────────────────────────────────────────────

_URL_RE = re.compile(
    r'https?://[^\s<>"\'()\[\]{}|\\^`]*',
    re.IGNORECASE
)


def _decode_str(value: str) -> str:
    if not value:
        return ""
    parts = []
    for raw, enc in decode_header(value):
        if isinstance(raw, bytes):
            # Normalise bogus encoding names
            charset = (enc or "utf-8").lower().replace("unknown-8bit", "latin-1")
            parts.append(raw.decode(charset, errors="replace"))
        else:
            parts.append(raw)
    return "".join(parts)


def _extract_body(msg) -> tuple[str, str]:
    """Return (body_text, body_html) from a parsed email.message object."""
    text_parts, html_parts = [], []

    def walk(part):
        ct = part.get_content_type()
        disp = str(part.get("Content-Disposition", ""))
        if "attachment" in disp:
            return
        if ct == "text/plain":
            payload = part.get_payload(decode=True)
            if payload:
                charset = (part.get_content_charset() or "utf-8").replace("unknown-8bit", "latin-1")
                text_parts.append(payload.decode(charset, errors="replace"))
        elif ct == "text/html":
            payload = part.get_payload(decode=True)
            if payload:
                charset = (part.get_content_charset() or "utf-8").replace("unknown-8bit", "latin-1")
                html_parts.append(payload.decode(charset, errors="replace"))
        elif part.is_multipart():
            for sub in part.get_payload():
                walk(sub)

    if msg.is_multipart():
        for part in msg.get_payload():
            walk(part)
    else:
        walk(msg)

    return "\n".join(text_parts), "\n".join(html_parts)


def _extract_attachments(msg) -> list[dict]:
    attachments = []

    def walk(part):
        ct = part.get_content_type()
        disp = str(part.get("Content-Disposition", ""))
        filename = part.get_filename()
        if filename or "attachment" in disp:
            filename = _decode_str(filename or "attachment")
            payload = part.get_payload(decode=True) or b""
            attachments.append({
                "filename":     filename,
                "content_type": ct,
                "size_bytes":   len(payload),
                "content":      payload,
            })
        elif part.is_multipart():
            for sub in part.get_payload():
                walk(sub)

    if msg.is_multipart():
        for part in msg.get_payload():
            walk(part)

    return attachments


def _extract_urls(text: str, html: str = "") -> list[str]:
    combined = f"{text}\n{html}"
    return list(dict.fromkeys(_URL_RE.findall(combined)))  # deduplicated, order preserved


def _extract_headers(msg) -> dict:
    headers = {}
    for key in msg.keys():
        val = msg.get(key, "")
        headers[key] = _decode_str(str(val))
    return headers


def _parse_email_message(msg, uid: str = "") -> dict:
    """Convert a parsed email.message object → flat dict for DB storage."""
    subject  = _decode_str(msg.get("Subject", "(no subject)"))
    sender   = _decode_str(msg.get("From", ""))
    receiver = _decode_str(msg.get("To", ""))
    reply_to = _decode_str(msg.get("Reply-To", ""))
    date_str = _decode_str(msg.get("Date", ""))
    msg_id   = _decode_str(msg.get("Message-ID", "")) or uid

    body_text, body_html = _extract_body(msg)
    attachments          = _extract_attachments(msg)
    urls                 = _extract_urls(body_text, body_html)
    headers              = _extract_headers(msg)

    return {
        "message_id":       msg_id.strip(),
        "subject":          subject,
        "sender":           sender,
        "receiver":         receiver,
        "reply_to":         reply_to,
        "date_str":         date_str,
        "headers":          headers,
        "body_text":        body_text,
        "body_html":        body_html,
        "urls":             urls,
        "has_attachments":  len(attachments) > 0,
        "attachment_count": len(attachments),
        "_attachments":     attachments,   # not stored in email_inbox directly
    }


# ── IMAP polling ──────────────────────────────────────────────────────────────

_seen_ids: set[str] = set()
_imap_conn: Optional[imaplib.IMAP4] = None


def _connect_imap():
    global _imap_conn
    try:
        if IMAP_USE_SSL:
            _imap_conn = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
        else:
            _imap_conn = imaplib.IMAP4(IMAP_SERVER, IMAP_PORT)
        _imap_conn.login(IMAP_USER, IMAP_PASSWORD)
        logger.info(f"[IMAP] Connected to {IMAP_SERVER}:{IMAP_PORT} as {IMAP_USER}")
        return True
    except Exception as e:
        logger.error(f"[IMAP] Connection failed: {e}")
        _imap_conn = None
        return False


def _poll_imap():
    global _imap_conn
    if _imap_conn is None and not _connect_imap():
        return

    try:
        _imap_conn.select(IMAP_MAILBOX)
        typ, data = _imap_conn.search(None, "ALL")
        if typ != "OK":
            return

        uids = data[0].split()
        new_uids = [u for u in uids if u.decode() not in _seen_ids]

        for uid in new_uids[-50:]:   # process up to 50 at once
            try:
                typ2, msg_data = _imap_conn.fetch(uid, "(RFC822)")
                if typ2 != "OK":
                    continue
                raw = msg_data[0][1]
                msg = email_lib.message_from_bytes(raw)
                parsed = _parse_email_message(msg, uid=uid.decode())
                _store_parsed(parsed)
                _seen_ids.add(uid.decode())
            except Exception as e:
                logger.warning(f"[IMAP] Error processing uid {uid}: {e}")

    except imaplib.IMAP4.abort:
        logger.warning("[IMAP] Connection aborted, will reconnect")
        _imap_conn = None
    except Exception as e:
        logger.error(f"[IMAP] Poll error: {e}")
        _imap_conn = None


# ── MailHog HTTP API polling ───────────────────────────────────────────────────

def _poll_mailhog():
    try:
        resp = requests.get(f"{MAILHOG_URL}/api/v2/messages?limit=100", timeout=5)
        if resp.status_code != 200:
            return
        data = resp.json()
        items = data.get("items", [])

        for item in items:
            mid = item.get("ID", "")
            if mid in _seen_ids:
                continue

            content     = item.get("Content", {})
            headers_raw = content.get("Headers", {})

            def _h(key):
                vals = headers_raw.get(key, [])
                return _decode_str(vals[0]) if vals else ""

            # MailHog Raw.Data contains the full RFC822 message — best source
            raw_data = item.get("Raw", {}).get("Data", "")
            msg = None
            if raw_data:
                try:
                    msg = email_lib.message_from_string(raw_data)
                except Exception:
                    msg = None

            # Fallback: reconstruct from MailHog structured headers + MIME body
            if msg is None or not msg.get("From"):
                header_lines = []
                for k, vals in headers_raw.items():
                    for v in (vals if isinstance(vals, list) else [vals]):
                        header_lines.append(f"{k}: {v}")
                reconstructed = "\r\n".join(header_lines) + "\r\n\r\n" + content.get("Body", "")
                try:
                    msg = email_lib.message_from_string(reconstructed)
                except Exception:
                    msg = None

            if msg and msg.get("Subject"):
                parsed = _parse_email_message(msg, uid=mid)
            else:
                # Last-resort: plain dict from structured fields
                body_text = content.get("Body", "")
                parsed = {
                    "message_id":       mid,
                    "subject":          _h("Subject") or "(no subject)",
                    "sender":           _h("From"),
                    "receiver":         _h("To"),
                    "reply_to":         _h("Reply-To"),
                    "date_str":         _h("Date"),
                    "headers":          {k: (v[0] if isinstance(v, list) else v) for k, v in headers_raw.items()},
                    "body_text":        body_text,
                    "body_html":        "",
                    "urls":             _extract_urls(body_text),
                    "has_attachments":  False,
                    "attachment_count": 0,
                    "_attachments":     [],
                }

            _store_parsed(parsed)
            _seen_ids.add(mid)

    except Exception as e:
        logger.warning(f"[MailHog] Poll error: {e}")


# ── Storage helper ────────────────────────────────────────────────────────────

def _store_parsed(parsed: dict):
    attachments = parsed.pop("_attachments", [])
    result = save_email(parsed)
    if result:
        email_id = result["id"]
        for att in attachments:
            save_attachment(email_id, att)
        logger.info(f"[EmailWorker] Saved: {parsed.get('subject','?')!r} (id={email_id})")


# ── Main polling thread ───────────────────────────────────────────────────────

def _worker_loop():
    logger.info(f"[EmailWorker] Starting — mode={'IMAP' if IMAP_ENABLED else 'MailHog'}, interval={POLL_INTERVAL}s")
    while True:
        try:
            if IMAP_ENABLED:
                _poll_imap()
            else:
                _poll_mailhog()
        except Exception as e:
            logger.error(f"[EmailWorker] Unhandled error: {e}")
        time.sleep(POLL_INTERVAL)


_worker_thread: Optional[threading.Thread] = None


def start_worker():
    global _worker_thread
    init_db()
    _worker_thread = threading.Thread(target=_worker_loop, daemon=True, name="imap-worker")
    _worker_thread.start()
    logger.info("[EmailWorker] Thread started")
