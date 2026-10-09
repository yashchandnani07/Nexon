"""
DLP Alert Manager v2 — Fully Offline
Uses local MailHog SMTP instead of SendGrid.
PagerDuty removed — WebSocket dashboard handles critical alerts.
Slack optional — only for orgs with internal Slack deployment.
"""
from __future__ import annotations

import asyncio
import logging
import os
import smtplib
import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Dict, Deque, Set, List, Optional

import httpx

logger = logging.getLogger("dlp.alerting")

REPEAT_VIOLATION_WINDOW = 600
REPEAT_VIOLATION_THRESHOLD = 3
HIGH_RISK_THRESHOLD = 80.0
DPDP_RISK_THRESHOLD = 50.0

# ── Local SMTP (MailHog in Docker — completely offline) ────────────────────────
SMTP_HOST = os.getenv("SMTP_HOST", "mailhog")       # Docker service name
SMTP_PORT = int(os.getenv("SMTP_PORT", "1025"))     # MailHog SMTP port
SMTP_FROM = os.getenv("SMTP_FROM", "dlp-alerts@internal.local")
SMTP_TO = os.getenv("SMTP_TO", "security-team@internal.local")

# ── Internal Slack (optional — only for orgs with Slack on-premise/cloud) ─────
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")


class AlertManager:
    def __init__(self):
        self._violation_times: Dict[str, Deque[datetime]] = defaultdict(deque)
        self._subscribers: Set[asyncio.Queue] = set()

    # ── WebSocket pub/sub ─────────────────────────────────────────────────────
    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=200)
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subscribers.discard(q)

    def _broadcast(self, payload: dict) -> None:
        dead = set()
        for q in self._subscribers:
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                dead.add(q)
        self._subscribers -= dead

    # ── Local SMTP Email (MailHog — completely offline) ────────────────────────
    async def _send_email(self, alert: dict) -> None:
        """
        Sends email via local MailHog SMTP server.
        No internet required. View all emails at http://localhost:8025
        """
        dpdp_badge = (
            "<span style='background:#ea580c;color:#fff;padding:2px 8px;"
            "border-radius:4px;font-size:11px;'>🇮🇳 DPDP VIOLATION</span>"
            if alert.get("dpdp_violation") else ""
        )
        tier_color = {
            "HIGH_RISK": "#ef4444",
            "DPDP_VIOLATION": "#f97316",
            "REPEAT_OFFENDER": "#f59e0b",
        }.get(alert["alert_type"], "#6366f1")

        html_body = f"""
        <div style="font-family:system-ui,sans-serif;max-width:540px;margin:auto;
                    background:#0f172a;color:#f1f5f9;border-radius:12px;
                    padding:24px;border:1px solid #334155;">
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:16px;">
                <span style="font-size:24px;">🛡️</span>
                <h2 style="margin:0;font-size:16px;">Guardrail DLP Alert</h2>
                <span style="background:{tier_color};color:#fff;padding:2px 10px;
                             border-radius:99px;font-size:11px;font-weight:600;">
                    {alert['alert_type']}
                </span>
                {dpdp_badge}
            </div>
            <table style="width:100%;border-collapse:collapse;font-size:13px;">
                <tr style="border-bottom:1px solid #334155;">
                    <td style="padding:8px 4px;color:#94a3b8;width:120px;">User</td>
                    <td style="padding:8px 4px;font-family:monospace;">{alert['user_id']}</td>
                </tr>
                <tr style="border-bottom:1px solid #334155;">
                    <td style="padding:8px 4px;color:#94a3b8;">Risk Score</td>
                    <td style="padding:8px 4px;font-weight:bold;color:{tier_color};">
                        {alert['risk_score']:.1f} / 100
                    </td>
                </tr>
                <tr style="border-bottom:1px solid #334155;">
                    <td style="padding:8px 4px;color:#94a3b8;">Event ID</td>
                    <td style="padding:8px 4px;font-family:monospace;font-size:11px;">
                        {alert['event_id']}
                    </td>
                </tr>
                <tr style="border-bottom:1px solid #334155;">
                    <td style="padding:8px 4px;color:#94a3b8;">Details</td>
                    <td style="padding:8px 4px;">{alert['message']}</td>
                </tr>
                <tr>
                    <td style="padding:8px 4px;color:#94a3b8;">Time</td>
                    <td style="padding:8px 4px;">{alert['timestamp']}</td>
                </tr>
            </table>
            <p style="font-size:11px;color:#475569;margin-top:16px;border-top:1px solid #334155;
                      padding-top:12px;">
                ⚙️ Guardrail DLP — Internal Alert System &nbsp;|&nbsp; View Dashboard:
                <a href="http://localhost:3000" style="color:#6366f1;">http://localhost:3000</a>
                &nbsp;|&nbsp; View Emails:
                <a href="http://localhost:8025" style="color:#6366f1;">http://localhost:8025</a>
            </p>
        </div>
        """

        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[DLP ALERT] {alert['alert_type']} — {alert['user_id']} ({alert['risk_score']:.0f}/100)"
            msg["From"] = SMTP_FROM
            msg["To"] = SMTP_TO
            msg.attach(MIMEText(html_body, "html"))

            # smtplib is built-in Python — no external dependencies
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=5) as server:
                server.sendmail(SMTP_FROM, [SMTP_TO], msg.as_string())

            logger.info("Alert email sent via local SMTP (%s:%d)", SMTP_HOST, SMTP_PORT)

        except Exception as e:
            logger.warning("Local SMTP email failed: %s", e)

    # ── Optional internal Slack (only if org uses Slack internally) ────────────
    async def _send_slack(self, alert: dict) -> None:
        if not SLACK_WEBHOOK_URL:
            return
        emoji = "🚨" if alert["alert_type"] == "HIGH_RISK" else "⚠️"
        dpdp = " 🇮🇳 *DPDP Violation*" if alert.get("dpdp_violation") else ""
        payload = {
            "text": f"{emoji} *DLP Alert — {alert['alert_type']}*{dpdp}",
            "blocks": [{
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"{emoji} *DLP Alert*{dpdp}\n"
                        f"*Type:* `{alert['alert_type']}`\n"
                        f"*User:* `{alert['user_id']}`\n"
                        f"*Risk:* `{alert['risk_score']:.1f}/100`\n"
                        f"*Details:* {alert['message']}\n"
                        f"*Dashboard:* http://localhost:3000"
                    ),
                },
            }],
        }
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                await client.post(SLACK_WEBHOOK_URL, json=payload)
        except Exception as e:
            logger.warning("Slack send failed: %s", e)

    # ── Main evaluation ───────────────────────────────────────────────────────
    async def evaluate(
        self,
        event_id: str,
        user_id: str,
        decision: str,
        risk_score: float,
        detected_types: List[str],
        dpdp_violation: bool = False,
        doc_classification: Optional[str] = None,
    ) -> List[dict]:
        alerts: List[dict] = []
        now = datetime.utcnow()

        # 1. High-risk alert
        if risk_score >= HIGH_RISK_THRESHOLD:
            alert = {
                "alert_id": str(uuid.uuid4()),
                "event_id": event_id,
                "user_id": user_id,
                "alert_type": "HIGH_RISK",
                "risk_score": risk_score,
                "dpdp_violation": dpdp_violation,
                "message": (
                    f"High-risk DLP event from {user_id} (score={risk_score:.1f}). "
                    f"Detected: {', '.join(detected_types[:3])}."
                ),
                "timestamp": now.isoformat(),
            }
            alerts.append(alert)
            self._broadcast({"type": "alert", "data": alert})
            logger.warning("[ALERT] HIGH_RISK user=%s score=%.1f", user_id, risk_score)
            # Email goes to MailHog — no internet needed
            await asyncio.gather(
                self._send_email(alert),
                self._send_slack(alert),   # no-op if SLACK_WEBHOOK_URL not set
            )

        # 2. DPDP violation alert
        if dpdp_violation and DPDP_RISK_THRESHOLD <= risk_score < HIGH_RISK_THRESHOLD:
            alert = {
                "alert_id": str(uuid.uuid4()),
                "event_id": event_id,
                "user_id": user_id,
                "alert_type": "DPDP_VIOLATION",
                "risk_score": risk_score,
                "dpdp_violation": True,
                "message": (
                    f"DPDP Act 2023 violation by {user_id}. "
                    f"Personal data categories detected: {', '.join(detected_types[:3])}."
                ),
                "timestamp": now.isoformat(),
            }
            alerts.append(alert)
            self._broadcast({"type": "alert", "data": alert})
            logger.warning("[ALERT] DPDP_VIOLATION user=%s", user_id)
            await asyncio.gather(
                self._send_email(alert),
                self._send_slack(alert),
            )

        # 3. Repeat offender alert
        if decision in ("BLOCK", "WARN"):
            window = self._violation_times[user_id]
            window.append(now)
            cutoff = now - timedelta(seconds=REPEAT_VIOLATION_WINDOW)
            while window and window[0] < cutoff:
                window.popleft()

            if len(window) >= REPEAT_VIOLATION_THRESHOLD:
                alert = {
                    "alert_id": str(uuid.uuid4()),
                    "event_id": event_id,
                    "user_id": user_id,
                    "alert_type": "REPEAT_OFFENDER",
                    "risk_score": risk_score,
                    "dpdp_violation": dpdp_violation,
                    "message": (
                        f"User {user_id} triggered {len(window)} policy violations "
                        f"in {REPEAT_VIOLATION_WINDOW // 60} minutes. Immediate review required."
                    ),
                    "timestamp": now.isoformat(),
                }
                alerts.append(alert)
                self._broadcast({"type": "alert", "data": alert})
                logger.warning(
                    "[ALERT] REPEAT_OFFENDER user=%s count=%d", user_id, len(window)
                )
                await asyncio.gather(
                    self._send_email(alert),
                    self._send_slack(alert),
                )

        # 4. Restricted / Confidential document alert
        if doc_classification in ("RESTRICTED", "CONFIDENTIAL"):
            emoji = "🔴" if doc_classification == "RESTRICTED" else "🟠"
            alert = {
                "alert_id": str(uuid.uuid4()),
                "event_id": event_id,
                "user_id": user_id,
                "alert_type": "DOC_RESTRICTED",
                "risk_score": risk_score,
                "dpdp_violation": dpdp_violation,
                "doc_classification": doc_classification,
                "message": (
                    f"{emoji} {doc_classification} document detected from {user_id}. "
                    f"Transmission blocked and logged. Immediate security review required."
                ),
                "timestamp": now.isoformat(),
            }
            alerts.append(alert)
            self._broadcast({"type": "alert", "data": alert})
            logger.warning("[ALERT] DOC_RESTRICTED user=%s level=%s", user_id, doc_classification)
            await asyncio.gather(
                self._send_email(alert),
                self._send_slack(alert),
            )

        # Persist all alerts to DB
        if alerts:
            try:
                from db.session import AsyncSessionLocal
                from db.models import Alert as AlertModel
                async with AsyncSessionLocal() as db_session:
                    for a in alerts:
                        db_alert = AlertModel(
                            alert_id=a["alert_id"],
                            event_id=a["event_id"],
                            user_id=a["user_id"],
                            alert_type=a["alert_type"],
                            risk_score=a["risk_score"],
                            message=a["message"],
                            dismissed=False,
                            dpdp_violation=a.get("dpdp_violation", False),
                            doc_classification=a.get("doc_classification"),
                        )
                        db_session.add(db_alert)
                    await db_session.commit()
            except Exception as e:
                logger.warning("Failed to persist alerts to DB: %s", e)

        return alerts


alert_manager = AlertManager()
