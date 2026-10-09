"""
DLP Gateway — SQLAlchemy async DB models
Includes tamper-proof hash chaining on DLPEvent rows.
"""
from __future__ import annotations

import hashlib
import uuid
from datetime import datetime

from sqlalchemy import (
    Column, String, Float, Boolean, Integer,
    DateTime, Text, JSON, ForeignKey, func,
)
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


class DLPEvent(Base):
    """Every prompt scan — one row per request."""
    __tablename__ = "dlp_events"

    id              = Column(Integer, primary_key=True, autoincrement=True)
    event_id        = Column(String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    user_id         = Column(String(128), nullable=False, index=True)
    department      = Column(String(64), nullable=False, default="default")
    role            = Column(String(64), nullable=False, default="employee")
    destination_model = Column(String(64), nullable=False, default="unknown")

    # Prompt stored as SHA-256 hash (privacy-preserving) + first 120 chars snippet
    prompt_hash     = Column(String(64), nullable=False)
    prompt_snippet  = Column(String(200), nullable=False, default="")

    # Scan result
    decision        = Column(String(8), nullable=False)     # PASS | BLOCK | WARN
    risk_score      = Column(Float, nullable=False)
    risk_tier       = Column(String(16), nullable=False)
    detected_types  = Column(JSON, nullable=False, default=list)
    block_reason    = Column(Text, nullable=True)
    layer_scores    = Column(JSON, nullable=False, default=dict)
    findings_count  = Column(Integer, nullable=False, default=0)
    processing_ms   = Column(Float, nullable=False, default=0.0)
    from_cache      = Column(Boolean, nullable=False, default=False)
    llm_triggered   = Column(Boolean, nullable=False, default=False)

    # Document classification (4-level banking taxonomy)
    doc_classification            = Column(String(16), nullable=True)   # RESTRICTED|CONFIDENTIAL|INTERNAL|PUBLIC
    doc_classification_confidence = Column(Float, nullable=True)
    doc_needs_review              = Column(Boolean, nullable=False, default=False)
    doc_type                      = Column(String(64), nullable=True)    # e.g. 'KYC Document'

    # DPDP compliance
    dpdp_violation  = Column(Boolean, nullable=False, default=False)

    # Tamper-proof chain
    chain_hash      = Column(String(64), nullable=True)

    timestamp       = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)

    @staticmethod
    def compute_chain_hash(prev_hash: str, event_id: str, timestamp: str, decision: str) -> str:
        raw = f"{prev_hash}:{event_id}:{timestamp}:{decision}"
        return hashlib.sha256(raw.encode()).hexdigest()


class UserRiskProfile(Base):
    """Rolling violation count and risk trend per user."""
    __tablename__ = "user_risk_profiles"

    id                   = Column(Integer, primary_key=True, autoincrement=True)
    user_id              = Column(String(128), unique=True, nullable=False, index=True)
    department           = Column(String(64), nullable=False, default="default")
    role                 = Column(String(64), nullable=False, default="employee")

    total_prompts        = Column(Integer, nullable=False, default=0)
    total_blocked        = Column(Integer, nullable=False, default=0)
    total_warned         = Column(Integer, nullable=False, default=0)
    violations_last_10m  = Column(Integer, nullable=False, default=0)
    avg_risk_score       = Column(Float, nullable=False, default=0.0)
    last_seen            = Column(DateTime, nullable=True)
    first_seen           = Column(DateTime, nullable=False, default=datetime.utcnow)


class DLPPolicy(Base):
    """Admin-managed named DLP rules stored in the database."""
    __tablename__ = "dlp_policies"

    id          = Column(Integer, primary_key=True, autoincrement=True)
    name        = Column(String(128), nullable=False)
    description = Column(Text, nullable=True)
    engine_type = Column(String(64), nullable=False, default="Regex")  # Regex | NER | BERT | Entropy | YARA
    action      = Column(String(16), nullable=False, default="Block")  # Block | Redact | Alert | Warn
    is_active   = Column(Boolean, nullable=False, default=True)
    # JSON arrays: list of department names this rule applies to (empty = all)
    departments = Column(JSON, nullable=False, default=list)
    # JSON array: list of detection category keys that trigger this rule
    patterns    = Column(JSON, nullable=False, default=list)
    created_at  = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at  = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)


class Alert(Base):
    """High-risk events flagged for admin review."""
    __tablename__ = "alerts"

    id              = Column(Integer, primary_key=True, autoincrement=True)
    alert_id        = Column(String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    event_id        = Column(String(36), nullable=False, index=True)
    user_id         = Column(String(128), nullable=False, index=True)
    alert_type      = Column(String(32), nullable=False)    # HIGH_RISK | REPEAT_VIOLATOR | DOC_RESTRICTED | DPDP_VIOLATION
    risk_score      = Column(Float, nullable=False)
    message         = Column(Text, nullable=False)
    dismissed       = Column(Boolean, nullable=False, default=False)
    dpdp_violation  = Column(Boolean, nullable=False, default=False)
    doc_classification = Column(String(16), nullable=True)
    timestamp       = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
