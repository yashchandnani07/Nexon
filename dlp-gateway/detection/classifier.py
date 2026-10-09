"""
DLP Gateway — Document Classification Engine v3
Hybrid pipeline:
  Stage 1: File header + keyword density (instant, always runs)
  Stage 2: Deep PII/credential regex scan (via DLP engine patterns)
  Stage 3: Contextual boost (destination, user role, source system)

Supports: .txt, .pdf, .docx, .xlsx, .csv, .json, .md, .py, .env, .sql, .log, .yaml
Fully offline — no LLM blocking the response path.
"""
from __future__ import annotations

import re
import json
import logging
import os
from dataclasses import dataclass, field
from typing import List, Tuple, Optional

import httpx

logger = logging.getLogger("dlp.classifier")

# ── Classification levels ─────────────────────────────────────────────────────
RESTRICTED   = "RESTRICTED"    # board/M&A/master keys — ALWAYS blocked
CONFIDENTIAL = "CONFIDENTIAL"  # customer PII, accounts, KYC — blocked
INTERNAL     = "INTERNAL"      # org-internal material — blocked externally
PUBLIC       = "PUBLIC"        # press releases, marketing — allowed

LEVEL_RANK = {PUBLIC: 0, INTERNAL: 1, CONFIDENTIAL: 2, RESTRICTED: 3}

# DOC_CLASS_TO_DECISION for the API response
DOC_CLASS_TO_DECISION = {
    RESTRICTED:   "BLOCK",
    CONFIDENTIAL: "BLOCK",
    INTERNAL:     "WARN",
    PUBLIC:       "PASS",
}
DOC_CLASS_SCORE_MAP = {
    RESTRICTED:   99.0,
    CONFIDENTIAL: 85.0,
    INTERNAL:     45.0,
    PUBLIC:        5.0,
}

# Ollama config — used for background audit only, not blocking
OLLAMA_BASE_URL = os.getenv("OLLAMA_URL", "http://ollama:11434")
OLLAMA_MODEL    = os.getenv("DOC_CLASSIFIER_MODEL", "llama3")
OLLAMA_TIMEOUT  = float(os.getenv("DOC_CLASSIFIER_TIMEOUT_S", "30"))

LLM_DESTINATIONS = [
    "chatgpt", "gemini", "claude", "deepseek", "perplexity",
    "mistral", "copilot", "openai", "anthropic", "grok", "poe",
]


@dataclass
class ClassificationResult:
    level: str
    confidence: float
    needs_review: bool
    method: str = "rule-based"
    llm_triggered: bool = False
    doc_type: str = ""
    reasons: List[str] = field(default_factory=list)
    matched_rules: List[str] = field(default_factory=list)
    # Detailed findings from deep scan
    pii_findings: List[dict] = field(default_factory=list)

    @property
    def action(self) -> str:
        if self.level in (RESTRICTED, CONFIDENTIAL):
            return "BLOCK"
        if self.level == INTERNAL:
            return "WARN"
        return "PASS"

    @property
    def color(self) -> str:
        return {"RESTRICTED": "🔴", "CONFIDENTIAL": "🟠",
                "INTERNAL": "🟡", "PUBLIC": "🟢"}.get(self.level, "⚪")


# ─────────────────────────────────────────────────────────────────────────────
# Stage 1A — Document Header / Watermark Markers (highest priority)
# ─────────────────────────────────────────────────────────────────────────────
HEADER_RULES: List[Tuple[str, str, float, str]] = [
    # RESTRICTED
    (r"(?i)\b(STRICTLY\s+CONFIDENTIAL|BARCLAYS\s+RESTRICTED|TOP\s+SECRET|HIGHLY\s+RESTRICTED)\b",
     RESTRICTED, 0.99, "Security watermark: STRICTLY CONFIDENTIAL / RESTRICTED"),
    (r"(?i)\b(Board\s+Minutes?|Board\s+Resolution|Board\s+Meeting|Minutes\s+of\s+(the\s+)?Board)\b",
     RESTRICTED, 0.97, "Board meeting document"),
    (r"(?i)\b(Merger|Acquisition|M\s*&\s*A|Takeover|Buyout|Carve.?out)\s+"
     r"(Plan|Discussion|Agreement|Terms|Target|Valuation|Proposal|Memorandum)\b",
     RESTRICTED, 0.98, "M&A / Acquisition document"),
    (r"(?i)\b(Non.?Disclosure\s+Agreement|NDA|Confidentiality\s+Agreement|Letter\s+of\s+Intent|LOI)\b",
     RESTRICTED, 0.96, "NDA / LOI document"),
    (r"(?i)\b(Insider\s+Information|Material\s+Non.?Public|MNPI|Trading\s+Restriction|Black.?out\s+Period)\b",
     RESTRICTED, 0.98, "Insider / MNPI information"),
    (r"(?i)\b(Master\s+(Key|Password|Secret|Credential)|Root\s+Credentials?|Production\s+Secrets?)\b",
     RESTRICTED, 0.99, "Master credentials / root keys"),
    (r"(?i)\b(Executive\s+Compensation|CEO\s+Remuneration|CXO\s+Package|Long.?Term\s+Incentive Plan|LTIP)\b",
     RESTRICTED, 0.95, "Executive compensation"),
    (r"(?i)\b(Project\s+Phoenix|Project\s+Mercury|Operation\s+\w+)\b",
     RESTRICTED, 0.88, "Codename project (potential M&A)"),
    # CONFIDENTIAL
    (r"(?i)\b(PRIVILEGED\s+AND\s+CONFIDENTIAL|ATTORNEY.CLIENT\s+PRIVILEGE|LEGAL\s+PRIVILEGE)\b",
     CONFIDENTIAL, 0.97, "Attorney-client privilege marker"),
    (r"(?i)\b(CONFIDENTIAL|STRICTLY\s+PRIVATE|PRIVATE\s+AND\s+CONFIDENTIAL)\b",
     CONFIDENTIAL, 0.90, "Confidential marker"),
    (r"(?i)\b(PERSONAL\s+AND\s+CONFIDENTIAL|IN\s+CONFIDENCE)\b",
     CONFIDENTIAL, 0.88, "Personal & Confidential marker"),
    # INTERNAL
    (r"(?i)\b(INTERNAL\s+USE\s+ONLY|FOR\s+INTERNAL\s+USE|NOT\s+FOR\s+EXTERNAL|BARCLAYS\s+INTERNAL)\b",
     INTERNAL, 0.92, "Internal use only marker"),
    (r"(?i)\b(DRAFT|WORKING\s+DOCUMENT|WORK\s+IN\s+PROGRESS|FOR\s+DISCUSSION\s+ONLY)\b",
     INTERNAL, 0.75, "Draft / WIP marker"),
    # PUBLIC
    (r"(?i)\b(For\s+Immediate\s+Release|Press\s+Release|Media\s+Contact)\b",
     PUBLIC, 0.95, "Press release marker"),
    (r"(?i)\b(Terms\s+and\s+Conditions|Privacy\s+Policy|Cookie\s+Policy|Published\s+Report)\b",
     PUBLIC, 0.82, "Public policy / published document"),
]

# ─────────────────────────────────────────────────────────────────────────────
# Stage 1B — Deep PII / Credential / Financial Regex Scan
# These patterns scan the actual data inside the document
# ─────────────────────────────────────────────────────────────────────────────
DEEP_SCAN_RULES: List[Tuple[str, str, str, float]] = [
    # RESTRICTED: Master credentials
    (r"(?i)(master\s+key|root\s+password|production\s+password)\s*[=:]\s*\S+",
     RESTRICTED, "Master/Root Credential", 0.99),
    (r"-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----",
     RESTRICTED, "Private Cryptographic Key", 0.99),
    # RESTRICTED: Board & insider
    (r"(?i)(board\s+of\s+directors|quorum|resolution\s+passed|extraordinary\s+general\s+meeting)",
     RESTRICTED, "Board Meeting Content", 0.95),
    (r"(?i)(acquisition\s+price|offer\s+price|enterprise\s+value|synergy|target\s+company\s+name)",
     RESTRICTED, "M&A Financial Data", 0.97),
    (r"(?i)(material\s+non.?public|insider\s+trade|front.?running|tipping.?off)",
     RESTRICTED, "Insider Trading Content", 0.99),

    # CONFIDENTIAL: Financial PII
    (r"\b4[0-9]{12}(?:[0-9]{3})?\b",
     CONFIDENTIAL, "Visa Card Number", 0.96),
    (r"\b5[1-5][0-9]{14}\b",
     CONFIDENTIAL, "Mastercard Number", 0.96),
    (r"\b3[47][0-9]{13}\b",
     CONFIDENTIAL, "Amex Card Number", 0.96),
    (r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7,26}\b",
     CONFIDENTIAL, "IBAN", 0.95),
    (r"\b\d{2}-\d{2}-\d{2}\b",
     CONFIDENTIAL, "UK Sort Code", 0.85),
    (r"(?i)account\s*(number|no|#)?\s*[=:.]?\s*\d{8,18}\b",
     CONFIDENTIAL, "Bank Account Number", 0.92),
    (r"(?i)(cvv|cvc|security\s+code)\s*[=:]\s*\d{3,4}\b",
     CONFIDENTIAL, "CVV/CVC Code", 0.98),

    # CONFIDENTIAL: Personal PII
    (r"\b\d{3}-\d{2}-\d{4}\b",
     CONFIDENTIAL, "US SSN", 0.97),
    (r"\b[A-Z]{2}[0-9]{6}[A-Z]\b",
     CONFIDENTIAL, "UK NI Number", 0.95),
    (r"\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b",
     CONFIDENTIAL, "Aadhaar Number", 0.97),
    (r"\b\d{4}-\d{4}-\d{4}\b",
     CONFIDENTIAL, "Aadhaar (Dashed)", 0.96),
    (r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
     CONFIDENTIAL, "PAN Number", 0.95),
    (r"(?i)(date\s+of\s+birth|dob)\s*[=:,]?\s*\d{1,2}[-/\s]\w+[-/\s]\d{2,4}",
     CONFIDENTIAL, "Date of Birth", 0.90),
    (r"(?i)passport\s*(number|no|#)?\s*[=:]\s*[A-Z]{1,2}\d{6,9}\b",
     CONFIDENTIAL, "Passport Number", 0.95),
    (r"(?i)(salary|compensation|ctc|annual\s+pay)\s*(is|[:=])?\s*[£$€¥]?\s*[\d,]+",
     CONFIDENTIAL, "Salary Figure", 0.90),
    (r"(?i)performance\s+(rating|score|review)\s*[=:]?\s*\d[\./]\d",
     CONFIDENTIAL, "Performance Rating", 0.88),
    (r"(?i)(credit\s+score|cibil\s+score)\s*[=:]?\s*\d{3,4}",
     CONFIDENTIAL, "Credit Score", 0.92),

    # CONFIDENTIAL: Customer/KYC data
    (r"(?i)(know\s+your\s+customer|kyc|aml|anti.?money\s+laundering|suspicious\s+activity\s+report|sar)\b",
     CONFIDENTIAL, "KYC/AML Document", 0.94),
    (r"(?i)(loan\s+amount|repayment\s+schedule|emi|equated\s+monthly|credit\s+facility|collateral)\b",
     CONFIDENTIAL, "Loan/Credit Document", 0.90),
    (r"(?i)transaction\s+(id|reference|ref)\s*[=:.]?\s*[A-Z0-9]{6,}",
     CONFIDENTIAL, "Transaction Reference", 0.85),

    # CONFIDENTIAL: Credentials in documents
    (r"(?i)(password|passwd|pwd|secret|api_key|apikey|token|access_key)\s*[=:]\s*\S{6,}",
     CONFIDENTIAL, "Hardcoded Credential", 0.96),
    (r"\bAKIA[0-9A-Z]{16}\b",
     CONFIDENTIAL, "AWS Access Key", 0.99),
    (r"\bsk-[A-Za-z0-9]{32,}\b",
     CONFIDENTIAL, "OpenAI API Key", 0.99),
    (r"\bghp_[A-Za-z0-9]{36}\b",
     CONFIDENTIAL, "GitHub Personal Access Token", 0.99),
    (r"(?i)AccountKey\s*=\s*['\"]?[A-Za-z0-9+/]{20,}={0,2}['\"]?",
     CONFIDENTIAL, "Azure Account Key", 0.98),
    (r"(?i)DefaultEndpointsProtocol=https;AccountName=",
     CONFIDENTIAL, "Azure Storage Connection String", 0.99),
    (r"eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}",
     CONFIDENTIAL, "JWT Token", 0.97),

    # INTERNAL
    (r"(?i)(sprint\s+planning|backlog|user\s+story|jira\s+ticket|confluence|epic|story\s+point)",
     INTERNAL, "Internal Project Tracker", 0.78),
    (r"(?i)(org\s+chart|reporting\s+structure|headcount|organisational\s+chart|team\s+structure)",
     INTERNAL, "Org Chart", 0.80),
    (r"(?i)(employee\s+handbook|code\s+of\s+conduct|acceptable\s+use\s+policy|data\s+governance)",
     INTERNAL, "Internal Policy", 0.80),
    (r"(?i)(internal\s+memo|all.?hands|town\s+hall|staff\s+circular|all\s+staff\s+email)",
     INTERNAL, "Internal Memo", 0.82),
]

# ─────────────────────────────────────────────────────────────────────────────
# Stage 1C — Document Type Detection (keyword density scoring)
# ─────────────────────────────────────────────────────────────────────────────
DOCUMENT_TYPE_RULES: List[Tuple[List[str], str, float, str]] = [
    # RESTRICTED
    (["board of directors", "resolution", "quorum", "minutes of the meeting", "chairman", "secretary"],
     RESTRICTED, 0.96, "Board Meeting Minutes"),
    (["non-disclosure agreement", "nda", "confidentiality obligation",
      "target company", "letter of intent", "due diligence", "exclusivity"],
     RESTRICTED, 0.97, "M&A / NDA Document"),
    (["insider information", "material non-public", "mnpi", "trading restriction",
      "blackout period", "front-running"],
     RESTRICTED, 0.98, "Insider Information"),
    (["executive salary", "ceo compensation", "board remuneration",
      "long-term incentive", "esop grant", "cxo package"],
     RESTRICTED, 0.94, "Executive Compensation"),
    (["acquisition", "merger", "takeover", "target", "synergy", "enterprise value",
      "deal structure", "bid price"],
     RESTRICTED, 0.93, "M&A Document"),

    # CONFIDENTIAL
    (["account number", "sort code", "iban", "swift", "account balance",
      "transaction history", "statement of account", "bank statement"],
     CONFIDENTIAL, 0.93, "Bank Account Statement"),
    (["customer name", "date of birth", "address", "kyc", "know your customer",
      "identity verification", "proof of address", "aml"],
     CONFIDENTIAL, 0.92, "KYC/AML Document"),
    (["loan amount", "interest rate", "repayment schedule", "collateral",
      "credit score", "loan application", "emi", "equated monthly", "principal"],
     CONFIDENTIAL, 0.91, "Loan / Credit Application"),
    (["employee id", "performance rating", "annual appraisal", "salary",
      "compensation", "ctc", "payroll", "pay slip", "gross pay", "net pay"],
     CONFIDENTIAL, 0.90, "Employee HR Record"),
    (["aml", "anti-money laundering", "suspicious transaction",
      "suspicious activity report", "financial crime", "cft", "counter terrorism"],
     CONFIDENTIAL, 0.94, "AML / Compliance Report"),
    (["aadhaar", "pan card", "voter id", "passport number", "biometric",
      "driving licence", "national id"],
     CONFIDENTIAL, 0.96, "Government ID Document"),
    (["credit card number", "card number", "cvv", "expiry date", "cardholder",
      "card verification", "security code"],
     CONFIDENTIAL, 0.96, "Payment Card Data"),
    (["health record", "medical history", "diagnosis", "prescription",
      "hospital", "patient id", "nhs number", "clinical"],
     CONFIDENTIAL, 0.94, "Medical / Health Record"),
    (["litigation", "lawsuit", "legal proceedings", "court order", "subpoena",
      "legal counsel", "privileged", "without prejudice"],
     CONFIDENTIAL, 0.92, "Legal Document"),

    # INTERNAL
    (["organisational chart", "org chart", "reporting structure", "headcount", "spans and layers"],
     INTERNAL, 0.83, "Org Chart"),
    (["sprint planning", "backlog", "user story", "jira", "confluence",
      "project roadmap", "milestone", "acceptance criteria"],
     INTERNAL, 0.77, "Internal Project Document"),
    (["training material", "onboarding guide", "employee handbook",
      "code of conduct", "desk manual", "induction"],
     INTERNAL, 0.80, "Internal Training Material"),
    (["internal memo", "all-hands", "town hall", "staff circular", "all staff"],
     INTERNAL, 0.82, "Internal Memo"),
    (["it policy", "acceptable use policy", "information security policy",
      "data governance", "change management", "incident response"],
     INTERNAL, 0.84, "Internal IT Policy"),
    (["product roadmap", "feature backlog", "go-to-market", "launch plan",
      "competitive analysis", "market research"],
     INTERNAL, 0.80, "Internal Product Strategy"),

    # PUBLIC
    (["press release", "media contact", "for immediate release",
      "investor relations", "published report"],
     PUBLIC, 0.90, "Press Release"),
    (["product brochure", "product leaflet", "marketing material",
      "advertisement", "promotional", "prospectus"],
     PUBLIC, 0.87, "Marketing Material"),
    (["annual report", "corporate social responsibility", "sustainability report",
      "esg report", "pillar 3"],
     PUBLIC, 0.84, "Public Annual Report"),
]

# Context boosts — how many levels to escalate based on context
CONTEXT_BOOSTS = {
    "llm_destination": 2,  # sending to any AI platform escalates 2 levels
    "external_email":  1,
    "executive_user":  1,
    "hr_source":       1,
    "trading_source":  2,
    "off_hours":       1,
}


# ─────────────────────────────────────────────────────────────────────────────
# Main Classifier
# ─────────────────────────────────────────────────────────────────────────────

class DocumentClassifier:
    """
    Hybrid document classifier — fully offline, no LLM blocking:
      Stage 1A: Header watermark markers (regex, instant, highest priority)
      Stage 1B: Deep PII/credential regex scan on document body
      Stage 1C: Keyword density scoring by document type
      Stage 2:  Contextual escalation (destination, role, source)
    """

    def __init__(self):
        logger.info("DocumentClassifier v3 ready (rule-based, fully offline)")

    async def classify(
        self,
        text: str,
        filename: str = "",
        context: dict | None = None,
    ) -> ClassificationResult:
        context = context or {}
        combined = (filename + "\n" + text).lower()
        full_text = filename + "\n" + text  # original case for regex

        # ── Stage 1A: Header markers ──────────────────────────────────────────
        header_level, header_conf, header_reason = self._check_headers(full_text)

        # ── Stage 1B: Deep PII/credential scan ───────────────────────────────
        deep_level, deep_conf, deep_findings = self._deep_scan(full_text)

        # ── Stage 1C: Keyword density ─────────────────────────────────────────
        kw_level, kw_conf, kw_type, kw_reasons = self._keyword_density(combined)

        # ── Merge results — take the HIGHEST risk signal ──────────────────────
        candidates = [
            (header_level, header_conf, header_reason or "Header marker", "Header Marker"),
            (deep_level,   deep_conf,   f"Deep scan: {len(deep_findings)} PII/credential patterns found", deep_level),
            (kw_level,     kw_conf,     kw_reasons[0] if kw_reasons else "Keyword match", kw_type or "Keyword Match"),
        ]
        best = max(candidates, key=lambda x: (LEVEL_RANK.get(x[0], 0), x[1]))
        level, confidence, reason, doc_type = best

        matched_rules: List[str] = []
        if header_reason:
            matched_rules.append(f"Header: {header_reason}")
        for f in deep_findings[:5]:
            matched_rules.append(f"Deep scan: {f['category']} detected → {f['level']}")
        matched_rules.extend(kw_reasons[:3])

        # ── Stage 2: Contextual escalation ───────────────────────────────────
        level, confidence, boost_notes = self._contextual_boost(level, confidence, context)
        matched_rules.extend(boost_notes)

        needs_review = confidence < 0.65

        return ClassificationResult(
            level=level,
            confidence=round(confidence, 3),
            needs_review=needs_review,
            method="rule-based-v3",
            llm_triggered=False,
            doc_type=doc_type,
            reasons=self._build_reasons(level, matched_rules),
            matched_rules=matched_rules,
            pii_findings=[{"category": f["category"], "level": f["level"]} for f in deep_findings[:10]],
        )

    def _check_headers(self, text: str) -> Tuple[str, float, str]:
        """Stage 1A: Check for document watermarks and header markers."""
        best_level = INTERNAL
        best_conf  = 0.35  # conservative default (unknown = treat as internal)
        best_reason = ""
        for pat, level, conf, reason in HEADER_RULES:
            if re.search(pat, text):
                if conf > best_conf:
                    best_level  = level
                    best_conf   = conf
                    best_reason = reason
        return best_level, best_conf, best_reason

    def _deep_scan(self, text: str) -> Tuple[str, float, List[dict]]:
        """Stage 1B: Scan for actual PII, credentials, and financial data."""
        findings: List[dict] = []
        best_level = PUBLIC
        best_conf  = 0.10

        for pat, level, category, conf in DEEP_SCAN_RULES:
            if re.search(pat, text):
                findings.append({"category": category, "level": level, "conf": conf})
                rank = LEVEL_RANK.get(level, 0)
                if rank > LEVEL_RANK.get(best_level, 0) or (rank == LEVEL_RANK.get(best_level, 0) and conf > best_conf):
                    best_level = level
                    best_conf  = conf

        return best_level, best_conf, findings

    def _keyword_density(self, combined: str) -> Tuple[str, float, str, List[str]]:
        """Stage 1C: Keyword co-occurrence density scoring."""
        best_level = PUBLIC
        best_conf  = 0.10
        best_type  = ""
        reasons: List[str] = []

        for keywords, level, weight, doc_type in DOCUMENT_TYPE_RULES:
            hits = sum(1 for kw in keywords if kw in combined)
            if hits == 0:
                continue
            density = hits / len(keywords)
            score   = weight * min(density * 2.0, 1.0)
            rank    = LEVEL_RANK.get(level, 0)
            if rank > LEVEL_RANK.get(best_level, 0) or (rank == LEVEL_RANK.get(best_level, 0) and score > best_conf):
                best_conf  = round(score, 3)
                best_level = level
                best_type  = doc_type
                reasons    = [f"Keyword match — {doc_type}: {hits}/{len(keywords)} keywords matched (confidence={score:.0%})"]

        return best_level, best_conf, best_type, reasons

    def _contextual_boost(
        self, level: str, confidence: float, context: dict
    ) -> Tuple[str, float, List[str]]:
        """Stage 2: Escalate classification based on destination and context."""
        notes: List[str] = []
        boost = 0

        dest = context.get("destination", "").lower()
        if any(d in dest for d in LLM_DESTINATIONS):
            boost += CONTEXT_BOOSTS["llm_destination"]
            notes.append(f"⚠️ Destination is an external LLM ({dest}) — escalating +{CONTEXT_BOOSTS['llm_destination']} levels")

        role = context.get("user_role", "").lower()
        if role in ("executive", "ceo", "cfo", "cto", "ciso", "vp", "svp", "md", "director"):
            boost += CONTEXT_BOOSTS["executive_user"]
            notes.append(f"Executive role ({role}) — escalating +1 level")

        source = context.get("source_system", "").lower()
        if any(s in source for s in ("hr", "peoplesoft", "workday", "successfactors")):
            boost += CONTEXT_BOOSTS["hr_source"]
            notes.append("HR source system — minimum CONFIDENTIAL")
        if any(s in source for s in ("trading", "bloomberg", "murex", "summit", "calypso")):
            boost += CONTEXT_BOOSTS["trading_source"]
            notes.append("Trading system source — minimum RESTRICTED")

        if context.get("off_hours"):
            boost += CONTEXT_BOOSTS["off_hours"]
            notes.append("Off-hours access detected — escalating +1 level")

        levels = [PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED]
        cur_rank = LEVEL_RANK.get(level, 0)
        new_rank = min(cur_rank + boost, 3)
        new_level = levels[new_rank]

        if new_rank > cur_rank:
            confidence = min(confidence + 0.05 * boost, 0.99)

        return new_level, confidence, notes

    def _build_reasons(self, level: str, rules: List[str]) -> List[str]:
        action_text = {
            RESTRICTED:   "🔴 RESTRICTED — Transmission BLOCKED. This document must never leave the organization.",
            CONFIDENTIAL: "🟠 CONFIDENTIAL — Transmission BLOCKED. Contains sensitive PII, financial, or credential data.",
            INTERNAL:     "🟡 INTERNAL — External transmission blocked. Permitted within the organization only.",
            PUBLIC:       "🟢 PUBLIC — Cleared for transmission. Audit entry created.",
        }
        return [action_text.get(level, ""), *rules[:6]]


doc_classifier = DocumentClassifier()
