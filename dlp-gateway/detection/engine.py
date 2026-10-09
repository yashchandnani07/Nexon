"""DLP Detection Engine — 10-layer async scanner (regex + NER + entropy, no LLM)"""
from __future__ import annotations

import re
import os
import math
import base64
import asyncio
import logging
import time
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple

from detection.patterns import (
    CREDENTIAL_PATTERNS, CARD_REGEX, FINANCIAL_PATTERNS,
    PII_PATTERNS, PII_NER_LABELS, CONFIDENTIAL_PATTERNS,
    EMPLOYEE_PATTERNS, STRATEGY_PATTERNS, INTENT_PATTERNS,
    ENTROPY_MIN_LENGTH, ENTROPY_THRESHOLD, ENTROPY_SEVERITY,
    FUZZY_KEYWORDS, FUZZY_THRESHOLD, FUZZY_SEVERITY,
    INVISIBLE_CHARS,
)

logger = logging.getLogger("dlp.engine")


@dataclass
class DLPFinding:
    layer: str
    category: str
    severity: float
    snippet: str
    explanation: str


@dataclass
class DLPScanResult:
    decision: str
    risk_score: float
    risk_tier: str
    detected_types: List[str]
    findings: List[dict]
    layer_scores: Dict[str, float]
    processing_ms: float
    block_reason: str = ""
    from_cache: bool = False
    llm_triggered: bool = False          # True if L11 LLM raised the risk score


class DLPEngine:
    def __init__(self):
        self._gliner = self._load_gliner()
        self._fuzzy = self._load_fuzzy()
        logger.info(
            "DLPEngine v2 ready — GLiNER=%s RapidFuzz=%s (no LLM)",
            "✓" if self._gliner else "✗",
            "✓" if self._fuzzy else "✗",
        )

    # ── Loaders ───────────────────────────────────────────────────────────────
    def _load_gliner(self):
        try:
            from gliner import GLiNER
            local_path = os.getenv("GLINER_MODEL_PATH", "./models/gliner_medium")
            if not os.path.isdir(local_path):
                logger.warning("GLiNER model not found at %s — NER disabled.", local_path)
                return None
            model = GLiNER.from_pretrained(local_path, local_files_only=True)
            logger.info("GLiNER loaded from %s ✓", local_path)
            return model
        except Exception as e:
            logger.warning("GLiNER load failed: %s", e)
            return None

    def _load_fuzzy(self):
        try:
            from rapidfuzz import fuzz
            return fuzz
        except Exception as e:
            logger.warning("RapidFuzz unavailable: %s", e)
            return None

    # ── Public scan API ───────────────────────────────────────────────────────
    async def scan(
        self,
        prompt: str,
        department: str = "default",
        extra_text: str = "",
    ) -> DLPScanResult:
        start = time.perf_counter()
        combined = (prompt + "\n\n" + extra_text).strip()

        ALL_LAYERS = [
            "credential", "financial", "confidential", "employee",
            "strategy", "entropy", "obfuscated", "pii", "fuzzy", "intent",
        ]
        WEIGHTS = {
            "credential": 1.00, "financial": 1.00, "pii": 0.90,
            "confidential": 0.95, "employee": 0.85, "strategy": 0.82,
            "entropy": 0.90, "fuzzy": 0.78, "obfuscated": 0.95,
            "intent": 0.88,
        }

        layer_scores: Dict[str, float] = {l: 0.0 for l in ALL_LAYERS}
        all_findings: List[DLPFinding] = []

        # Fast layers — run in parallel
        fast_results = await asyncio.gather(
            asyncio.to_thread(self._l1_credentials, combined),
            asyncio.to_thread(self._l2_financial, combined),
            asyncio.to_thread(self._l4_confidential, combined),
            asyncio.to_thread(self._l5_employee, combined),
            asyncio.to_thread(self._l6_strategy, combined),
            asyncio.to_thread(self._l7_entropy, combined),
            asyncio.to_thread(self._l9_obfuscated, combined),
        )
        fast_labels = [
            "credential", "financial", "confidential",
            "employee", "strategy", "entropy", "obfuscated",
        ]
        for label, (findings, score) in zip(fast_labels, fast_results):
            all_findings.extend(findings)
            layer_scores[label] = round(score, 3)

        fast_max = max(layer_scores[lbl] * WEIGHTS[lbl] for lbl in fast_labels)

        # Slow layers — only run if fast layers haven't already flagged
        if fast_max < 0.50:
            slow_results = await asyncio.gather(
                asyncio.to_thread(self._l3_pii, combined),
                asyncio.to_thread(self._l8_fuzzy, combined),
                asyncio.to_thread(self._l10_intent, combined),
            )
            for label, (findings, score) in zip(["pii", "fuzzy", "intent"], slow_results):
                all_findings.extend(findings)
                layer_scores[label] = round(score, 3)
        else:
            # Intent regex is cheap — always run it
            intent_findings, intent_score = self._l10_intent(combined)
            all_findings.extend(intent_findings)
            layer_scores["intent"] = round(intent_score, 3)

        # Final risk score from regex/NER layers only
        raw = max(
            (layer_scores[lbl] * WEIGHTS[lbl] for lbl in ALL_LAYERS),
            default=0.0,
        )
        risk_score = round(min(raw, 1.0) * 100, 1)
        tier = (
            "critical" if risk_score >= 80
            else "high"   if risk_score >= 60
            else "medium" if risk_score >= 30
            else "low"
        )
        decision = (
            "BLOCK" if risk_score >= 55
            else "WARN" if risk_score >= 30
            else "PASS"
        )
        detected    = list({f.category for f in all_findings})
        block_reason = self._build_reason(all_findings, tier) if decision == "BLOCK" else ""

        return DLPScanResult(
            decision=decision,
            risk_score=risk_score,
            risk_tier=tier,
            detected_types=detected,
            findings=[{
                "layer":       f.layer,
                "category":    f.category,
                "severity":    round(f.severity, 3),
                "snippet":     f.snippet,
                "explanation": f.explanation,
            } for f in all_findings],
            layer_scores=layer_scores,
            processing_ms=round((time.perf_counter() - start) * 1000, 2),
            block_reason=block_reason,
            llm_triggered=False,
        )

    # ── Layer 1: API keys, passwords, tokens ──────────────────────────────────
    def _l1_credentials(self, text: str) -> Tuple[List[DLPFinding], float]:
        findings, max_s = [], 0.0
        for pat, label, sev in CREDENTIAL_PATTERNS:
            if re.search(pat, text):
                findings.append(DLPFinding(
                    "credential", label, sev,
                    f"[{label.upper()}]",
                    f"{label} detected. Sharing credentials with external AI is a critical violation.",
                ))
                max_s = max(max_s, sev)
        return findings, max_s

    # ── Layer 2: Payment cards, IFSC, account numbers ─────────────────────────
    def _luhn(self, n: str) -> bool:
        d = [int(x) for x in n if x.isdigit()]
        for i, v in enumerate(reversed(d)):
            if i % 2 == 1:
                v *= 2
                if v > 9:
                    v -= 9
            d[-(i + 1)] = v
        return sum(d) % 10 == 0

    def _l2_financial(self, text: str) -> Tuple[List[DLPFinding], float]:
        findings, max_s = [], 0.0
        for m in CARD_REGEX.finditer(text):
            num = re.sub(r"\D", "", m.group())
            if self._luhn(num):
                findings.append(DLPFinding(
                    "financial", "Payment Card Number", 0.97,
                    f"****-****-****-{num[-4:]}",
                    "Luhn-validated payment card detected. PCI-DSS violation.",
                ))
                max_s = max(max_s, 0.97)
        for pat, label, sev in FINANCIAL_PATTERNS:
            if re.search(pat, text):
                findings.append(DLPFinding(
                    "financial", label, sev,
                    f"[{label.upper()}]",
                    f"{label} detected. Financial identifiers must not be sent to external AI.",
                ))
                max_s = max(max_s, sev)
        return findings, max_s

    # ── Layer 3: PII — regex + optional GLiNER NER ────────────────────────────
    _NER_ALLOWLIST = {
        "app", "cafe", "build", "want", "make", "create", "help", "need",
        "data", "user", "system", "web", "site", "api", "code", "service",
        "tool", "team", "form", "page", "list", "type", "mode", "plan",
        "bank", "card", "date", "time", "name", "test", "demo", "base",
    }

    def _l3_pii(self, text: str) -> Tuple[List[DLPFinding], float]:
        findings, max_s = [], 0.0

        for pat, label, sev in PII_PATTERNS:
            if re.search(pat, text):
                findings.append(DLPFinding(
                    "pii", label, sev,
                    f"[{label.upper()}]",
                    f"{label} detected. DPDP/GDPR compliance violation.",
                ))
                max_s = max(max_s, sev)

        if self._gliner:
            try:
                ents = self._gliner.predict_entities(
                    text[:3000], PII_NER_LABELS, threshold=0.72
                )
                seen: set = set()
                for e in ents:
                    et = e["text"].strip().lower()
                    if et in self._NER_ALLOWLIST or len(et) <= 2:
                        continue
                    k = (e["label"], et[:20])
                    if k in seen:
                        continue
                    seen.add(k)
                    sev = round(e["score"] * 0.92, 3)
                    findings.append(DLPFinding(
                        "pii", e["label"].title(), sev,
                        f"[{e['label'].upper()}]",
                        f"Personal data ({e['label']}) detected at {e['score']:.0%} confidence.",
                    ))
                    max_s = max(max_s, sev)
            except Exception as ex:
                logger.warning("GLiNER inference error: %s", ex)

        return findings, max_s

    # ── Layer 4: Confidential document markers ────────────────────────────────
    def _l4_confidential(self, text: str) -> Tuple[List[DLPFinding], float]:
        findings, max_s = [], 0.0
        for pat, label, sev in CONFIDENTIAL_PATTERNS:
            if re.search(pat, text, re.IGNORECASE):
                findings.append(DLPFinding(
                    "confidential", label, sev,
                    f"[{label.upper()}]",
                    f"Document marked '{label}' detected. Sharing restricted docs with AI is prohibited.",
                ))
                max_s = max(max_s, sev)
        return findings, max_s

    # ── Layer 5: Employee / HR data ───────────────────────────────────────────
    def _l5_employee(self, text: str) -> Tuple[List[DLPFinding], float]:
        findings, max_s = [], 0.0
        for pat, label, sev in EMPLOYEE_PATTERNS:
            if re.search(pat, text, re.IGNORECASE):
                findings.append(DLPFinding(
                    "employee", label, sev,
                    f"[{label.upper()}]",
                    f"Employee/HR data ({label}) detected. Sharing HR data with AI violates policy.",
                ))
                max_s = max(max_s, sev)
        return findings, max_s

    # ── Layer 6: Business strategy / IP ──────────────────────────────────────
    def _l6_strategy(self, text: str) -> Tuple[List[DLPFinding], float]:
        findings, max_s = [], 0.0
        for pat, label, sev in STRATEGY_PATTERNS:
            if re.search(pat, text, re.IGNORECASE):
                findings.append(DLPFinding(
                    "strategy", label, sev,
                    f"[{label.upper()}]",
                    f"Business-sensitive content ({label}) detected. IP/strategy must not leave org.",
                ))
                max_s = max(max_s, sev)
        return findings, max_s

    # ── Layer 7: High-entropy strings (JWT, API keys, secrets) ───────────────
    @staticmethod
    def _shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        freq: Dict[str, int] = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        return -sum(
            (v / len(s)) * math.log2(v / len(s))
            for v in freq.values()
        )

    def _l7_entropy(self, text: str) -> Tuple[List[DLPFinding], float]:
        findings, max_s = [], 0.0
        tokens = re.findall(r"[A-Za-z0-9+/=_\-]{20,}", text)
        for token in tokens:
            if len(token) < ENTROPY_MIN_LENGTH:
                continue
            entropy = self._shannon_entropy(token)
            if entropy >= ENTROPY_THRESHOLD:
                sev = min(ENTROPY_SEVERITY + (entropy - ENTROPY_THRESHOLD) * 0.08, 0.95)
                findings.append(DLPFinding(
                    "entropy", "High-Entropy Secret", round(sev, 3),
                    f"{token[:6]}…{token[-4:]}",
                    f"High-entropy token (entropy={entropy:.2f}). Possible API key, JWT or secret.",
                ))
                max_s = max(max_s, sev)
        return findings, max_s

    # ── Layer 8: Fuzzy keyword matching ──────────────────────────────────────
    def _l8_fuzzy(self, text: str) -> Tuple[List[DLPFinding], float]:
        findings, max_s = [], 0.0
        if not self._fuzzy:
            return findings, max_s
        words = re.findall(r"\b\w{4,}\b", text.lower())
        for word in set(words):
            for keyword in FUZZY_KEYWORDS:
                score = self._fuzzy.ratio(word, keyword) / 100.0
                if score >= FUZZY_THRESHOLD:
                    sev = round(FUZZY_SEVERITY * score, 3)
                    findings.append(DLPFinding(
                        "fuzzy", f"Fuzzy match: {keyword}", sev,
                        f"[~{keyword}]",
                        f"Keyword '{word}' resembles '{keyword}' ({score:.0%} match).",
                    ))
                    max_s = max(max_s, sev)
        return findings, max_s

    # ── Layer 9: Obfuscation / invisible chars / base64 secrets ──────────────
    def _l9_obfuscated(self, text: str) -> Tuple[List[DLPFinding], float]:
        findings, max_s = [], 0.0

        for char in INVISIBLE_CHARS:
            if char in text:
                findings.append(DLPFinding(
                    "obfuscated", f"U+{ord(char):04X}", 0.88,
                    f"[U+{ord(char):04X}]",
                    f"Invisible character (U+{ord(char):04X}) detected. Possible prompt injection.",
                ))
                max_s = max(max_s, 0.88)

        for b64 in re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", text):
            try:
                decoded = base64.b64decode(b64 + "==").decode("utf-8", errors="ignore")
                if any(kw in decoded.lower() for kw in ["password", "secret", "token", "key", "private"]):
                    findings.append(DLPFinding(
                        "obfuscated", "Base64 Encoded Secret", 0.91,
                        f"{b64[:10]}…",
                        "Base64 block decodes to sensitive keywords. Possible secret exfiltration.",
                    ))
                    max_s = max(max_s, 0.91)
            except Exception:
                pass

        return findings, max_s

    # ── Layer 10: Intent detection (regex only, no LLM) ──────────────────────
    def _l10_intent(self, text: str) -> Tuple[List[DLPFinding], float]:
        findings, max_s = [], 0.0
        for pat, label, sev in INTENT_PATTERNS:
            if re.search(pat, text, re.IGNORECASE):
                findings.append(DLPFinding(
                    "intent", label, sev,
                    f"[INTENT: {label.upper()}]",
                    f"Data exfiltration intent detected: {label}. Policy violation.",
                ))
                max_s = max(max_s, sev)
        return findings, max_s

    # ── Helpers ───────────────────────────────────────────────────────────────
    @staticmethod
    def _build_reason(findings: List[DLPFinding], tier: str) -> str:
        if not findings:
            return "Security policy violation detected."
        top = sorted(findings, key=lambda f: f.severity, reverse=True)[:3]
        cats = ", ".join(f.category for f in top)
        verb = {
            "critical": "critically",
            "high":     "significantly",
            "medium":   "potentially",
        }.get(tier, "")
        return (
            f"Your message {verb} violates data security policy. "
            f"Detected: {cats}. This request is blocked and logged."
        )


dlp_engine = DLPEngine()
