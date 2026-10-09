"""
ner_detector.py  –  NER Layer (BERT-based PII detection)
==========================================================
Primary model : SoelMgd/bert-pii-detection  (HuggingFace)
Fallback       : NLTK ne_chunk  (if model unavailable / failed to load)

The BERT model classifies tokens into PII entity types
(PER, ORG, LOC, EMAIL, DATE, PHONE, ADDRESS, etc.) and is far more
accurate than a rule-based tagger for detecting real PII in email bodies.

Deduplication is performed via SHA-256 hash of the raw entity text, so
no entity is ever reported twice even when the same name appears in
multiple overlapping windows.
"""

from __future__ import annotations

import re
import hashlib
from typing import Optional
from patterns import redact, hash_value

# ─────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────
BERT_MODEL_NAME = "SoelMgd/bert-pii-detection"

# Keyword list – paragraphs must contain one of these to be NER-scanned
CRED_KEYWORDS = [
    "password", "passwd", "pwd", "secret", "token", "key",
    "pin", "otp", "cvv", "account number", "card number",
    "sort code", "iban", "api key", "auth", "credential",
    "login", "passphrase", "access key",
    "welcome", "dear", "confidential", "username",
    "system access", "details", "induction", "regards",
    "access details", "please find", "as discussed",
    "please keep", "do not share", "verification", "code", "initiated",
    "re-verification", "suspended", "blocked", "closure",
    "confirm", "validate", "verify",
]

# Sensitive sentence patterns (regex – run regardless of BERT availability)
SENSITIVE_PATTERNS = [
    r"(?i)(your|my|the)\s+(password|pin|otp|token)\s+(is|was|:)\s+\S+",
    r"(?i)(please|kindly)\s+(use|enter)\s+(otp|pin|password)\s*[:]\s*\d+",
    r"(?i)credentials?\s*[:=]\s*\S+",
    r"(?i)login\s+(details?|info)\s*[:]\s*\S+",
    r"(?i)(maiden|mother.?s)\s+name\s+(is|was|:)\s+\S+",
    r"(?i)date\s+of\s+birth\s*(is|was|:)\s*[\d\/\-]+",
    r"(?i)passport\s+(number|no)?\s*(is|:)\s*[A-Z0-9]+",
    r"(?i)sort\s+code\s*(is|:)\s*[\d\-]+",
    r"(?i)account\s+(number|no)\s*(is|:)\s*[\d]+",
]

# Entity-type → (risk_tier, description template, category)
ENTITY_RISK_MAP: dict[str, tuple[str, str, str]] = {
    "PER":     ("Medium", "Person name detected (PII exposure)",           "named_entity"),
    "PERSON":  ("Medium", "Person name detected (PII exposure)",           "named_entity"),
    "ORG":     ("Low",    "Organisation name in credential context",       "named_entity"),
    "LOC":     ("Low",    "Location in credential context",                "named_entity"),
    "GPE":     ("Low",    "Geo-political entity in credential context",    "named_entity"),
    "EMAIL":   ("High",   "Email address exposed (PII)",                   "personal_info"),
    "PHONE":   ("High",   "Phone number exposed (PII)",                    "personal_info"),
    "ADDRESS": ("High",   "Physical address exposed (PII)",                "personal_info"),
    "DATE":    ("Low",    "Date of birth or sensitive date exposed",        "personal_info"),
    "ID":      ("High",   "Government/national ID number exposed",         "identity"),
    "NORP":    ("Low",    "Nationality/religious/political group found",    "named_entity"),
    "MISC":    ("Low",    "Miscellaneous named entity in credential context","named_entity"),
}

DEFAULT_ENTITY_RISK = ("Low", "Named entity in credential context", "named_entity")

# Confidence scores by source
BERT_CONFIDENCE  = 0.82
NLTK_CONFIDENCE  = 0.60
REGEX_CONFIDENCE = 0.80


# ─────────────────────────────────────────────────────────────
# Model loading  (lazy – only imported once on first call)
# ─────────────────────────────────────────────────────────────
_bert_pipeline = None          # None = not tried; False = failed
_bert_load_error: Optional[str] = None


def _get_bert_pipeline():
    """Return the HuggingFace NER pipeline, or None if unavailable."""
    global _bert_pipeline, _bert_load_error
    if _bert_pipeline is False:        # already tried and failed
        return None
    if _bert_pipeline is not None:     # already loaded
        return _bert_pipeline

    try:
        from transformers import pipeline
        print(f"[ner] Loading BERT model: {BERT_MODEL_NAME} …")
        _bert_pipeline = pipeline(
            "token-classification",
            model=BERT_MODEL_NAME,
            aggregation_strategy="simple",    # merge sub-tokens into full entities
        )
        print(f"[ner] BERT model loaded successfully")
        return _bert_pipeline
    except Exception as exc:
        _bert_load_error = str(exc)
        print(f"[ner] BERT model unavailable ({exc}); falling back to NLTK")
        _bert_pipeline = False
        return None


# ─────────────────────────────────────────────────────────────
# BERT entity extraction
# ─────────────────────────────────────────────────────────────

def _bert_get_entities(text: str) -> list[tuple[str, str, float]]:
    """
    Returns list of (entity_text, entity_label, score) detected by BERT.
    Processes text in 512-token-safe chunks.
    """
    pipe = _get_bert_pipeline()
    if not pipe:
        return []

    MAX_CHARS = 1800   # safe char limit per BERT call (~512 tokens)
    entities: list[tuple[str, str, float]] = []

    for i in range(0, len(text), MAX_CHARS):
        chunk = text[i : i + MAX_CHARS]
        try:
            results = pipe(chunk)
        except Exception as exc:
            print(f"[ner] BERT inference error on chunk: {exc}")
            continue

        for ent in results:
            raw   = ent.get("word", "").strip()
            label = ent.get("entity_group", "MISC").upper()
            score = float(ent.get("score", 0.0))
            if raw and score >= 0.55:        # filter very-low-confidence tokens
                entities.append((raw, label, score))

    return entities


# ─────────────────────────────────────────────────────────────
# NLTK fallback entity extraction
# ─────────────────────────────────────────────────────────────

def _nltk_get_entities(text: str) -> list[tuple[str, str, float]]:
    """Fallback NLTK chunker – returns (entity_text, label, fixed_score)."""
    try:
        import nltk
        from nltk import word_tokenize, pos_tag, ne_chunk
        from nltk.tree import Tree

        # Ensure NLTK data is available silently
        for resource in ("punkt", "averaged_perceptron_tagger", "maxent_ne_chunker", "words"):
            try:
                nltk.data.find(f"tokenizers/{resource}" if resource == "punkt" else resource)
            except LookupError:
                try:
                    nltk.download(resource, quiet=True)
                except Exception:
                    pass

        tokens  = word_tokenize(text)
        tagged  = pos_tag(tokens)
        chunked = ne_chunk(tagged)
        entities: list[tuple[str, str, float]] = []
        for subtree in chunked:
            if isinstance(subtree, Tree):
                label       = subtree.label()
                entity_text = " ".join(w for w, t in subtree.leaves())
                entities.append((entity_text, label, NLTK_CONFIDENCE))
        return entities
    except Exception:
        return []


# ─────────────────────────────────────────────────────────────
# Public scan function
# ─────────────────────────────────────────────────────────────

def run_ner_scan(text: str) -> list:
    """
    NER scan returning standardised finding dicts.

    Steps:
      1. Split text into paragraphs.
      2. For each paragraph containing a credential keyword, run entity
         recognition (BERT preferred, NLTK fallback).
      3. Run sensitive sentence pattern matching over the full text.
      4. All findings are deduplicated via SHA-256 of raw entity text.
    """
    findings: list  = []
    seen:     set   = set()
    offset         = 0

    for para in text.split("\n"):
        if not para.strip():
            offset += len(para) + 1
            continue

        para_lower = para.lower()
        has_keyword = any(kw in para_lower for kw in CRED_KEYWORDS)

        if has_keyword:
            # Prefer BERT; fall back to NLTK if model not loaded
            pipe = _get_bert_pipeline()
            if pipe:
                raw_entities = _bert_get_entities(para[:2000])
                base_confidence = BERT_CONFIDENCE
            else:
                raw_entities = _nltk_get_entities(para[:5000])
                base_confidence = NLTK_CONFIDENCE

            for raw_text, label, score in raw_entities:
                raw_text = raw_text.replace("##", "").strip()   # strip BERT sub-token artefacts
                if len(raw_text) < 3:
                    continue
                h = hash_value(raw_text)
                if h in seen:
                    continue
                seen.add(h)

                risk, desc, category = ENTITY_RISK_MAP.get(label, DEFAULT_ENTITY_RISK)
                conf = min(base_confidence * score * 1.2 if pipe else base_confidence, 0.97)

                findings.append({
                    "layer":           "ner",
                    "sublayer":        "bert" if pipe else "nltk",
                    "credential_type": f"ner_{label.lower()}",
                    "description":     desc,
                    "risk_tier":       risk,
                    "category":        category,
                    "redacted_value":  redact(raw_text) if len(raw_text) > 4 else "****",
                    "value_hash":      h,
                    "context_snippet": para[:200],
                    "char_position":   offset,
                    "confidence":      round(min(conf, 0.97), 3),
                    "entity_label":    label,
                })

        offset += len(para) + 1

    # ── Sensitive sentence pattern matching (regex, layer=ner) ──────────────
    for pattern in SENSITIVE_PATTERNS:
        for match in re.finditer(pattern, text):
            raw = match.group(0)
            h   = hash_value(raw)
            if h in seen:
                continue
            seen.add(h)
            s = max(0, match.start() - 40)
            e = min(len(text), match.end() + 40)
            findings.append({
                "layer":           "ner",
                "sublayer":        "sensitive_pattern",
                "credential_type": "sensitive_sentence",
                "description":     "Sentence strongly suggests credential exposure",
                "risk_tier":       "High",
                "category":        "credential",
                "redacted_value":  redact(raw),
                "value_hash":      h,
                "context_snippet": text[s:e],
                "char_position":   match.start(),
                "confidence":      REGEX_CONFIDENCE,
                "entity_label":    "SENSITIVE",
            })

    return findings