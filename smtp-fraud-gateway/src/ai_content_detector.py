"""
AI-Generated Content Detector (Statistical)
=============================================
Detects AI-generated text using statistical features without heavy ML models.
Uses burstiness, vocabulary richness, sentence uniformity, and other markers.

Research basis: DetectGPT (Mitchell et al. 2023), GLTR (Gehrmann et al. 2019)
"""

import re
import math
from typing import Dict

SENT_RE = re.compile(r'(?<=[.!?])\s+')
WORD_RE = re.compile(r'\b[a-zA-Z]+\b')


def detect_ai_content(text: str) -> dict:
    """
    Analyze text for AI-generated content markers.
    
    Returns:
        {
            "burstiness": float,  # Human text has HIGH burstiness (varied sentence lengths)
            "vocabulary_richness": float,  # Unique words / total words
            "repetition_score": float,  # Repeated phrases
            "sentence_uniformity": float,  # How similar sentence lengths are (AI = very uniform)
            "formality_consistency": float,  # AI tends to maintain consistent formality
            "avg_sentence_length": float,
            "ai_probability": float,  # 0.0 - 1.0, higher = more likely AI
            "markers": [str],  # Human-readable markers found
        }
    """
    if not text or len(text.strip()) < 50:
        return _empty_result()

    sentences = [s.strip() for s in SENT_RE.split(text) if s.strip() and len(s.strip()) > 3]
    words = WORD_RE.findall(text.lower())

    if len(sentences) < 3 or len(words) < 20:
        return _empty_result()

    # ── Burstiness: variance in sentence length ──────────────────────────────
    # Human writing has HIGH burstiness (mix of short and long sentences)
    # AI text has LOW burstiness (uniform sentence lengths)
    sent_lengths = [len(WORD_RE.findall(s)) for s in sentences]
    mean_len = sum(sent_lengths) / len(sent_lengths)
    variance = sum((l - mean_len) ** 2 for l in sent_lengths) / len(sent_lengths)
    burstiness = math.sqrt(variance) / max(mean_len, 1)  # CV (coefficient of variation)

    # ── Vocabulary richness (Type-Token Ratio) ───────────────────────────────
    # AI tends to use a narrower vocabulary
    unique_words = set(words)
    vocab_richness = len(unique_words) / max(len(words), 1)

    # ── Sentence uniformity ──────────────────────────────────────────────────
    # How close sentence lengths are to the mean
    if mean_len > 0:
        deviations = [abs(l - mean_len) / mean_len for l in sent_lengths]
        uniformity = 1.0 - (sum(deviations) / len(deviations))
    else:
        uniformity = 0.5

    # ── Repetition score ─────────────────────────────────────────────────────
    # Check for repeated 3-grams
    trigrams = [' '.join(words[i:i+3]) for i in range(len(words) - 2)]
    if trigrams:
        trigram_counts = {}
        for tg in trigrams:
            trigram_counts[tg] = trigram_counts.get(tg, 0) + 1
        repeated = sum(1 for c in trigram_counts.values() if c > 1)
        repetition = repeated / max(len(trigram_counts), 1)
    else:
        repetition = 0.0

    # ── Formality consistency ────────────────────────────────────────────────
    # Check if formality level varies (human) or stays constant (AI)
    formal_markers = ['regarding', 'furthermore', 'therefore', 'consequently',
                      'hereby', 'pursuant', 'accordingly', 'henceforth']
    informal_markers = ["don't", "won't", "can't", "i'm", "i've", "gonna",
                        "wanna", "hey", "hi", "thanks", "ok", "yeah"]
    formal_count = sum(1 for w in words if w in formal_markers)
    informal_count = sum(1 for w in words if w in informal_markers)
    total_markers = formal_count + informal_count
    if total_markers > 0:
        formality_consistency = abs(formal_count - informal_count) / total_markers
    else:
        formality_consistency = 0.5  # Neutral

    # ── AI probability calculation ───────────────────────────────────────────
    markers = []
    ai_score = 0.0

    # Low burstiness = likely AI (threshold ~0.5)
    if burstiness < 0.3:
        ai_score += 0.25
        markers.append("Very uniform sentence lengths")
    elif burstiness < 0.5:
        ai_score += 0.15
        markers.append("Low sentence length variation")

    # High uniformity = likely AI
    if uniformity > 0.85:
        ai_score += 0.20
        markers.append("High sentence uniformity")

    # Moderate vocabulary (AI avoids extremes)
    if 0.4 < vocab_richness < 0.6:
        ai_score += 0.10
        markers.append("Moderate vocabulary range")

    # Low repetition with high uniformity = AI
    if repetition < 0.05 and uniformity > 0.7:
        ai_score += 0.15
        markers.append("Low repetition with high uniformity")

    # High formality consistency
    if formality_consistency > 0.8:
        ai_score += 0.10
        markers.append("Consistent formality level")

    # Perfect grammar indicators (all sentences start with capital, end with period)
    proper_starts = sum(1 for s in sentences if s[0].isupper()) / len(sentences)
    if proper_starts > 0.95:
        ai_score += 0.05
        markers.append("Perfect sentence capitalization")

    ai_probability = min(ai_score, 0.95)

    return {
        "burstiness": round(burstiness, 3),
        "vocabulary_richness": round(vocab_richness, 3),
        "repetition_score": round(repetition, 3),
        "sentence_uniformity": round(uniformity, 3),
        "formality_consistency": round(formality_consistency, 3),
        "avg_sentence_length": round(mean_len, 1),
        "ai_probability": round(ai_probability, 3),
        "markers": markers,
    }


def _empty_result():
    return {
        "burstiness": 0.0,
        "vocabulary_richness": 0.0,
        "repetition_score": 0.0,
        "sentence_uniformity": 0.0,
        "formality_consistency": 0.0,
        "avg_sentence_length": 0.0,
        "ai_probability": 0.0,
        "markers": [],
    }
