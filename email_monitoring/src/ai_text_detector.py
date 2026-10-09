# src/ai_text_detector.py
"""
AI-Generated Content Detector.

Wraps llama_analyzer.get_ai_text_probability() and normalises the response
into the structure expected by the React frontend:
  {
    "ai_generated_probability": float  0.0–1.0,
    "is_ai_generated":          bool,
    "method":                   str    e.g. "llama3:latest",
    "model":                    str,
    "indicators":               list[str],
  }

Falls back to heuristic detection if Ollama is unavailable.
"""
from __future__ import annotations
import re
from typing import Dict, Any


def detect_ai_text(text: str) -> Dict[str, Any]:
    """Return AI-generation probability for the supplied text."""
    try:
        from llama_analyzer import get_ai_text_probability
        raw = get_ai_text_probability(text[:2000])

        # Normalise probability to 0.0–1.0
        prob = float(raw.get("probability", raw.get("score", 0)))
        if prob > 1.0:
            prob = prob / 100.0

        indicators = raw.get("ai_indicators", [])
        if not isinstance(indicators, list):
            indicators = [str(indicators)] if indicators else []

        verdict = raw.get("verdict", "")
        is_ai = verdict in ("likely-ai", "definitely-ai") or prob >= 0.5

        return {
            "ai_generated_probability": round(prob, 3),
            "is_ai_generated":          is_ai,
            "method":                   raw.get("model", "llama3:latest"),
            "model":                    raw.get("model", "llama3:latest"),
            "indicators":               indicators,
            "verdict":                  verdict,
            "confidence":               raw.get("confidence", 0),
        }
    except Exception:
        return _heuristic_detect(text)


def _heuristic_detect(text: str) -> Dict[str, Any]:
    ai_pattern_labels = [
        (r"\bcertainly\b",                       "formal filler: 'certainly'"),
        (r"\bof course\b",                        "formal filler: 'of course'"),
        (r"\bplease do not hesitate\b",           "AI boilerplate: 'please do not hesitate'"),
        (r"\bshould you (have|need|require)\b",   "AI boilerplate: 'should you need/have'"),
        (r"\bfeel free to\b",                     "AI boilerplate: 'feel free to'"),
        (r"\bi hope this (email|message|finds)\b","AI opener: 'I hope this email...'"),
        (r"\babsolutely\b",                        "over-formal: 'absolutely'"),
        (r"\bkindly\b",                            "over-formal: 'kindly'"),
        (r"\brest assured\b",                      "AI filler: 'rest assured'"),
        (r"\bwe regret to inform\b",               "template phrase: 'we regret to inform'"),
    ]
    matched = [label for pattern, label in ai_pattern_labels
               if re.search(pattern, text, re.IGNORECASE)]
    prob = min(0.9, len(matched) * 0.15)
    return {
        "ai_generated_probability": round(prob, 3),
        "is_ai_generated":          prob >= 0.5,
        "method":                   "heuristic-fallback",
        "model":                    "heuristic-fallback",
        "indicators":               matched,
        "verdict":                  "likely-ai" if prob >= 0.5 else "human-written",
        "confidence":               0,
    }
