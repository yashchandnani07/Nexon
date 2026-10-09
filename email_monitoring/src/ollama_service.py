# src/ollama_service.py
"""
Ollama service wrapper — calls qwen3:8b for email content understanding.

Returns a structured threat analysis dict. Gracefully falls back to an
empty result if Ollama is not running.
"""
from __future__ import annotations
import json
import re

import os as _os

_OLLAMA_MODEL = "llama3"
_OLLAMA_URL   = _os.environ.get("OLLAMA_HOST", _os.environ.get("OLLAMA_URL", "http://localhost:11434"))

# ── Prompt template ────────────────────────────────────────────────────────────
_PROMPT = """You are an expert email security analyst. Analyze the following email and return ONLY a valid JSON object (no markdown, no explanation).

Email:
FROM: {sender}
SUBJECT: {subject}
BODY:
{body}

Return JSON in this exact format:
{{
  "threat_type": "PHISHING|SPAM|FRAUD|SCAM|LEGITIMATE",
  "intent": "brief description of email intent",
  "urgency_level": "LOW|MEDIUM|HIGH|CRITICAL",
  "urgency_score": <0-100 integer>,
  "summary": "2-3 sentence plain-english analysis of why this email is or is not suspicious",
  "suspicious_phrases": ["phrase1", "phrase2"],
  "extracted_entities": {{
    "emails": ["email@example.com"],
    "accounts": ["ACC-12345"],
    "phones": [],
    "names": []
  }},
  "flags": ["FLAG1", "FLAG2"],
  "overall_risk_score": <0-100 integer>,
  "recommendation": "ALLOW|REVIEW|BLOCK"
}}"""


def analyze_email_content(sender: str, subject: str, body: str) -> dict:
    """
    Call Ollama qwen3:8b to analyze email content.
    
    Returns a structured dict with threat_type, intent, urgency, summary,
    suspicious_phrases, extracted_entities, flags, overall_risk_score,
    recommendation — or an empty fallback dict on failure.
    """
    try:
        import ollama
        prompt = _PROMPT.format(
            sender=sender[:200],
            subject=subject[:300],
            body=body[:3000],
        )
        resp = ollama.chat(
            model=_OLLAMA_MODEL,
            messages=[{"role": "user", "content": prompt}],
            options={"temperature": 0.1, "num_predict": 1024},
        )
        raw = resp["message"]["content"].strip()

        # Strip markdown code fences if present
        if raw.startswith("```"):
            raw = re.sub(r"^```[a-z]*\n?", "", raw)
            raw = re.sub(r"\n?```$", "", raw)

        # Remove <think>…</think> blocks that qwen3 sometimes emits
        raw = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL).strip()

        # Find the JSON object boundaries
        start = raw.find("{")
        end   = raw.rfind("}") + 1
        if start >= 0 and end > start:
            raw = raw[start:end]

        data = json.loads(raw)
        data["ollama_available"] = True
        return data

    except Exception as exc:
        return {
            "ollama_available":  False,
            "error":             str(exc),
            "threat_type":       "UNKNOWN",
            "intent":            "",
            "urgency_level":     "UNKNOWN",
            "urgency_score":     0,
            "summary":           "Ollama analysis unavailable — ensure Ollama is running with llama3 model",
            "suspicious_phrases": [],
            "extracted_entities": {"emails": [], "accounts": [], "phones": [], "names": []},
            "flags":             [],
            "overall_risk_score": 0,
            "recommendation":    "REVIEW",
        }
