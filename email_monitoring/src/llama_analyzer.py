# src/llama_analyzer.py
"""
Llama-based email analysis using llama3:latest via Ollama.

Functions:
  get_roberta_score()         → ML-style phishing score from LLM reasoning
  get_ai_text_probability()   → AI-generated content detection
  get_threat_analysis()       → Specific threat extraction
  analyze_content_for_phishing() → Deep content analysis for attachments
"""
from __future__ import annotations
import json
import re
from typing import Dict, Any

import os as _os

_OLLAMA_MODEL = "llama3"
_OLLAMA_URL   = _os.environ.get("OLLAMA_HOST", _os.environ.get("OLLAMA_URL", "http://localhost:11434"))


def _call_llama(prompt: str, temperature: float = 0.1, max_tokens: int = 1024) -> str:
    """Call llama3:latest and return raw response text."""
    try:
        import ollama
        resp = ollama.chat(
            model=_OLLAMA_MODEL,
            messages=[{"role": "user", "content": prompt}],
            options={"temperature": temperature, "num_predict": max_tokens},
        )
        raw = resp["message"]["content"].strip()
        # Strip <think> blocks if present
        raw = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL).strip()
        return raw
    except Exception as exc:
        raise RuntimeError(f"Ollama llama3:latest unavailable: {exc}") from exc


def _parse_json(raw: str) -> Dict:
    """Extract and parse JSON from LLM response."""
    # Strip markdown fences
    if "```" in raw:
        raw = re.sub(r"^```[a-z]*\n?", "", raw)
        raw = re.sub(r"\n?```$", "", raw)
    start = raw.find("{")
    end   = raw.rfind("}") + 1
    if start >= 0 and end > start:
        raw = raw[start:end]
    return json.loads(raw)


# ── Prompt templates ────────────────────────────────────────────────────────

_ROBERTA_PROMPT = """You are a cybersecurity ML model mimicking RoBERTa phishing classifier. Analyze this email and return ONLY valid JSON.

FROM: {sender}
SUBJECT: {subject}
BODY:
{body}

Return ONLY this JSON (no extra text):
{{
  "phishing_probability": <0-100 integer>,
  "label": "phishing" or "legitimate",
  "confidence": <0-100 integer>,
  "key_features": ["feature1", "feature2", "feature3"],
  "reasoning": "1-2 sentences explaining the classification",
  "top_category": "Social Engineering" or "Credential Harvesting" or "Financial Fraud" or "Malware Distribution" or "Legitimate"
}}"""

_AI_TEXT_PROMPT = """You are an AI-generated text detector. Analyze if this email was written by a human or AI.

EMAIL BODY:
{body}

Look for: overly formal language, generic phrasing, lack of specific personal details, perfect grammar, AI-typical phrases like "feel free to", "please do not hesitate", "I hope this email finds you well", "certainly", "absolutely", etc.

Return ONLY this JSON (no extra text):
{{
  "ai_probability": <0-100 integer>,
  "verdict": "human-written" or "likely-ai" or "definitely-ai",
  "confidence": <0-100 integer>,
  "ai_indicators": ["indicator1", "indicator2"],
  "human_indicators": ["indicator1"],
  "analysis": "1-2 sentences explaining the verdict"
}}"""

_THREAT_PROMPT = """You are an expert email threat analyst. Identify specific threats and attack vectors in this email.

FROM: {sender}
SUBJECT: {subject}
BODY:
{body}

Return ONLY this JSON (no extra text):
{{
  "threat_type": "PHISHING" or "SPEAR_PHISHING" or "BEC" or "CREDENTIAL_HARVEST" or "MALWARE" or "SCAM" or "SPAM" or "LEGITIMATE",
  "urgency_level": "LOW" or "MEDIUM" or "HIGH" or "CRITICAL",
  "intent": "Brief description of the attacker's goal",
  "specific_threats": [
    "Specific threat 1 (e.g., 'Fake PayPal login page linked to harvest credentials')",
    "Specific threat 2",
    "Specific threat 3"
  ],
  "social_engineering_tactics": ["tactic1", "tactic2"],
  "impersonated_entity": "Entity being impersonated (or null)",
  "call_to_action": "What the email wants the victim to do",
  "summary": "2-3 sentence plain-english threat assessment",
  "risk_score": <0-100 integer>
}}"""

_CONTENT_ANALYSIS_PROMPT = """You are analyzing the content of an email attachment for security threats. Extract all security-relevant information.

FILENAME: {filename}
CONTENT:
{content}

Return ONLY this JSON (no extra text):
{{
  "phishing_score": <0-100 integer>,
  "verdict": "CLEAN" or "SUSPICIOUS" or "PHISHING" or "MALWARE",
  "credentials_found": [
    {{"type": "email/password/api_key/etc", "value": "redacted-or-actual", "context": "surrounding text"}}
  ],
  "links_found": [
    {{"url": "http://...", "suspicious": true/false, "reason": "why suspicious or safe"}}
  ],
  "sensitive_data": ["type1: description", "type2: description"],
  "threats_detected": ["threat1", "threat2"],
  "summary": "2-3 sentence analysis of this document's security risk"
}}"""


# ── Public functions ─────────────────────────────────────────────────────────

def get_roberta_score(body: str, subject: str = "", sender: str = "") -> Dict[str, Any]:
    """
    Get ML-style phishing score from llama3:latest (mimicking RoBERTa).
    Returns dict with phishing_probability, label, confidence, key_features, reasoning.
    """
    try:
        prompt = _ROBERTA_PROMPT.format(
            sender=sender[:200],
            subject=subject[:300],
            body=body[:3000],
        )
        raw  = _call_llama(prompt, temperature=0.1, max_tokens=512)
        data = _parse_json(raw)
        return {
            "score":         int(data.get("phishing_probability", 0)),
            "label":         data.get("label", "legitimate"),
            "confidence":    int(data.get("confidence", 0)),
            "key_features":  data.get("key_features", []),
            "reasoning":     data.get("reasoning", ""),
            "top_category":  data.get("top_category", "Legitimate"),
            "model":         "llama3:latest (RoBERTa-style)",
            "available":     True,
        }
    except Exception as exc:
        return {
            "score":        0,
            "label":        "unknown",
            "confidence":   0,
            "key_features": [],
            "reasoning":    "",
            "top_category": "Unknown",
            "model":        "llama3:latest",
            "available":    False,
            "error":        str(exc),
        }


def get_ai_text_probability(body: str) -> Dict[str, Any]:
    """
    Detect if email was AI-generated using llama3:latest.
    Returns dict with ai_probability, verdict, ai_indicators, analysis.
    """
    try:
        prompt = _AI_TEXT_PROMPT.format(body=body[:3000])
        raw    = _call_llama(prompt, temperature=0.1, max_tokens=512)
        data   = _parse_json(raw)
        prob   = int(data.get("ai_probability", 0))
        return {
            "score":           prob,
            "probability":     round(prob / 100.0, 2),
            "verdict":         data.get("verdict", "unknown"),
            "confidence":      int(data.get("confidence", 0)),
            "ai_indicators":   data.get("ai_indicators", []),
            "human_indicators":data.get("human_indicators", []),
            "analysis":        data.get("analysis", ""),
            "model":           "llama3:latest",
            "available":       True,
        }
    except Exception as exc:
        return {
            "score":           0,
            "probability":     0.0,
            "verdict":         "unknown",
            "confidence":      0,
            "ai_indicators":   [],
            "human_indicators":[],
            "analysis":        "",
            "model":           "llama3:latest",
            "available":       False,
            "error":           str(exc),
        }


def get_threat_analysis(body: str, subject: str = "", sender: str = "") -> Dict[str, Any]:
    """
    Extract specific threats from email using llama3:latest.
    Returns dict with threat_type, specific_threats, social engineering tactics, summary.
    """
    try:
        prompt = _THREAT_PROMPT.format(
            sender=sender[:200],
            subject=subject[:300],
            body=body[:3000],
        )
        raw  = _call_llama(prompt, temperature=0.1, max_tokens=768)
        data = _parse_json(raw)
        return {
            "threat_type":              data.get("threat_type", "UNKNOWN"),
            "urgency_level":            data.get("urgency_level", "LOW"),
            "intent":                   data.get("intent", ""),
            "specific_threats":         data.get("specific_threats", []),
            "social_engineering_tactics": data.get("social_engineering_tactics", []),
            "impersonated_entity":      data.get("impersonated_entity"),
            "call_to_action":           data.get("call_to_action", ""),
            "summary":                  data.get("summary", ""),
            "risk_score":               int(data.get("risk_score", 0)),
            "model":                    "llama3:latest",
            "available":                True,
        }
    except Exception as exc:
        return {
            "threat_type":              "UNKNOWN",
            "urgency_level":            "LOW",
            "intent":                   "",
            "specific_threats":         [],
            "social_engineering_tactics": [],
            "impersonated_entity":      None,
            "call_to_action":           "",
            "summary":                  "LLM threat analysis unavailable.",
            "risk_score":               0,
            "model":                    "llama3:latest",
            "available":                False,
            "error":                    str(exc),
        }


def analyze_content_for_phishing(content: str, filename: str = "document") -> Dict[str, Any]:
    """
    Deep content analysis for attachment files using llama3:latest.
    Extracts credentials, links, phishing indicators.
    """
    try:
        prompt = _CONTENT_ANALYSIS_PROMPT.format(
            filename=filename,
            content=content[:4000],
        )
        raw  = _call_llama(prompt, temperature=0.1, max_tokens=1024)
        data = _parse_json(raw)
        return {
            "phishing_score":    int(data.get("phishing_score", 0)),
            "verdict":           data.get("verdict", "CLEAN"),
            "credentials_found": data.get("credentials_found", []),
            "links_found":       data.get("links_found", []),
            "sensitive_data":    data.get("sensitive_data", []),
            "threats_detected":  data.get("threats_detected", []),
            "summary":           data.get("summary", ""),
            "model":             "llama3:latest",
            "available":         True,
        }
    except Exception as exc:
        return {
            "phishing_score":    0,
            "verdict":           "UNKNOWN",
            "credentials_found": [],
            "links_found":       [],
            "sensitive_data":    [],
            "threats_detected":  [],
            "summary":           "Deep content analysis unavailable.",
            "model":             "llama3:latest",
            "available":         False,
            "error":             str(exc),
        }
