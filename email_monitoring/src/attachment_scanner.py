# src/attachment_scanner.py
"""
Attachment scanner wrapper — calls existing attachment_analyzer and
the attachment-scanner microservice (port 8007).

Tries the HTTP microservice first; falls back to local rule-based check.
"""
from __future__ import annotations
from typing import List, Dict
from pathlib import Path


def scan_attachments(attachments: List[Dict]) -> List[Dict]:
    """
    Scan a list of attachment descriptors.

    Each input item should have at minimum:
      { "filename": str, "content": bytes | None, "path": str | None }

    Returns a list of per-attachment result dicts.
    """
    results = []
    for att in attachments:
        fname   = att.get("filename", "unknown")
        content = att.get("content")
        path    = att.get("path")

        # Try the running attachment-scanner microservice
        res = _try_http_scan(fname, content)
        if res:
            results.append(res)
            continue

        # Fallback: local rule-based check
        text = ""
        if content:
            try:
                text = content.decode("utf-8", errors="replace")
            except Exception:
                pass
        elif path and Path(path).exists():
            try:
                with open(path, "rb") as f:
                    text = f.read().decode("utf-8", errors="replace")
            except Exception:
                pass

        results.append(_local_scan(fname, text))
    return results


def _try_http_scan(filename: str, content: bytes | None) -> dict | None:
    """Try the attachment-scanner HTTP service at :8007. Returns None on failure."""
    if not content:
        return None
    try:
        import requests
        files = {"file": (filename, content, "application/octet-stream")}
        resp  = requests.post("http://localhost:8007/analyze", files=files, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            data.setdefault("filename", filename)
            data.setdefault("source", "microservice")
            return data
    except Exception:
        pass
    return None


def _local_scan(filename: str, text: str) -> dict:
    """Rule-based local attachment scan."""
    try:
        from attachment_analyzer import rule_based_fraud_check
        result = rule_based_fraud_check(text, "")
        result["filename"] = filename
        result["source"]   = "local_rules"
        return result
    except Exception as exc:
        return {
            "filename": filename,
            "source":   "fallback",
            "is_suspicious": False,
            "score":    0,
            "reasons":  [],
            "error":    str(exc),
        }
