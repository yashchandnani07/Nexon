# src/url_analyzer.py
"""
URL analyzer wrapper — calls existing url_scanner.fast_scan() per URL.

This is a thin wrapper so pipeline_controller has a clean API surface
without importing url_scanner directly.
"""
from __future__ import annotations
from typing import List, Dict


def analyze_urls(urls: List[str], limit: int = 10) -> List[Dict]:
    """
    Run fast URL scan on a list of URLs using the existing PhishGuard pipeline.

    Returns a list of per-URL result dicts matching the url_scanner output schema:
      {
        "url": str,
        "verdict": str,          # SAFE / SUSPICIOUS / DANGEROUS / ERROR
        "risk_score_pct": float, # 0-100
        "risk_reasons": list,
        "details": {
          "ml_model": {...},
          "ssl": {...},
          "whois": {...},
          "cookies": {...},
          "encoding": {...},
          "html": {...},
        },
        ...
      }
    """
    try:
        from url_scanner import fast_scan
    except ImportError:
        return [{"url": u, "verdict": "ERROR", "risk_score_pct": 0,
                 "error": "url_scanner module unavailable"} for u in urls[:limit]]

    results = []
    for url in urls[:limit]:
        try:
            res = fast_scan(url)
            results.append(res)
        except Exception as exc:
            results.append({"url": url, "verdict": "ERROR", "risk_score_pct": 0, "error": str(exc)})
    return results
