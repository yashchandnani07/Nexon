# src/voice_analyzer.py
"""
Voice analyzer wrapper — calls existing voice/evaluate.py analyze_audio_file().

Handles audio attachments from email, saves bytes to a temp file if needed,
then runs the dual-model (best_eer_v2.pt + XGBoost) ensemble.
"""
from __future__ import annotations
import os
import tempfile
from pathlib import Path
from typing import List, Dict

AUDIO_EXTENSIONS = {".wav", ".flac", ".mp3", ".m4a", ".aac", ".ogg", ".wma"}


def analyze_voice_attachments(attachments: List[Dict]) -> List[Dict]:
    """
    Scan audio attachments for deepfake detection.

    Input: list of attachment dicts with keys:
      { "filename": str, "content": bytes | None, "path": str | None }

    Returns: list of voice analysis result dicts (only for audio files).
    Each result matches the spec schema from voice/evaluate.py:
      {
        "filename": str, "format": str,
        "verdict": "REAL|FAKE|REVIEW|SKIPPED",
        "risk_score": int (0-100),
        "risk_tier": str, "confidence": str,
        "best_eer_score": float, "xgboost_score": float,
        "mfcc_features_used": int, "model_agreement": bool,
        "recommended_action": str, "skip_reason": str | None,
        "processing_ms": int, "indicators": list, ...
      }
    """
    # Import here so the module can be loaded without heavy deps at import time
    try:
        import sys
        _voice_dir = Path(__file__).parent / "voice"
        if str(_voice_dir) not in sys.path:
            sys.path.insert(0, str(_voice_dir))
        from voice.evaluate import analyze_audio_file
    except Exception as exc:
        return [{"error": f"Voice module unavailable: {exc}", "filename": ""}]

    results = []
    for att in attachments:
        fname = att.get("filename", "")
        ext   = Path(fname).suffix.lower()
        if ext not in AUDIO_EXTENSIONS:
            continue  # Not an audio file

        path    = att.get("path")
        content = att.get("content")

        # Use provided path directly if it exists
        if path and os.path.exists(path):
            results.append(analyze_audio_file(path, fname))
            continue

        # Write bytes to a temp file
        if content:
            tmp = None
            try:
                with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp_f:
                    tmp_f.write(content)
                    tmp = tmp_f.name
                results.append(analyze_audio_file(tmp, fname))
            except Exception as exc:
                results.append({
                    "filename": fname, "format": ext,
                    "verdict": "SKIPPED ⏭️", "risk_score": 0,
                    "skip_reason": str(exc), "error": str(exc),
                })
            finally:
                if tmp and os.path.exists(tmp):
                    try:
                        os.unlink(tmp)
                    except Exception:
                        pass
        else:
            results.append({
                "filename": fname, "format": ext,
                "verdict":  "SKIPPED ⏭️",
                "risk_score": 0,
                "skip_reason": "No file content available",
                "error": None,
            })

    return results
