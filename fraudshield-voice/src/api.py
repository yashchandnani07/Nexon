# src/api.py  –  Enhanced FraudShield Voice API
import os
import io
import tempfile
import time
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn
import numpy as np
import torch

from evaluate   import load_models, predict
from db         import init_db, save_prediction, get_scan_history, save_feedback, get_feedback_stats, mark_retraining_used

SAMPLE_RATE   = 16000
CLIP_SAMPLES  = SAMPLE_RATE * 3   # score every 3 seconds of audio

app = FastAPI(
    title="FraudShield Voice API",
    description="Deepfake voice detection — AegisAI",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

SUPPORTED_FORMATS = {
    ".wav", ".mp3", ".flac", ".ogg",
    ".m4a", ".aac", ".wma",
    ".mp4", ".webm", ".3gp",
}


# ── Startup ────────────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    app.state.deep, app.state.rf = load_models()
    init_db()
    print("[API] Models loaded and DB ready.")


# ── Health ─────────────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {"status": "ok", "models_loaded": True}


# ══════════════════════════════════════════════════════════════════════════
#  Main analysis endpoint
# ══════════════════════════════════════════════════════════════════════════
@app.post("/analyze/voice")
async def analyze_voice(
    file:      UploadFile = File(...),
    caller_id: str  = Form(default=""),
    channel:   str  = Form(default="upload"),
    use_llm:   bool = Form(default=True),
):
    ext = Path(file.filename).suffix.lower()
    if ext not in SUPPORTED_FORMATS:
        raise HTTPException(400, f"Unsupported format '{ext}'. Supported: {', '.join(SUPPORTED_FORMATS)}")

    audio_bytes = await file.read()

    with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp:
        tmp.write(audio_bytes)
        tmp_path = tmp.name

    try:
        result         = predict(tmp_path, app.state.deep, app.state.rf, use_llm=use_llm)
        result["caller_id"] = caller_id
        result["channel"]   = channel
        result["file_name"] = file.filename

        # ── Compute waveform samples for frontend display ──────────────────
        try:
            import librosa
            y, sr = librosa.load(tmp_path, sr=16000, mono=True, duration=60)
            # downsample to 80 points for waveform
            target = 80
            step   = max(1, len(y) // target)
            samples = [round(float(abs(y[i * step])), 4) for i in range(target)]
            result["waveform_samples"] = samples
            result["duration_s"]       = round(len(y) / sr, 2)
            result["sample_rate"]      = sr
        except Exception as e:
            result["waveform_samples"] = [0.1] * 80
            result["duration_s"]       = 0

        # ── Persist to DB ──────────────────────────────────────────────────
        pred_id = save_prediction(result, audio_bytes=audio_bytes, file_name=file.filename)
        result["prediction_id"] = pred_id

        return result
    except Exception as e:
        raise HTTPException(500, str(e))
    finally:
        os.unlink(tmp_path)


# ════════════════════════════════════════════════════════════════════════════
#  WebSocket — Real-time Recording Analysis
# ════════════════════════════════════════════════════════════════════════════
@app.websocket("/ws/realtime")
async def realtime_stream(websocket: WebSocket):
    """
    WebSocket real-time voice analysis.
    Client sends raw PCM Float32 chunks (16 kHz mono).
    Server sends JSON risk assessment every 3 seconds of accumulated audio.
    """
    await websocket.accept()
    buffer: np.ndarray = np.array([], dtype=np.float32)
    deep   = websocket.app.state.deep
    rf     = websocket.app.state.rf
    chunk_num = 0
    print("[WS] Real-time session started")

    try:
        while True:
            data  = await websocket.receive_bytes()
            chunk = np.frombuffer(data, dtype=np.float32)
            buffer = np.concatenate([buffer, chunk])

            # Build a small waveform preview (20 points) from the buffer
            step = max(1, len(buffer) // 20)
            wf_preview = [round(float(abs(buffer[i * step])), 4) for i in range(min(20, len(buffer) // step))]

            # Always send a liveness tick so frontend sees the waveform
            tick = {
                "type":            "tick",
                "waveform_preview": wf_preview,
                "buffer_duration":  round(len(buffer) / SAMPLE_RATE, 2),
            }

            # Score every CLIP_SAMPLES (3 seconds)
            if len(buffer) >= CLIP_SAMPLES:
                audio_chunk = buffer[:CLIP_SAMPLES].copy()
                buffer      = buffer[CLIP_SAMPLES:]
                chunk_num  += 1

                try:
                    import librosa
                    audio_chunk = librosa.util.normalize(audio_chunk)
                except Exception:
                    pass

                with torch.no_grad():
                    from features import extract_sequence, extract_aggregate
                    DEVICE = next(deep.parameters()).device
                    seq    = torch.tensor(extract_sequence(audio_chunk)).unsqueeze(0).to(DEVICE)
                    ds     = float(deep(seq).squeeze().item())

                rs    = float(rf.predict_proba([extract_aggregate(audio_chunk)])[0][1])
                final = 0.85 * ds + 0.15 * rs
                risk  = int(final * 100)

                TIERS = [(86,"CRITICAL"), (61,"HIGH"), (31,"MEDIUM"), (0,"LOW")]
                tier  = next(t for thresh, t in TIERS if risk >= thresh)

                # Waveform from this chunk (40 pts)
                step = max(1, len(audio_chunk) // 40)
                wf   = [round(float(abs(audio_chunk[i * step])), 4) for i in range(40)]

                result = {
                    "type":       "result",
                    "chunk":      chunk_num,
                    "verdict":    "FAKE" if final >= 0.50 else "REAL",
                    "risk_score": risk,
                    "tier":       tier,
                    "deep_score": round(ds,    4),
                    "rf_score":   round(rs,    4),
                    "final_score":round(final, 4),
                    "waveform":   wf,
                    "timestamp":  time.time(),
                }
                await websocket.send_json(result)
            else:
                await websocket.send_json(tick)

    except WebSocketDisconnect:
        print(f"[WS] Session ended after {chunk_num} chunks")


# ══════════════════════════════════════════════════════════════════════════
#  Scan history
# ══════════════════════════════════════════════════════════════════════════
@app.get("/history")
def scan_history(limit: int = Query(default=30, le=200)):
    """Return recent voice scan results."""
    rows = get_scan_history(limit=limit)
    # Convert non-serializable types
    safe = []
    for r in rows:
        r = dict(r)
        for k, v in r.items():
            if isinstance(v, (bytes, memoryview)):
                r[k] = None          # don't return audio bytes in history
        safe.append(r)
    return {"history": safe, "count": len(safe)}


# ══════════════════════════════════════════════════════════════════════════
#  Feedback
# ══════════════════════════════════════════════════════════════════════════
@app.post("/feedback/{prediction_id}")
async def submit_review(
    prediction_id: int,
    correct_label: str = Form(...),
    reviewer_id:   str = Form(default="analyst"),
    notes:         str = Form(default=""),
    verdict:       str = Form(default=""),
):
    if correct_label not in ("REAL", "FAKE"):
        raise HTTPException(400, "correct_label must be REAL or FAKE")
    return save_feedback(prediction_id, correct_label, reviewer_id, notes, verdict)


@app.get("/feedback/stats")
def feedback_stats():
    return get_feedback_stats()


# ══════════════════════════════════════════════════════════════════════════
#  Admin — Retraining
# ══════════════════════════════════════════════════════════════════════════
@app.post("/admin/retrain")
async def trigger_retraining():
    """
    Admin endpoint: triggers retraining using all queued corrections.
    Marks queue items as used.
    """
    from db import get_feedback_stats
    stats = get_feedback_stats()
    queue_size = stats.get("retraining_queue_size", 0)

    if queue_size == 0:
        return {"status": "skipped", "reason": "No new corrections in queue", "queue_size": 0}

    # Mark queue consumed
    mark_retraining_used()

    # ── Trigger actual retraining (async background in production) ─────────
    retrain_log = []
    try:
        from train import retrain_from_feedback
        retrain_log = retrain_from_feedback()
        status = "started"
    except Exception as e:
        status = "queued"
        retrain_log = [f"Retraining queued — {queue_size} samples will be used. ({e})"]

    return {
        "status":          status,
        "queue_size":      queue_size,
        "log":             retrain_log,
        "message":         f"Retraining initiated on {queue_size} correction(s).",
    }


@app.get("/admin/retrain/status")
def retrain_status():
    stats = get_feedback_stats()
    return {
        "queue_size":    stats.get("retraining_queue_size", 0),
        "total_scans":   stats.get("total_predictions", 0),
        "total_feedback":stats.get("total_feedback", 0),
        "accuracy":      stats.get("accuracy"),
    }


if __name__ == "__main__":
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=False)