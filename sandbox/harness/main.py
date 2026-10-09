"""
harness/main.py — AI Security Sandbox — fully offline
Improvements:
  - SSE streaming upload progress (saving + Ollama registration)
  - File-size guard (MAX_UPLOAD_GB env var)
  - Async background scan with per-dimension polling
  - GET /models — Ollama model metadata
  - DELETE /models/{name} — remove registered model
"""

import json, os, shutil, datetime, asyncio, uuid
from fastapi import FastAPI, BackgroundTasks, UploadFile, File
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from harness.dimensions.adversarial   import run_adversarial
from harness.dimensions.pii_probe     import run_pii_probe
from harness.dimensions.multiturn     import run_multiturn
from harness.dimensions.tool_abuse    import run_tool_abuse
from harness.dimensions.consistency   import run_consistency
from harness.dimensions.context_atk   import run_context_attacks
from harness.dimensions.output_scan   import run_output_scan
from harness.dimensions.agent_monitor import run_agent_tests
from harness.scoring                  import compute_risk_score
from harness.report_gen               import generate_report
import harness.model_client           as _mc

app = FastAPI(title="AI Security Sandbox — Offline", version="4.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)

OLLAMA_HOST   = os.getenv("OLLAMA_HOST",   "http://localhost:11434")
UPLOADS_DIR   = os.getenv("UPLOADS_DIR",   "./uploads")
RESULTS_DIR   = os.getenv("RESULTS_DIR",   "./results")
REPORTS_DIR   = os.getenv("REPORTS_DIR",   "./reports")
UI_DIR        = os.getenv("UI_DIR",        "./ui")
MAX_UPLOAD_GB = float(os.getenv("MAX_UPLOAD_GB", "10"))
os.makedirs(UPLOADS_DIR, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

# ── In-memory scan registry ──────────────────────────────────────────────────
# scan_id → {"status": "running"|"done"|"error", "result": {...}, "current_dim": "...", "progress_pct": 0-100}
_scans: dict = {}

# ── Serve UI ─────────────────────────────────────────────────────────────────
@app.get("/", response_class=FileResponse)
def serve_ui():
    idx = os.path.join(UI_DIR, "index.html")
    return FileResponse(idx) if os.path.exists(idx) else JSONResponse({"status": "ok"})

if os.path.exists(UI_DIR):
    app.mount("/ui", StaticFiles(directory=UI_DIR), name="ui")


# ── Health ────────────────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    import httpx
    try:
        async with httpx.AsyncClient() as c:
            r = await c.get(f"{OLLAMA_HOST}/api/tags", timeout=5)
            models = [m["name"] for m in r.json().get("models", [])]
        return {"status": "ok", "ollama": "connected", "models_available": models, "judge": "offline (tinyllama)"}
    except Exception as e:
        return {"status": "ok", "ollama": "offline", "models_available": [], "error": str(e)}


# ── GET /models — rich metadata ───────────────────────────────────────────────
@app.get("/models")
async def list_models():
    import httpx
    try:
        async with httpx.AsyncClient() as c:
            r = await c.get(f"{OLLAMA_HOST}/api/tags", timeout=5)
            r.raise_for_status()
            raw = r.json().get("models", [])
        out = []
        for m in raw:
            name  = m.get("name", "")
            size  = m.get("size", 0)
            # derive quantization from name tag (e.g. "phi3:q4_k_m" → "Q4_K_M")
            tag   = name.split(":")[-1] if ":" in name else "latest"
            quant = tag.upper() if any(c in tag.upper() for c in ["Q4","Q8","Q2","Q5","Q6","F16","F32"]) else tag
            family = m.get("details", {}).get("family", name.split(":")[0])
            params = m.get("details", {}).get("parameter_size", "")
            modified = m.get("modified_at", "")
            out.append({
                "name":      name,
                "family":    family,
                "params":    params,
                "quant":     quant,
                "size_bytes": size,
                "size_gb":   round(size / 1e9, 2) if size else 0,
                "modified":  modified,
            })
        return {"models": out}
    except Exception as e:
        return {"models": [], "error": str(e)}


# ── DELETE /models/{name} ─────────────────────────────────────────────────────
@app.delete("/models/{model_name:path}")
async def delete_model(model_name: str):
    import httpx
    try:
        async with httpx.AsyncClient(timeout=30) as c:
            r = await c.request("DELETE", f"{OLLAMA_HOST}/api/delete",
                                json={"name": model_name})
        if r.status_code in (200, 204):
            return {"status": "deleted", "model": model_name}
        return JSONResponse(status_code=502,
                            content={"status": "error",
                                     "error": f"Ollama {r.status_code}: {r.text[:200]}"})
    except Exception as e:
        return JSONResponse(status_code=500, content={"status": "error", "error": str(e)})


# ── Upload model — SSE streaming progress ─────────────────────────────────────
@app.post("/upload")
async def upload_model(file: UploadFile = File(...)):
    """
    Returns a text/event-stream with JSON events:
      {"phase":"validating"}
      {"phase":"saving","saved_bytes":N,"total_bytes":N,"pct":N}
      {"phase":"registering","status":"...","completed":N,"total":N,"pct":N}
      {"phase":"ready","model_name":"..."}
      {"phase":"error","error":"..."}
    """
    import httpx

    if not file.filename.lower().endswith(".gguf"):
        async def _err():
            yield 'data: ' + json.dumps({"phase": "error", "error": "Only .gguf files are supported"}) + '\n\n'
        return StreamingResponse(_err(), media_type="text/event-stream")

    # derive safe model name
    stem       = file.filename[:-5]
    model_name = stem.replace(" ", "-").replace(".", "-").lower()
    dest       = os.path.join(UPLOADS_DIR, file.filename)

    async def _stream():
        yield 'data: ' + json.dumps({"phase": "validating"}) + '\n\n'

        # ── Save file in 1 MB chunks, track progress ──────────────────────
        CHUNK = 1024 * 1024  # 1 MB
        saved = 0
        # content-length may not always be present
        total_bytes = 0
        max_bytes   = int(MAX_UPLOAD_GB * 1e9)
        try:
            with open(dest, "wb") as out:
                while True:
                    chunk = await file.read(CHUNK)
                    if not chunk:
                        break
                    saved += len(chunk)
                    if saved > max_bytes:
                        out.close()
                        os.remove(dest)
                        yield 'data: ' + json.dumps({
                            "phase": "error",
                            "error": f"File exceeds {MAX_UPLOAD_GB} GB limit"
                        }) + '\n\n'
                        return
                    out.write(chunk)
                    # We don't know total bytes upfront; emit saved bytes
                    yield 'data: ' + json.dumps({
                        "phase": "saving",
                        "saved_bytes": saved,
                        "pct": -1   # -1 = indeterminate
                    }) + '\n\n'
        except Exception as e:
            yield 'data: ' + json.dumps({"phase": "error", "error": f"Save failed: {e}"}) + '\n\n'
            return

        file_size = os.path.getsize(dest)
        yield 'data: ' + json.dumps({
            "phase": "saving_done",
            "saved_bytes": file_size,
            "pct": 100
        }) + '\n\n'

        # ── Register with Ollama — stream progress ────────────────────────
        # Use modelfile with FROM directive (works across all Ollama versions).
        # The `from` field is for existing model names, NOT file paths.
        payload = {"model": model_name, "modelfile": f"FROM {dest}\n"}
        try:
            async with httpx.AsyncClient(timeout=600) as c:
                async with c.stream("POST", f"{OLLAMA_HOST}/api/create", json=payload) as resp:
                    if resp.status_code != 200:
                        body = await resp.aread()
                        yield 'data: ' + json.dumps({
                            "phase": "error",
                            "error": f"Ollama HTTP {resp.status_code}: {body.decode()[:200]}"
                        }) + '\n\n'
                        return

                    async for raw_line in resp.aiter_lines():
                        line = raw_line.strip()
                        if not line:
                            continue
                        try:
                            obj = json.loads(line)
                        except json.JSONDecodeError:
                            continue

                        if obj.get("error"):
                            yield 'data: ' + json.dumps({
                                "phase": "error", "error": obj["error"]
                            }) + '\n\n'
                            return

                        completed = obj.get("completed", 0)
                        total     = obj.get("total", 0)
                        pct       = round(completed / total * 100) if total else -1
                        yield 'data: ' + json.dumps({
                            "phase":     "registering",
                            "status":    obj.get("status", ""),
                            "completed": completed,
                            "total":     total,
                            "pct":       pct
                        }) + '\n\n'

        except Exception as e:
            yield 'data: ' + json.dumps({
                "phase": "error",
                "error": f"Ollama registration error: {e}"
            }) + '\n\n'
            return

        yield 'data: ' + json.dumps({"phase": "ready", "model_name": model_name}) + '\n\n'

    return StreamingResponse(_stream(), media_type="text/event-stream")


# ── Scan request schema ───────────────────────────────────────────────────────
class ScanRequest(BaseModel):
    model_config = {"protected_namespaces": ()}
    model_name:    str       = "tinyllama"
    dimensions:    list[str] = ["all"]
    judge_enabled: bool      = True


TASK_MAP = {
    "adversarial": ("run_adversarial",   run_adversarial),
    "pii":         ("run_pii_probe",     run_pii_probe),
    "multiturn":   ("run_multiturn",     run_multiturn),
    "tool_abuse":  ("run_tool_abuse",    run_tool_abuse),
    "consistency": ("run_consistency",   run_consistency),
    "context":     ("run_context_attacks", run_context_attacks),
    "output":      ("run_output_scan",   run_output_scan),
    "agent":       ("run_agent_tests",   run_agent_tests),
}


# ── Background scan worker ────────────────────────────────────────────────────
async def _run_dim(scan_id: str, dim_id: str, fn, model_name: str,
                   judge_enabled: bool, results: dict):
    """Run a single dimension and update shared state atomically."""
    import traceback
    print(f"[scan:{scan_id}] ▶ Starting dimension: {dim_id}", flush=True)
    try:
        result = await fn(
            model_name=model_name,
            ollama_host=OLLAMA_HOST,
            judge_enabled=judge_enabled,
        )
        results[dim_id] = result
        print(f"[scan:{scan_id}] ✔ Done:  {dim_id}  pass_rate={result.get('pass_rate')}%", flush=True)
    except Exception as e:
        tb = traceback.format_exc()
        print(f"[scan:{scan_id}] ✘ ERROR in {dim_id}:\n{tb}", flush=True)
        results[dim_id] = {
            "dimension": dim_id, "error": str(e),
            "tests": [], "passed": 0, "failed": 0, "total": 0, "pass_rate": 0,
        }
    finally:
        # Update progress counter thread-safely (asyncio is single-threaded)
        _scans[scan_id]["done_dims"] = _scans[scan_id].get("done_dims", 0) + 1
        done = _scans[scan_id]["done_dims"]
        total = _scans[scan_id]["total_dims"]
        _scans[scan_id]["progress_pct"] = round(done / total * 100)


async def _scan_worker(scan_id: str, model_name: str, dimensions: list[str],
                       judge_enabled: bool):
    run_all = "all" in dimensions
    results: dict = {}
    ts = datetime.datetime.now().isoformat()

    active_dims = {k: v for k, v in TASK_MAP.items()
                   if run_all or k in dimensions}
    total_dims = len(active_dims)

    # ── Initialise per-scan log in model_client ────────────────────────────
    _mc._scan_logs[scan_id] = []
    _mc._scan_id_cv.set(scan_id)

    _scans[scan_id].update({
        "status":       "running",
        "current_dim":  "warming_up",
        "progress_pct": 0,
        "total_dims":   total_dims,
        "done_dims":    0,
        "dim_status":   {k: "running" for k in active_dims},
    })

    # ── Pre-warm: load model into Ollama RAM before test dimensions start ──
    import httpx as _httpx
    try:
        print(f"[scan:{scan_id}] Pre-warming model {model_name}…", flush=True)
        async with _httpx.AsyncClient(timeout=120) as c:
            await c.post(
                f"{OLLAMA_HOST}/api/chat",
                json={
                    "model":      model_name,
                    "messages":   [{"role": "user", "content": "hi"}],
                    "stream":     False,
                    "keep_alive": _mc.MODEL_KEEP_ALIVE,
                    "options":    {"num_predict": 1},
                }
            )
        print(f"[scan:{scan_id}] Model warm.", flush=True)
    except Exception as e:
        print(f"[scan:{scan_id}] Warm-up failed (continuing): {e}", flush=True)

    print(f"[scan:{scan_id}] Running {total_dims} dimensions SEQUENTIALLY for model={model_name}", flush=True)

    # ── Run dimensions one-at-a-time to avoid OOM (two models in RAM = crash) ──
    for dim_id, (_, fn) in active_dims.items():
        _scans[scan_id]["current_dim"] = dim_id
        await _run_dim(scan_id, dim_id, fn, model_name, judge_enabled, results)

    print(f"[scan:{scan_id}] All dimensions complete. Computing score…", flush=True)

    score   = compute_risk_score(results)
    scan_id_clean = ts.replace(":", "-").replace(".", "-")

    payload = {
        "scan_id":    scan_id,
        "model":      model_name,
        "timestamp":  ts,
        "risk_score": score,
        "dimensions": results
    }

    json_path = f"{RESULTS_DIR}/{scan_id}.json"
    with open(json_path, "w") as f:
        json.dump(payload, f, indent=2, default=str)

    try:
        generate_report(payload)
    except Exception as e:
        print(f"[report] {e}")

    _scans[scan_id].update({
        "status":      "done",
        "progress_pct": 100,
        "result":      payload,
        "current_dim": "",
    })
    print(f"[scan] {scan_id} complete — score {score.get('score')}/100")


# ── POST /scan — returns scan_id immediately ──────────────────────────────────
@app.post("/scan")
async def start_scan(req: ScanRequest, bg: BackgroundTasks):
    import httpx as _httpx
    # Validate model exists in Ollama before queuing — avoids silent failures
    try:
        async with _httpx.AsyncClient(timeout=8) as c:
            r = await c.get(f"{OLLAMA_HOST}/api/tags")
            r.raise_for_status()
            available = [m["name"] for m in r.json().get("models", [])]
            # Ollama may append ":latest" tag
            model_variants = {req.model_name, f"{req.model_name}:latest"}
            if not any(m in available or m.split(":")[0] in [a.split(":")[0] for a in available]
                       for m in model_variants):
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": f"Model '{req.model_name}' not found in Ollama. "
                                 f"Available: {available}. "
                                 "Upload the model first or choose an installed one."
                    }
                )
    except Exception as e:
        print(f"[scan] Could not verify model with Ollama: {e}", flush=True)
        # Continue anyway — Ollama might be warming up

    scan_id = str(uuid.uuid4())
    _scans[scan_id] = {
        "status":      "queued",
        "model":       req.model_name,
        "dimensions":  req.dimensions,
        "progress_pct": 0,
        "current_dim": "",
        "result":      None,
        "created_at":  datetime.datetime.now().isoformat(),
    }
    bg.add_task(_scan_worker, scan_id, req.model_name, req.dimensions, req.judge_enabled)
    return {"scan_id": scan_id, "status": "queued"}


# ── GET /scan/{scan_id}/status ─────────────────────────────────────────────────
@app.get("/scan/{scan_id}/status")
async def scan_status(scan_id: str):
    entry = _scans.get(scan_id)
    if not entry:
        # Check persisted JSON
        json_path = f"{RESULTS_DIR}/{scan_id}.json"
        if os.path.exists(json_path):
            with open(json_path) as f:
                payload = json.load(f)
            return {
                "scan_id":      scan_id,
                "status":       "done",
                "progress_pct": 100,
                "current_dim":  "",
                "result":       payload,
                "log":          [],
            }
        return JSONResponse(status_code=404, content={"error": "Scan not found"})

    return {
        "scan_id":      scan_id,
        "status":       entry["status"],
        "model":        entry.get("model"),
        "progress_pct": entry.get("progress_pct", 0),
        "current_dim":  entry.get("current_dim", ""),
        "done_dims":    entry.get("done_dims", 0),
        "total_dims":   entry.get("total_dims", 0),
        "result":       entry.get("result"),
        "log":          _mc._scan_logs.get(scan_id, [])[-40:],
    }


# ── Download report ───────────────────────────────────────────────────────────
@app.get("/report/{scan_id}")
async def get_report(scan_id: str):
    scan_id = scan_id.replace("..", "").replace("/", "").replace("\\", "")
    html_path = f"{RESULTS_DIR}/{scan_id}_report.html"
    json_path = f"{RESULTS_DIR}/{scan_id}.json"

    if os.path.exists(html_path):
        return FileResponse(
            html_path, media_type="text/html",
            filename=f"security_report_{scan_id}.html",
            headers={"Content-Disposition": f"attachment; filename=security_report_{scan_id}.html"}
        )
    if os.path.exists(json_path):
        try:
            with open(json_path) as f:
                payload = json.load(f)
            generate_report(payload)
            if os.path.exists(html_path):
                return FileResponse(
                    html_path, media_type="text/html",
                    filename=f"security_report_{scan_id}.html",
                    headers={"Content-Disposition": f"attachment; filename=security_report_{scan_id}.html"}
                )
        except Exception as e:
            print(f"[report] Regen failed: {e}")

    available = [f.replace("_report.html", "") for f in os.listdir(RESULTS_DIR)
                 if f.endswith("_report.html")]
    return JSONResponse(status_code=404,
                        content={"error": "Report not found", "scan_id": scan_id,
                                 "available_scans": available[-5:]})


# ── List results ──────────────────────────────────────────────────────────────
@app.get("/results")
def list_results():
    try:
        files = sorted([f for f in os.listdir(RESULTS_DIR) if f.endswith(".json")], reverse=True)
        out = []
        for f in files[:20]:
            try:
                with open(f"{RESULTS_DIR}/{f}") as fh:
                    d = json.load(fh)
                has_report = os.path.exists(f"{RESULTS_DIR}/{d['scan_id']}_report.html")
                out.append({
                    "scan_id":    d["scan_id"],
                    "model":      d.get("model", "?"),
                    "timestamp":  d.get("timestamp", ""),
                    "risk":       d.get("risk_score", {}),
                    "has_report": has_report
                })
            except Exception:
                pass
        return {"scans": out}
    except Exception as e:
        return {"scans": [], "error": str(e)}