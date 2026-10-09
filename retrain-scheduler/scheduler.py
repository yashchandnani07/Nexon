"""
retrain-scheduler/scheduler.py
───────────────────────────────────────────────────────────────────
Nightly auto-retraining scheduler for FraudShield AI models.

• Runs APScheduler cron job at configurable hour/minute (default 02:00)
• Calls /admin/retrain on every model service in the Docker network
• Exposes a FastAPI status API so the Frontend can read / configure it
• Persists state to /data/scheduler_state.json across restarts

Endpoints:
  GET  /health              – liveness probe
  GET  /status              – full state (schedule, last run, per-model results)
  POST /trigger             – run retrain now (all or specific model)
  PUT  /schedule            – update cron time / enabled flag
  GET  /history             – last N run logs
"""

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import httpx
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ─── Logging ─────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SCHEDULER] %(levelname)s  %(message)s",
)
logger = logging.getLogger("retrain-scheduler")

# ─── Config ──────────────────────────────────────────────────────────────────
SCHEDULE_HOUR   = int(os.getenv("RETRAIN_HOUR",   "2"))
SCHEDULE_MINUTE = int(os.getenv("RETRAIN_MINUTE", "0"))
TIMEZONE        = os.getenv("RETRAIN_TZ", "UTC")
STATE_PATH      = Path(os.getenv("STATE_PATH", "/data/scheduler_state.json"))
HISTORY_LIMIT   = int(os.getenv("HISTORY_LIMIT", "30"))
HTTP_TIMEOUT    = float(os.getenv("HTTP_TIMEOUT", "600"))   # 10-min per model

# Model retrain endpoints (internal Docker network URLs)
MODELS = {
    "voice": {
        "label":      "Deepfake Voice",
        "retrain_url": os.getenv("VOICE_RETRAIN_URL",   "http://voice-scanner:8000/admin/retrain"),
        "status_url":  os.getenv("VOICE_STATUS_URL",    "http://voice-scanner:8000/admin/retrain/status"),
    },
    "website": {
        "label":      "Website Spoofing",
        "retrain_url": os.getenv("WEBSITE_RETRAIN_URL", "http://website-spoofing:5000/admin/retrain"),
        "status_url":  os.getenv("WEBSITE_STATUS_URL",  "http://website-spoofing:5000/admin/retrain/status"),
    },
    "email": {
        "label":      "Email Phishing",
        "retrain_url": os.getenv("EMAIL_RETRAIN_URL",   "http://email-monitor:8009/admin/retrain"),
        "status_url":  os.getenv("EMAIL_STATUS_URL",    "http://email-monitor:8009/admin/retrain/status"),
    },
}

# ─── State persistence ───────────────────────────────────────────────────────
STATE_PATH.parent.mkdir(parents=True, exist_ok=True)

_DEFAULT_STATE = {
    "enabled":         True,
    "hour":            SCHEDULE_HOUR,
    "minute":          SCHEDULE_MINUTE,
    "timezone":        TIMEZONE,
    "last_run":        None,       # ISO timestamp
    "next_run":        None,       # ISO timestamp (filled by scheduler)
    "last_run_results": {},        # { model_id: { status, message, queue_size, duration_s } }
    "history":         [],         # list of run records (newest first)
}


def _load_state() -> dict:
    if STATE_PATH.exists():
        try:
            return json.loads(STATE_PATH.read_text())
        except Exception as e:
            logger.warning(f"State file corrupt, resetting: {e}")
    return dict(_DEFAULT_STATE)


def _save_state(state: dict) -> None:
    STATE_PATH.write_text(json.dumps(state, indent=2, default=str))


_state = _load_state()

# ─── FastAPI app ─────────────────────────────────────────────────────────────
app = FastAPI(
    title="FraudShield Retrain Scheduler",
    version="1.0.0",
    description="Nightly automated model retraining orchestrator",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

scheduler = AsyncIOScheduler(timezone=TIMEZONE)


# ─── Core retrain logic ──────────────────────────────────────────────────────

async def _call_retrain(model_id: str, model_cfg: dict) -> dict:
    """Call a single model's /admin/retrain endpoint and return a result dict."""
    start = datetime.now(timezone.utc)
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            resp = await client.post(model_cfg["retrain_url"])
        elapsed = (datetime.now(timezone.utc) - start).total_seconds()

        if resp.status_code == 200:
            data = resp.json()
            result = {
                "status":     data.get("status", "ok"),
                "message":    data.get("message", "Retrain triggered."),
                "queue_size": data.get("queue_size", 0),
                "log":        data.get("log", []),
                "duration_s": round(elapsed, 1),
                "timestamp":  datetime.now(timezone.utc).isoformat(),
            }
            logger.info(f"[{model_id}] ✅  {result['status']} — queue={result['queue_size']}  ({result['duration_s']}s)")
        else:
            result = {
                "status":     "error",
                "message":    f"HTTP {resp.status_code}: {resp.text[:200]}",
                "queue_size": 0,
                "log":        [],
                "duration_s": round(elapsed, 1),
                "timestamp":  datetime.now(timezone.utc).isoformat(),
            }
            logger.warning(f"[{model_id}] ⚠️  HTTP {resp.status_code}")

    except httpx.ConnectError:
        result = {
            "status":     "unreachable",
            "message":    f"Service unreachable at {model_cfg['retrain_url']}",
            "queue_size": 0,
            "log":        [],
            "duration_s": round((datetime.now(timezone.utc) - start).total_seconds(), 1),
            "timestamp":  datetime.now(timezone.utc).isoformat(),
        }
        logger.error(f"[{model_id}] ❌  Service unreachable")

    except Exception as exc:
        result = {
            "status":     "error",
            "message":    str(exc),
            "queue_size": 0,
            "log":        [],
            "duration_s": round((datetime.now(timezone.utc) - start).total_seconds(), 1),
            "timestamp":  datetime.now(timezone.utc).isoformat(),
        }
        logger.error(f"[{model_id}] ❌  {exc}")

    return result


async def run_scheduled_retraining(model_ids: Optional[list] = None, triggered_by: str = "scheduler"):
    """
    Retrain all (or specified) models sequentially.
    Updates global state and history.
    """
    targets = model_ids or list(MODELS.keys())
    run_ts  = datetime.now(timezone.utc).isoformat()

    logger.info(f"━━━ Retrain run started  triggered_by={triggered_by}  models={targets} ━━━")

    results = {}
    for mid in targets:
        cfg = MODELS.get(mid)
        if not cfg:
            continue
        logger.info(f"  → Triggering {cfg['label']} ({mid}) …")
        results[mid] = await _call_retrain(mid, cfg)

    # Update state
    _state["last_run"]         = run_ts
    _state["last_run_results"] = results
    _update_next_run()

    # Append to history (newest first, capped at HISTORY_LIMIT)
    _state["history"].insert(0, {
        "run_at":       run_ts,
        "triggered_by": triggered_by,
        "models":       results,
    })
    _state["history"] = _state["history"][:HISTORY_LIMIT]

    _save_state(_state)

    statuses = [r["status"] for r in results.values()]
    logger.info(f"━━━ Retrain run complete  statuses={statuses} ━━━")
    return results


def _update_next_run():
    """Compute and store the scheduler's next fire time in ISO format."""
    job = scheduler.get_job("nightly_retrain")
    if job and job.next_run_time:
        _state["next_run"] = job.next_run_time.isoformat()
    else:
        _state["next_run"] = None


def _reschedule(hour: int, minute: int, tz: str):
    """Replace the cron job with new time settings."""
    scheduler.remove_job("nightly_retrain")
    scheduler.add_job(
        run_scheduled_retraining,
        CronTrigger(hour=hour, minute=minute, timezone=tz),
        id="nightly_retrain",
        replace_existing=True,
        kwargs={"triggered_by": "scheduler"},
    )
    _update_next_run()
    _save_state(_state)
    logger.info(f"Rescheduled nightly retrain → {hour:02d}:{minute:02d} {tz}")


# ─── App lifecycle ────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    h  = _state.get("hour",     SCHEDULE_HOUR)
    m  = _state.get("minute",   SCHEDULE_MINUTE)
    tz = _state.get("timezone", TIMEZONE)

    scheduler.add_job(
        run_scheduled_retraining,
        CronTrigger(hour=h, minute=m, timezone=tz),
        id="nightly_retrain",
        replace_existing=True,
        kwargs={"triggered_by": "scheduler"},
    )
    scheduler.start()
    _update_next_run()
    _save_state(_state)

    enabled_str = "ENABLED" if _state.get("enabled", True) else "DISABLED"
    logger.info(f"Scheduler started — nightly retrain at {h:02d}:{m:02d} {tz}  [{enabled_str}]")
    logger.info(f"Next run: {_state['next_run']}")


@app.on_event("shutdown")
async def shutdown():
    scheduler.shutdown(wait=False)
    logger.info("Scheduler stopped.")


# ─── API Endpoints ────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "scheduler_running": scheduler.running}


@app.get("/status")
def get_status():
    _update_next_run()
    return {
        "enabled":          _state.get("enabled", True),
        "schedule": {
            "hour":   _state.get("hour",     SCHEDULE_HOUR),
            "minute": _state.get("minute",   SCHEDULE_MINUTE),
            "timezone": _state.get("timezone", TIMEZONE),
            "cron_expression": f"{_state.get('minute',0)} {_state.get('hour',2)} * * *",
        },
        "next_run":          _state.get("next_run"),
        "last_run":          _state.get("last_run"),
        "last_run_results":  _state.get("last_run_results", {}),
        "models": {
            mid: {"label": cfg["label"]} for mid, cfg in MODELS.items()
        },
    }


@app.get("/history")
def get_history(limit: int = 10):
    h = _state.get("history", [])
    return {"history": h[:limit], "total": len(h)}


class TriggerRequest(BaseModel):
    models: Optional[list] = None  # None = all models


@app.post("/trigger")
async def trigger_now(req: TriggerRequest = TriggerRequest()):
    """Manually trigger retraining immediately."""
    model_ids = req.models or list(MODELS.keys())
    # Validate model ids
    bad = [m for m in model_ids if m not in MODELS]
    if bad:
        raise HTTPException(400, f"Unknown model id(s): {bad}. Valid: {list(MODELS.keys())}")

    results = await run_scheduled_retraining(model_ids=model_ids, triggered_by="manual")
    return {
        "status":  "triggered",
        "results": results,
        "run_at":  _state["last_run"],
    }


class ScheduleUpdate(BaseModel):
    hour:     Optional[int]  = None   # 0-23
    minute:   Optional[int]  = None   # 0-59
    timezone: Optional[str]  = None
    enabled:  Optional[bool] = None


@app.put("/schedule")
def update_schedule(body: ScheduleUpdate):
    """Update the nightly schedule (time, timezone, enable/disable)."""
    changed = False

    if body.enabled is not None:
        _state["enabled"] = body.enabled
        if body.enabled and not scheduler.get_job("nightly_retrain"):
            _reschedule(
                _state.get("hour", SCHEDULE_HOUR),
                _state.get("minute", SCHEDULE_MINUTE),
                _state.get("timezone", TIMEZONE),
            )
        elif not body.enabled:
            job = scheduler.get_job("nightly_retrain")
            if job:
                job.pause()
                logger.info("Nightly retrain PAUSED")
        else:
            job = scheduler.get_job("nightly_retrain")
            if job:
                job.resume()
                logger.info("Nightly retrain RESUMED")
        changed = True

    if body.hour is not None or body.minute is not None or body.timezone is not None:
        new_h  = body.hour     if body.hour     is not None else _state.get("hour",     SCHEDULE_HOUR)
        new_m  = body.minute   if body.minute   is not None else _state.get("minute",   SCHEDULE_MINUTE)
        new_tz = body.timezone if body.timezone is not None else _state.get("timezone", TIMEZONE)

        if not (0 <= new_h <= 23):
            raise HTTPException(400, "hour must be 0-23")
        if not (0 <= new_m <= 59):
            raise HTTPException(400, "minute must be 0-59")

        _state["hour"]     = new_h
        _state["minute"]   = new_m
        _state["timezone"] = new_tz
        _reschedule(new_h, new_m, new_tz)
        changed = True

    if not changed:
        raise HTTPException(400, "No changes provided.")

    _update_next_run()
    _save_state(_state)
    return {"status": "updated", "schedule": {
        "hour":    _state["hour"],
        "minute":  _state["minute"],
        "timezone": _state["timezone"],
        "enabled": _state["enabled"],
        "next_run": _state.get("next_run"),
    }}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("scheduler:app", host="0.0.0.0", port=9000, reload=False)
