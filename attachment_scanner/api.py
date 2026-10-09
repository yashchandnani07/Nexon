from fastapi import FastAPI, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn
import shutil
import os
import time
from datetime import timezone

from attachment_main import analyze_attachment
from db import init_db, save_scan, get_history, get_stats

app = FastAPI(title="Attachment Scanner API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

TEMP_DIR = "temp_uploads"
os.makedirs(TEMP_DIR, exist_ok=True)


@app.on_event("startup")
async def startup():
    init_db()


@app.post("/analyze")
async def analyze_file(file: UploadFile = File(...)):
    start_time = time.time()

    file_path = os.path.join(TEMP_DIR, file.filename)
    try:
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        with open(file_path, "rb") as f:
            file_bytes = f.read()

        result = analyze_attachment(file_bytes, file.filename)
        result["analysis_time_ms"] = round((time.time() - start_time) * 1000, 1)

        # Persist to database (non-blocking — failure does not break the scan)
        saved = save_scan(result)
        if saved:
            result["scan_id"]    = saved.get("id")
            result["scanned_at"] = saved.get("scanned_at").isoformat() \
                if saved.get("scanned_at") else None

        return result

    finally:
        if os.path.exists(file_path):
            os.remove(file_path)


@app.get("/history")
async def scan_history(limit: int = 50):
    """Return recent scan history from the database."""
    rows = get_history(limit=min(limit, 100))
    # Serialize datetime → ISO string for JSON
    for row in rows:
        if row.get("scanned_at"):
            row["scanned_at"] = row["scanned_at"].isoformat()
    return {"history": rows, "count": len(rows)}


@app.get("/stats")
async def scan_stats():
    """Return aggregate scan statistics."""
    return get_stats()


if __name__ == "__main__":
    uvicorn.run("api:app", host="0.0.0.0", port=8007, reload=False)
