"""
SentinelAI — FastAPI Backend Entry Point
Handles all HTTP + WebSocket endpoints for the cyber-defense platform.
"""

import asyncio
import json
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, UploadFile, File, Form, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import uvicorn

from orchestrator import Orchestrator
from utils.mitre_mapper import mitre_mapper

# ── App init ──────────────────────────────────────────────────────────────────
app = FastAPI(
    title="SentinelAI API",
    description="Multi-threat cyber-defense platform — IndiaNext Hackathon 2026",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

orchestrator = Orchestrator()

# In-memory incident store
incident_store: dict[str, dict] = {}
# Active WebSocket connections
ws_clients: list[WebSocket] = []


# ── Request models ─────────────────────────────────────────────────────────────
class AnalyseRequest(BaseModel):
    url: Optional[str] = None
    text: Optional[str] = None
    log_data: Optional[str] = None
    source: Optional[str] = "manual"


class URLIngestRequest(BaseModel):
    url: str
    tab_id: Optional[int] = None
    timestamp: Optional[str] = None


class EmailIngestRequest(BaseModel):
    subject: str
    body: str
    sender: str
    headers: Optional[dict] = None


class LogIngestRequest(BaseModel):
    log_lines: str
    log_type: Optional[str] = "auth"


class FeedbackRequest(BaseModel):
    is_false_positive: bool
    notes: Optional[str] = None


# ── Helpers ────────────────────────────────────────────────────────────────────
def make_incident_id() -> str:
    now = datetime.now(timezone.utc)
    seq = str(len(incident_store) + 1).zfill(4)
    return f"INC-{now.strftime('%Y%m%d')}-{seq}"


async def broadcast_incident(incident: dict):
    """Push new incident to all connected WebSocket clients."""
    dead = []
    for client in ws_clients:
        try:
            await client.send_text(json.dumps(incident))
        except Exception:
            dead.append(client)
    for c in dead:
        ws_clients.remove(c)


# ── Core analysis endpoint ─────────────────────────────────────────────────────
@app.post("/analyse")
async def analyse(req: AnalyseRequest):
    """
    Submit any input for full-pipeline analysis.
    Accepts URL, text/email, or log data.
    """
    if not any([req.url, req.text, req.log_data]):
        raise HTTPException(status_code=400, detail="Provide at least one of: url, text, log_data")

    incident = await orchestrator.run(
        url=req.url,
        text=req.text,
        log_data=req.log_data,
        source=req.source or "manual",
    )
    incident["incident_id"] = make_incident_id()
    incident_store[incident["incident_id"]] = incident
    asyncio.create_task(broadcast_incident(incident))
    return JSONResponse(content=incident)


# ── Ingestion endpoints (from passive agents) ──────────────────────────────────
@app.post("/ingest/url")
async def ingest_url(req: URLIngestRequest):
    incident = await orchestrator.run(url=req.url, source="browser_extension")
    incident["incident_id"] = make_incident_id()
    incident_store[incident["incident_id"]] = incident
    asyncio.create_task(broadcast_incident(incident))
    return JSONResponse(content=incident)


@app.post("/ingest/email")
async def ingest_email(req: EmailIngestRequest):
    combined_text = f"Subject: {req.subject}\nFrom: {req.sender}\n\n{req.body}"
    incident = await orchestrator.run(
        text=combined_text,
        source="email_daemon",
        email_headers=req.headers,
    )
    incident["incident_id"] = make_incident_id()
    incident_store[incident["incident_id"]] = incident
    asyncio.create_task(broadcast_incident(incident))
    return JSONResponse(content=incident)


@app.post("/ingest/log")
async def ingest_log(req: LogIngestRequest):
    incident = await orchestrator.run(log_data=req.log_lines, source="log_collector")
    incident["incident_id"] = make_incident_id()
    incident_store[incident["incident_id"]] = incident
    asyncio.create_task(broadcast_incident(incident))
    return JSONResponse(content=incident)


# ── Client-friendly analysis API (used by extension) ───────────────────────────
@app.post("/analyze/url")
async def analyze_url(req: AnalyseRequest):
    """Specific endpoint for browser extension URL analysis."""
    incident = await orchestrator.run(url=req.url, source="browser_extension")
    incident["incident_id"] = make_incident_id()
    incident_store[incident["incident_id"]] = incident
    asyncio.create_task(broadcast_incident(incident))
    return {
        "score": incident["sentinel_score"],
        "severity": incident["severity"].lower(),
        "explanation": incident["threat_brief"],
        "incident_id": incident["incident_id"]
    }


@app.post("/analyze/text")
async def analyze_text(req: AnalyseRequest):
    """Specific endpoint for browser extension text/email analysis."""
    incident = await orchestrator.run(text=req.text, source="browser_extension_overlay")
    incident["incident_id"] = make_incident_id()
    incident_store[incident["incident_id"]] = incident
    asyncio.create_task(broadcast_incident(incident))
    return {
        "score": incident["sentinel_score"],
        "severity": incident["severity"].lower(),
        "explanation": incident["threat_brief"],
        "incident_id": incident["incident_id"]
    }


@app.post("/log/threat")
async def log_threat(incident_data: dict):
    """External logging endpoint for extension-side detections."""
    incident_id = make_incident_id()
    incident_data["incident_id"] = incident_id
    incident_data["timestamp"] = datetime.now(timezone.utc).isoformat()
    incident_store[incident_id] = incident_data
    asyncio.create_task(broadcast_incident(incident_data))
    return {"status": "logged", "incident_id": incident_id}


@app.post("/ingest/file")
async def ingest_file(file: UploadFile = File(...)):
    """Accept uploaded file (image/video for deepfake, or text file)."""
    contents = await file.read()
    filename = file.filename or ""

    if filename.lower().endswith((".jpg", ".jpeg", ".png", ".mp4", ".avi", ".mov")):
        incident = await orchestrator.run(file_bytes=contents, filename=filename, source="manual")
    else:
        text = contents.decode("utf-8", errors="ignore")
        incident = await orchestrator.run(text=text, source="manual")

    incident["incident_id"] = make_incident_id()
    incident_store[incident["incident_id"]] = incident
    asyncio.create_task(broadcast_incident(incident))
    return JSONResponse(content=incident)


# ── Incident management ────────────────────────────────────────────────────────
@app.get("/incidents")
async def list_incidents(page: int = 1, limit: int = 20, severity: Optional[str] = None):
    items = list(incident_store.values())
    items.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    if severity:
        items = [i for i in items if i.get("severity", "").lower() == severity.lower()]
    start = (page - 1) * limit
    return {"total": len(items), "page": page, "data": items[start: start + limit]}


@app.get("/incidents/{incident_id}")
async def get_incident(incident_id: str):
    if incident_id not in incident_store:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident_store[incident_id]


@app.post("/feedback/{incident_id}")
async def submit_feedback(incident_id: str, req: FeedbackRequest):
    if incident_id not in incident_store:
        raise HTTPException(status_code=404, detail="Incident not found")
    incident_store[incident_id]["is_false_positive"] = req.is_false_positive
    incident_store[incident_id]["feedback_notes"] = req.notes
    return {"status": "ok", "incident_id": incident_id}


# ── Health ─────────────────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": "SentinelAI",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "incidents_in_memory": len(incident_store),
        "ws_clients_connected": len(ws_clients),
    }


@app.get("/mitre/{tactic_key}")
async def get_mitre(tactic_key: str):
    info = mitre_mapper.get_mapping(tactic_key)
    if not info:
        raise HTTPException(status_code=404, detail="Tactic not found")
    return info


# ── WebSocket — real-time live feed ───────────────────────────────────────────
@app.websocket("/ws/live")
async def websocket_live(websocket: WebSocket):
    await websocket.accept()
    ws_clients.append(websocket)
    # Send last 10 incidents immediately on connect
    recent = sorted(list(incident_store.values()), key=lambda x: x.get("timestamp", ""), reverse=True)[:10]
    for inc in recent:
        await websocket.send_text(json.dumps(inc))
    try:
        while True:
            # Keep-alive ping
            await asyncio.sleep(30)
            await websocket.send_text(json.dumps({"type": "ping"}))
    except WebSocketDisconnect:
        ws_clients.remove(websocket)


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
