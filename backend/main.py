"""
SentinelAI — FastAPI Backend Entry Point
Handles all HTTP + WebSocket endpoints for the cyber-defense platform.
"""

import asyncio
import json
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, UploadFile, File, Form, WebSocket, WebSocketDisconnect, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import uvicorn

# Rate limiting
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from starlette.middleware.base import BaseHTTPMiddleware

from orchestrator import Orchestrator
from utils.mitre_mapper import mitre_mapper

# Feature Imports
from utils.sanitiser import sanitise_text_input, sanitise_url_input, sanitise_log_input
from utils.audit_logger import log_scan
from utils.surge_detector import check_surge
from utils.feedback_logger import log_feedback, get_model_health_stats

# ── App init ──────────────────────────────────────────────────────────────────
app = FastAPI(
    title="SentinelAI API",
    description="Multi-threat cyber-defense platform — IndiaNext Hackathon 2026",
    version="1.0.0",
)

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        return response

app.add_middleware(SecurityHeadersMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

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
    
class SettingsModeRequest(BaseModel):
    local_mode: bool

class SettingsThresholdRequest(BaseModel):
    threshold: float

# ── Helpers ────────────────────────────────────────────────────────────────────
def make_incident_id() -> str:
    now = datetime.now(timezone.utc)
    seq = str(len(incident_store) + 1).zfill(4)
    return f"INC-{now.strftime('%Y%m%d')}-{seq}"

async def process_and_broadcast(incident: dict):
    """Processes an orchestration result, logs it, checks surge, and broadcasts."""
    incident_store[incident["incident_id"]] = incident
    
    score = incident.get("sentinel_score", 0.0)
    
    # Check surge
    surge_status = check_surge(score)
    if surge_status.get("surge"):
        asyncio.create_task(broadcast_msg(surge_status))

    # Audit config
    raw_input = json.dumps(incident.get("evidence", {}))
    log_scan(incident.get("ingestion_source", "manual"), raw_input, incident)
    
    # Broadcast incident if above threshold
    if score >= orchestrator.threshold:
        asyncio.create_task(broadcast_msg(incident))
    return incident

async def broadcast_msg(msg: dict):
    """Push new msg to all connected WebSocket clients."""
    dead = []
    for client in ws_clients:
        try:
            await client.send_text(json.dumps(msg))
        except Exception:
            dead.append(client)
    for c in dead:
        ws_clients.remove(c)


# ── Core analysis endpoint ─────────────────────────────────────────────────────
@app.post("/analyse")
@limiter.limit("30/minute")
async def analyse(request: Request, req: AnalyseRequest):
    req.url = sanitise_url_input(req.url) if req.url else None
    req.text = sanitise_text_input(req.text) if req.text else None
    req.log_data = sanitise_log_input(req.log_data) if req.log_data else None

    if not any([req.url, req.text, req.log_data]):
        raise HTTPException(status_code=400, detail="Provide at least one of: url, text, log_data")

    incident = await orchestrator.run(
        url=req.url, text=req.text, log_data=req.log_data, source=req.source or "manual",
    )
    incident["incident_id"] = make_incident_id()
    await process_and_broadcast(incident)
    return JSONResponse(content=incident)


# ── Ingestion endpoints (from passive agents) ──────────────────────────────────
@app.post("/ingest/url")
@limiter.limit("100/minute")
async def ingest_url(request: Request, req: URLIngestRequest):
    req.url = sanitise_url_input(req.url)
    incident = await orchestrator.run(url=req.url, source="browser_extension")
    incident["incident_id"] = make_incident_id()
    await process_and_broadcast(incident)
    return JSONResponse(content=incident)

@app.post("/ingest/email")
@limiter.limit("30/minute")
async def ingest_email(request: Request, req: EmailIngestRequest):
    subject = sanitise_text_input(req.subject)
    sender = sanitise_text_input(req.sender)
    body = sanitise_text_input(req.body)
    combined_text = f"Subject: {subject}\\nFrom: {sender}\\n\\n{body}"
    incident = await orchestrator.run(text=combined_text, source="email_daemon", email_headers=req.headers)
    incident["incident_id"] = make_incident_id()
    await process_and_broadcast(incident)
    return JSONResponse(content=incident)

@app.post("/ingest/log")
@limiter.limit("60/minute")
async def ingest_log(request: Request, req: LogIngestRequest):
    req.log_lines = sanitise_log_input(req.log_lines)
    incident = await orchestrator.run(log_data=req.log_lines, source="log_collector")
    incident["incident_id"] = make_incident_id()
    await process_and_broadcast(incident)
    return JSONResponse(content=incident)


# ── Client-friendly analysis API (used by extension) ───────────────────────────
@app.post("/analyze/url")
@limiter.limit("100/minute")
async def analyze_url(request: Request, req: AnalyseRequest):
    req.url = sanitise_url_input(req.url) if req.url else None
    incident = await orchestrator.run(url=req.url, source="browser_extension")
    incident["incident_id"] = make_incident_id()
    await process_and_broadcast(incident)
    return {
        "score": incident["sentinel_score"],
        "severity": incident["severity"].lower(),
        "explanation": incident["threat_brief"],
        "incident_id": incident["incident_id"]
    }

@app.post("/analyze/text")
@limiter.limit("30/minute")
async def analyze_text(request: Request, req: AnalyseRequest):
    req.text = sanitise_text_input(req.text) if req.text else None
    incident = await orchestrator.run(text=req.text, source="browser_extension_overlay")
    incident["incident_id"] = make_incident_id()
    await process_and_broadcast(incident)
    return {
        "score": incident["sentinel_score"],
        "severity": incident["severity"].lower(),
        "explanation": incident["threat_brief"],
        "incident_id": incident["incident_id"]
    }

@app.post("/log/threat")
@limiter.limit("30/minute")
async def log_threat(request: Request, incident_data: dict):
    incident_id = make_incident_id()
    incident_data["incident_id"] = incident_id
    incident_data["timestamp"] = datetime.now(timezone.utc).isoformat()
    await process_and_broadcast(incident_data)
    return {"status": "logged", "incident_id": incident_id}

@app.post("/ingest/file")
@limiter.limit("10/minute")
async def ingest_file(request: Request, file: UploadFile = File(...)):
    contents = await file.read()
    filename = sanitise_text_input(file.filename or "")
    if filename.lower().endswith((".jpg", ".jpeg", ".png", ".mp4", ".avi", ".mov")):
        incident = await orchestrator.run(file_bytes=contents, filename=filename, source="manual")
    else:
        text = sanitise_text_input(contents.decode("utf-8", errors="ignore"))
        incident = await orchestrator.run(text=text, source="manual")
    incident["incident_id"] = make_incident_id()
    await process_and_broadcast(incident)
    return JSONResponse(content=incident)


# ── Incident management & Settings ─────────────────────────────────────────────
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

# Feedback Loop (Responsible AI)
@app.post("/feedback/{incident_id}")
@limiter.limit("60/minute")
async def submit_feedback(request: Request, incident_id: str, verdict: str, note: str = ""):
    if incident_id in incident_store:
         # Also update memory store
         incident_store[incident_id]["feedback_verdict"] = verdict
         incident_store[incident_id]["feedback_notes"] = note
    log_feedback(incident_id, verdict, note)
    return {"status": "logged", "incident_id": incident_id}

@app.get("/model-health")
async def model_health():
    return get_model_health_stats()

# Settings Mode (Local Mode & Threshold)
@app.post("/settings/mode")
async def set_mode(req: SettingsModeRequest):
    orchestrator.local_mode = req.local_mode
    return {"local_mode": orchestrator.local_mode}

@app.post("/settings/threshold")
async def set_threshold(req: SettingsThresholdRequest):
    orchestrator.threshold = req.threshold
    return {"threshold": orchestrator.threshold}

# ── Health ─────────────────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": "SentinelAI",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "incidents_in_memory": len(incident_store),
        "ws_clients_connected": len(ws_clients),
        "local_mode": orchestrator.local_mode,
        "threshold": orchestrator.threshold,
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
    recent = sorted(list(incident_store.values()), key=lambda x: x.get("timestamp", ""), reverse=True)[:10]
    for inc in recent:
        await websocket.send_text(json.dumps(inc))
    try:
        while True:
            await asyncio.sleep(30)
            await websocket.send_text(json.dumps({"type": "ping"}))
    except WebSocketDisconnect:
        ws_clients.remove(websocket)

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
