# pyre-ignore-all-errors
"""
SentinelAI — FastAPI Backend Entry Point
Handles all HTTP + WebSocket endpoints for the cyber-defense platform.
"""

import asyncio
import json
import uuid
import subprocess
import os
import sys
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, UploadFile, File, Form, WebSocket, WebSocketDisconnect, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel
import uvicorn
import asyncio
import json
import uuid

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
from red_team.robustness_evaluator import evaluate_text_robustness, evaluate_url_robustness
from red_team.model_health import health_tracker

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

# Connection manager
class ConnectionManager:
    def __init__(self):
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, data: dict):
        dead = []
        for ws in self.active:
            try:
                await ws.send_text(json.dumps(data))
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

manager = ConnectionManager()

# Simple in-memory agent registry
agent_registry = {
    "browser_extension": {"status": "offline", "last_seen": None},
    "email_daemon":       {"status": "offline", "last_seen": None},
    "log_collector":      {"status": "offline", "last_seen": None},
}


# ── Request models ─────────────────────────────────────────────────────────────
from typing import Optional, List, Set, Dict, Any, Union, Literal

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

class AgentStartRequest(BaseModel):
    config: dict

# ── Active Python Subprocesses ────────────────────────────────────────────────
import subprocess
import os
import sys

active_agents = {}

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
        asyncio.create_task(manager.broadcast(surge_status))

    # Audit config
    raw_input = json.dumps(incident.get("evidence", {}))
    log_scan(incident.get("ingestion_source", "manual"), raw_input, incident)
    
    # Broadcast incident
    asyncio.create_task(manager.broadcast(incident))
    return incident


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


# In-memory trusted domains (loaded from settings)
trusted_domains_extra: set = set()

@app.post("/settings/trusted-domains")
async def update_trusted_domains(payload: dict):
    global trusted_domains_extra
    trusted_domains_extra = set(payload.get("domains", []))
    return {"updated": len(trusted_domains_extra)}

@app.get("/settings/trusted-domains")
async def get_trusted_domains():
    return {"domains": list(trusted_domains_extra)}

# ── SSE Alert stream ──────────────────────────────────────────────────────────
# Clients subscribe to GET /alerts/stream (Server-Sent Events)
# Backend pushes alerts via POST /alerts/push (from email daemon)

alert_queues: list[asyncio.Queue] = []

@app.get("/alerts/stream")
async def alert_stream(request: Request):
    """SSE endpoint — frontend subscribes here for real-time alerts."""
    queue = asyncio.Queue()
    alert_queues.append(queue)

    async def event_generator():
        try:
            # Send connected confirmation
            yield f"data: {json.dumps({'type': 'connected'})}\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    alert = await asyncio.wait_for(queue.get(), timeout=30)
                    yield f"data: {json.dumps(alert)}\n\n"
                except asyncio.TimeoutError:
                    # Keepalive ping
                    yield f"data: {json.dumps({'type': 'ping'})}\n\n"
        finally:
            if queue in alert_queues:
                alert_queues.remove(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        }
    )

@app.post("/alerts/push")
async def push_alert(payload: dict):
    """Called by email daemon / browser extension when threat detected."""
    alert = {
        "type":        payload.get("type", "threat"),
        "severity":    payload.get("severity", "Suspicious"),
        "score":       payload.get("score", 0),
        "from":        payload.get("from", ""),
        "subject":     payload.get("subject", ""),
        "incident_id": payload.get("incident_id", ""),
        "timestamp":   datetime.now(timezone.utc).isoformat(),
        "id":          str(uuid.uuid4())[:8],
    }
    # Push to all subscribed SSE clients
    for q in alert_queues:
        await q.put(alert)
    return {"pushed": len(alert_queues), "alert_id": alert["id"]}


@app.post("/ingest/url")
@limiter.limit("100/minute")
async def ingest_url(request: Request, req: URLIngestRequest):
    req.url = sanitise_url_input(req.url)
    incident = await orchestrator.run(url=req.url, source="browser_extension")
    incident["incident_id"] = make_incident_id()
    await process_and_broadcast(incident)
    return JSONResponse(content=incident)

@app.post("/ingest/email")
async def ingest_email(payload: dict):
    score = payload.get("sentinel_score", 0)

    # HARD THRESHOLD — do not save clean emails as incidents
    if score < 40:
        return {"status": "ignored", "reason": "score below threshold", "score": score}

    # Save to incidents store
    incident_id = payload.get("incident_id", f"INC-{int(datetime.now().timestamp())}")
    incident_store[incident_id] = payload

    # Broadcast to WebSocket live feed
    await manager.broadcast({
        **payload,
        "incident_id": incident_id,
    })

    return {"status": "logged", "incident_id": incident_id}

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

# ── Red Team & Model Health ──────────────────────────────────────────────────
@app.post("/red-team/run")
async def run_red_team(payload: dict):
    input_type  = payload.get("input_type", "text")
    input_value = payload.get("input_value", "")
    incident_id = payload.get("incident_id", "")

    if not input_value:
        return {"error": "input_value is required"}

    try:
        if input_type == "url":
            from detectors.url_detector import URLDetector
            detector = URLDetector()
            orig = await detector.score(input_value)
            original_score = orig.get("score", 0.5)
            result = await evaluate_url_robustness(input_value, detector, original_score)
        else:
            from detectors.nlp_detector import NLPDetector
            detector = NLPDetector()
            orig = await detector.analyse(input_value)
            original_score = orig.get("score", 0.5)
            result = await evaluate_text_robustness(input_value, detector, original_score)

        result["incident_id"]   = incident_id
        result["input_type"]    = input_type
        result["original_score"] = original_score

        health_tracker.record_adversarial_result(result)
        return result

    except Exception as e:
        return {"error": str(e), "input_type": input_type}

@app.get("/model-health")
async def get_model_health():
    return health_tracker.get_health_report()

@app.post("/feedback/{incident_id}")
async def submit_feedback(incident_id: str, payload: dict):
    verdict = payload.get("verdict", "true_positive")
    score   = float(payload.get("score", 0.5))
    health_tracker.record_feedback(incident_id, verdict, score)
    return {"status": "recorded", "incident_id": incident_id}

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
        "ws_clients_connected": len(manager.active),
        "local_mode": orchestrator.local_mode,
        "threshold": orchestrator.threshold,
    }

@app.get("/mitre/{tactic_key}")
async def get_mitre(tactic_key: str):
    info = mitre_mapper.get_mapping(tactic_key)
    if not info:
        raise HTTPException(status_code=404, detail="Tactic not found")
    return info

# ── Agent Status & Checkin ───────────────────────────────────────────────────
@app.get("/agents/status")
async def get_agent_status():
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    result = {}
    for name, info in agent_registry.items():
        if info["last_seen"] is None:
            result[name] = "offline"
        elif (now - datetime.fromisoformat(info["last_seen"])) > timedelta(seconds=30):
            result[name] = "offline"   # missed heartbeat
        else:
            result[name] = info["status"]
    return result

@app.post("/agents/checkin")
async def agent_checkin(payload: dict):
    from datetime import datetime, timezone
    name = payload.get("agent")
    if name in agent_registry:
        agent_registry[name] = {
            "status":    "online",
            "last_seen": datetime.now(timezone.utc).isoformat()
        }
    return {"ok": True}

@app.post("/agents/start/{agent_name}")
async def start_agent(agent_name: str, req: AgentStartRequest):
    if agent_name in active_agents:
        try:
            active_agents[agent_name].terminate()
        except Exception:
            pass

    env = os.environ.copy()
    script_path = os.path.join(os.path.dirname(__file__), "agents", f"{agent_name}.py")

    if not os.path.exists(script_path):
        raise HTTPException(404, "Agent script not found")

    args = [sys.executable, script_path]

    if agent_name == "email_daemon":
        env["EMAIL_IMAP_HOST"] = req.config.get("host", "imap.gmail.com")
        env["EMAIL_USER"] = req.config.get("user", "")
        env["EMAIL_APP_PASSWORD"] = req.config.get("password", "")
        env["SENTINEL_API_URL"] = "http://localhost:8000"

    elif agent_name == "log_collector":
        log_type = req.config.get("type", "auth")
        args.extend(["--type", log_type])
        env["SENTINEL_API_URL"] = "http://localhost:8000"

    proc = subprocess.Popen(args, env=env)
    active_agents[agent_name] = proc

    agent_registry[agent_name] = {
        "status": "starting",
        "last_seen": datetime.now(timezone.utc).isoformat()
    }

    return {"status": "started", "pid": proc.pid}

# ── WebSocket — real-time live feed ───────────────────────────────────────────
@app.websocket("/ws/live")
async def websocket_live(websocket: WebSocket):
    from datetime import datetime, timezone
    await manager.connect(websocket)
    recent = sorted(list(incident_store.values()), key=lambda x: x.get("timestamp", ""), reverse=True)[:10]
    for inc in recent:
        await websocket.send_text(json.dumps(inc))
    try:
        while True:
            await asyncio.sleep(15)
            await websocket.send_text(json.dumps({
                "type": "heartbeat",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }))
    except WebSocketDisconnect:
        manager.disconnect(websocket)


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
