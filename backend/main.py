# pyre-ignore-all-errors
"""
SentinelAI - Unified Threat Intelligence Platform
(Hackathon MVP - Backend)
"""

import asyncio
import json
import os
import subprocess
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, File, UploadFile, Form, BackgroundTasks, HTTPException, WebSocket, WebSocketDisconnect, Request
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
from utils.sanitiser import Sanitiser
from utils.audit_logger import AuditLogger
from utils.surge_detector import SurgeDetector
from utils.feedback_logger import FeedbackLogger
from red_team.robustness_evaluator import RobustnessEvaluator
from red_team.model_health import ModelHealthMonitor

app = FastAPI(title="SentinelAI API", version="1.0.0")

# CORS setup for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Global service instances (lazy loaded)
_orchestrator = None
_sanitiser = None
_audit_log = None
_surge_detector = None
_feedback_log = None
_robustness_eval = None
_health_monitor = None

def get_orchestrator():
    global _orchestrator
    if _orchestrator is None:
        print("[*] Initializing Orchestrator...")
        _orchestrator = Orchestrator()
    return _orchestrator

def get_sanitiser():
    global _sanitiser
    if _sanitiser is None:
        _sanitiser = Sanitiser()
    return _sanitiser

def get_audit_log():
    global _audit_log
    if _audit_log is None:
        _audit_log = AuditLogger()
    return _audit_log

def get_surge_detector():
    global _surge_detector
    if _surge_detector is None:
        _surge_detector = SurgeDetector()
    return _surge_detector

def get_feedback_log():
    global _feedback_log
    if _feedback_log is None:
        _feedback_log = FeedbackLogger()
    return _feedback_log

def get_robustness_eval():
    global _robustness_eval
    if _robustness_eval is None:
        _robustness_eval = RobustnessEvaluator()
    return _robustness_eval

def get_health_monitor():
    global _health_monitor
    if _health_monitor is None:
        _health_monitor = ModelHealthMonitor()
    return _health_monitor

# Performance metrics
metrics = {
    "total_scans": 0,
    "threats_blocked": 0,
    "avg_latency_ms": 0.0,
    "last_surge": None,
}

# In-memory store for demonstrations (normally a DB)
incident_store = {}
_blocklist = []

BLOCKLIST_FILE = os.path.join(os.getcwd(), "blocklist.json")

def _load_blocklist():
    global _blocklist
    if os.path.exists(BLOCKLIST_FILE):
        try:
            with open(BLOCKLIST_FILE, "r") as f:
                _blocklist = json.load(f)
        except:
            _blocklist = []

def _save_blocklist():
    try:
        with open(BLOCKLIST_FILE, "w") as f:
            json.dump(_blocklist, f, indent=2)
    except:
        pass

_load_blocklist()

class ConnectionManager:
    def __init__(self):
        self.active: List[WebSocket] = []

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

class AnalyseRequest(BaseModel):
    input: str
    type: str  # 'url', 'text', 'log'
    source: Optional[str] = "manual"

@app.post("/analyse")
@limiter.limit("50/minute")
async def analyse_threat(request: Request, analyse_req: AnalyseRequest, background_tasks: BackgroundTasks):
    start_time = datetime.now()
    
    # Check blocklist first
    if analyse_req.type == 'url':
        for entry in _blocklist:
            if entry.get("value") == analyse_req.input:
                return {
                    "sentinel_score": 100,
                    "severity": "CRITICAL",
                    "threat_brief": "This URL is on the organization BLOCKLIST.",
                    "recommended_action": "Connection TERMINATED."
                }

    # Run orchestrator
    url = analyse_req.input if analyse_req.type == 'url' else None
    text = analyse_req.input if analyse_req.type == 'text' else None
    log_data = analyse_req.input if analyse_req.type == 'log' else None

    result = await get_orchestrator().run(
        url=url,
        text=text,
        log_data=log_data,
        source=analyse_req.source or "manual"
    )
    
    # Enrich and persist
    incident_id = str(len(incident_store) + 1)
    result["incident_id"] = incident_id
    incident_store[incident_id] = result
    
    # Broadcast to live feed
    background_tasks.add_task(manager.broadcast, {"type": "incident", "data": result})
    
    # Update metrics
    metrics["total_scans"] += 1
    if result["sentinel_score"] >= 70:
        metrics["threats_blocked"] += 1
        
    return result

@app.post("/analyse/file")
async def analyse_file(file: UploadFile = File(...), background_tasks: BackgroundTasks = None):
    content = await file.read()
    result = await get_orchestrator().run(
        file_bytes=content,
        filename=file.filename,
        source="file_upload"
    )
    
    incident_id = str(len(incident_store) + 1)
    result["incident_id"] = incident_id
    incident_store[incident_id] = result
    
    if background_tasks:
        background_tasks.add_task(manager.broadcast, {"type": "incident", "data": result})
        
    return result

@app.get("/incidents")
async def get_incidents():
    return list(incident_store.values())

@app.get("/agents/status")
async def get_agents():
    return agent_registry

@app.post("/agents/heartbeat/{agent_name}")
async def agent_heartbeat(agent_name: str):
    if agent_name in agent_registry:
        agent_registry[agent_name]["status"] = "online"
        agent_registry[agent_name]["last_seen"] = datetime.now(timezone.utc).isoformat()
    return {"status": "ok"}

@app.get("/blocklist")
async def get_blocklist():
    return {"items": _blocklist, "total": len(_blocklist)}

@app.post("/blocklist/add")
async def add_to_blocklist(payload: dict):
    entry = {
        "incident_id": payload.get("incident_id"),
        "value":       payload.get("value", ""),
        "input_type":  payload.get("input_type", "url"),
        "score":       payload.get("score", 0),
        "blocked_at":  datetime.now(timezone.utc).isoformat()
    }
    _blocklist.append(entry)
    _save_blocklist()
    return {"status": "blocked", "entry": entry, "total_blocked": len(_blocklist)}

@app.websocket("/ws/live")
async def websocket_live(websocket: WebSocket):
    await manager.connect(websocket)
    # Send recent incidents upon connection
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
    uvicorn.run(app, host="0.0.0.0", port=8000)
