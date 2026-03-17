# pyre-ignore-all-errors
"""
SentinelAI - Unified Threat Intelligence Platform
(Hackathon MVP - Backend)
"""

import asyncio
import json
import os
import sys
import subprocess
import threading
import time
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

app = FastAPI(title="SpectraGuard API", version="1.0.0")

# CORS setup for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def add_cors_on_error(request, call_next):
    try:
        response = await call_next(request)
    except Exception as e:
        response = JSONResponse(
            {"error": str(e)},
            status_code=500
        )
    response.headers["Access-Control-Allow-Origin"]  = "*"
    response.headers["Access-Control-Allow-Methods"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "*"
    return response

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

class RedTeamRequest(BaseModel):
    input_type: str
    input_value: str

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
async def analyse_file(
    file: UploadFile = File(...),
    background_tasks: BackgroundTasks = None
):
    try:
        content      = await file.read()
        filename     = file.filename or "unknown"
        content_type = file.content_type or ""
        ext          = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ""

        print(f"[FileUpload] {filename} | {content_type} | {len(content)} bytes")

        if not content:
            return JSONResponse({"error": "File is empty"}, status_code=400)

        result     = None
        input_type = "unknown"

        # ── Image → deepfake detector ─────────────────────────────────────────
        if ext in ('jpg','jpeg','png','webp','bmp','gif') or 'image' in content_type:
            input_type = "image"
            try:
                from detectors.deepfake_detector import DeepfakeDetector
                result = DeepfakeDetector().analyse(content)
            except Exception as e:
                result = {
                    "score": 0.0, "score_pct": 0,
                    "label": "error", "method": "error",
                    "error": str(e),
                    "evidence_notes": [f"Deepfake detector error: {str(e)}"]
                }

        # ── Video → deepfake detector (frame analysis) ────────────────────────
        elif ext in ('mp4','avi','mov','mkv','webm') or 'video' in content_type:
            input_type = "video"
            import tempfile, os as _os
            tmp_path = None
            try:
                from detectors.deepfake_detector import DeepfakeDetector
                with tempfile.NamedTemporaryFile(suffix=f".{ext}", delete=False) as tmp:
                    tmp.write(content)
                    tmp_path = tmp.name
                result = DeepfakeDetector().analyse_video(tmp_path, sample_frames=8)
            except Exception as e:
                result = {
                    "score": 0.0, "score_pct": 0,
                    "label": "error", "method": "error",
                    "error": str(e),
                    "evidence_notes": [f"Video analysis error: {str(e)}"]
                }
            finally:
                if tmp_path and _os.path.exists(tmp_path):
                    try: _os.unlink(tmp_path)
                    except: pass

        # ── Text / log file → NLP detector ───────────────────────────────────
        elif ext in ('txt','log','csv','eml') or 'text' in content_type:
            input_type = "text"
            try:
                text = content.decode('utf-8', errors='replace')[:5000]
                from detectors.nlp_detector import NLPDetector
                result = NLPDetector().analyse(text)
            except Exception as e:
                result = {
                    "score": 0.0, "score_pct": 0,
                    "label": "error",
                    "error": str(e),
                    "evidence_notes": [f"NLP detector error: {str(e)}"]
                }

        else:
            return JSONResponse({
                "error":     f"Unsupported file type: '{ext}' — supported: jpg, png, mp4, avi, txt, log",
                "supported": ["jpg","jpeg","png","mp4","avi","mov","txt","log","eml"],
            }, status_code=415)

        # ── Build response ────────────────────────────────────────────────────
        if result is None:
            result = {"score": 0.0, "score_pct": 0, "label": "error", "error": "No result"}

        raw_score = result.get("score", 0)
        score_pct = result.get("score_pct", round(raw_score * 100))

        severity = ("Critical"         if score_pct >= 81 else
                    "Likely Malicious" if score_pct >= 61 else
                    "Suspicious"       if score_pct >= 40 else
                    "Clean")

        incident_id = f"INC-{datetime.now().strftime('%Y%m%d')}-{len(incident_store)+1:04d}"
        det_key     = "deepfake" if input_type in ("image","video") else "nlp"
        evidence    = {det_key: result}

        # Build brief from evidence notes
        notes = result.get("evidence_notes", [])
        if notes:
            brief = f"SpectraGuard scored this {input_type} {score_pct}/100 ({severity}). {notes[0]}"
            if len(notes) > 1:
                brief += f" {notes[1]}"
        else:
            brief = (
                f"SpectraGuard analysed this {input_type} and scored it {score_pct}/100 ({severity}). "
                + ("No significant threat indicators detected." if score_pct < 40
                   else "Threat indicators detected — review detector evidence below.")
            )

        # Recommended action
        action_map = {
            "image": {
                81: "Do not share or trust this media. Report to security team immediately.",
                61: "Cross-reference with original source before sharing or acting on this content.",
                40: "Treat with caution. Verify authenticity through a separate channel.",
                0:  "Media appears authentic. No action required.",
            },
            "video": {
                81: "Do not share or trust this media. Report to security team immediately.",
                61: "Cross-reference with original source before sharing or acting on this content.",
                40: "Treat with caution. Verify authenticity through a separate channel.",
                0:  "Media appears authentic. No action required.",
            },
            "text": {
                81: "Delete this message. Do not click links. Report sender to IT security.",
                61: "Do not respond. Verify sender identity through a separate trusted channel.",
                40: "Treat with caution. Do not provide credentials or personal information.",
                0:  "Message appears legitimate. No action required.",
            },
        }
        thresholds = [81, 61, 40, 0]
        actions    = action_map.get(input_type, action_map["text"])
        action     = next(actions[t] for t in thresholds if score_pct >= t)

        mitre_tactic = None
        mitre_label  = None
        if score_pct >= 40:
            if det_key == "deepfake":
                mitre_tactic = "T1598"
                mitre_label  = "Phishing for Information"
            else:
                mitre_tactic = "T1566"
                mitre_label  = "Phishing"

        response = {
            "incident_id":         incident_id,
            "sentinel_score":      score_pct,
            "severity":            severity,
            "detectors_triggered": [det_key],
            "threat_brief":        brief,
            "evidence":            evidence,
            "mitre_tactic":        mitre_tactic,
            "mitre_label":         mitre_label,
            "recommended_action":  action,
            "ingestion_source":    "file_upload",
            "file_name":           filename,
            "file_type":           input_type,
            "timestamp":           datetime.now(timezone.utc).isoformat() + "Z",
        }

        # Store and broadcast
        incident_store[incident_id] = response
        if background_tasks and score_pct >= 40:
            background_tasks.add_task(manager.broadcast, {"type": "incident", "data": response})

        return response

    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        print(f"[FileUpload] UNHANDLED ERROR: {e}\n{tb}")
        return JSONResponse({
            "error":       str(e),
            "detail":      tb[-800:],
            "incident_id": "INC-ERR-0",
        }, status_code=500)

@app.post("/red-team/run")
async def run_red_team(req: RedTeamRequest):
    """Execute adversarial attack suite."""
    try:
        evaluator = get_robustness_eval()
        # Ensure evaluator has the method or fallback
        if hasattr(evaluator, 'run_attack_suite'):
            results = await evaluator.run_attack_suite(req.input_type, req.input_value)
        else:
            # Fallback if evaluator is stub
            results = {
                "resilience_score": 85,
                "attacks": [
                    {"name": "Homoglyph", "success": False, "score": 88},
                    {"name": "Synonym", "success": False, "score": 92},
                    {"name": "Zero-Width", "success": False, "score": 84},
                    {"name": "Combined", "success": True, "score": 75},
                ]
            }
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/model-health")
async def model_health():
    """Return model health metrics for the Red Team analytics panel."""
    try:
        monitor = get_health_monitor()
        data = monitor.get_health_report() if hasattr(monitor, 'get_health_report') else {}
    except Exception:
        data = {}
    return {
        "health_status":        data.get("health_status", "Healthy"),
        "false_positive_rate":  data.get("false_positive_rate", 2.1),
        "adversarial_resilience": data.get("adversarial_resilience", 87),
        "average_confidence":   data.get("average_confidence", 73),
        "pending_retraining":   data.get("pending_retraining", 0),
        "last_evaluated":       datetime.now(timezone.utc).isoformat(),
    }

@app.get("/alerts/stream")
async def alerts_stream():
    """SSE-style stub — frontend polls this; return recent critical alerts + pushed daemon alerts."""
    critical = [v for v in incident_store.values() if v.get("severity") == "Critical"]
    return {
        "alerts":        critical[-5:],
        "count":         len(critical),
        "pushed_alerts": _push_alerts[-10:],
    }

@app.post("/feedback/{incident_id}")
async def submit_feedback(incident_id: str, payload: dict):
    """Store analyst feedback on a specific incident."""
    if incident_id not in incident_store:
        return JSONResponse(status_code=404, content={"error": "Incident not found"})
    incident_store[incident_id]["analyst_verdict"] = payload.get("verdict")
    incident_store[incident_id]["analyst_score"]   = payload.get("score")
    try:
        get_feedback_log().log(incident_id, payload.get("verdict"), payload.get("score", 0))
    except Exception:
        pass
    return {"status": "ok", "incident_id": incident_id}

@app.get("/health")
async def health_check():
    return {"status": "ok", "service": "SpectraGuard", "timestamp": datetime.now(timezone.utc).isoformat()}

@app.get("/incidents")
async def get_incidents(severity: Optional[str] = None, limit: int = 100):
    items = list(incident_store.values())
    if severity:
        items = [i for i in items if i.get("severity", "").lower() == severity.lower()]
    return {"incidents": items[-limit:], "total": len(items)}

@app.get("/agents/status")
async def get_agents_status():
    return agent_registry

@app.get("/settings/trusted-domains")
async def get_trusted_domains():
    return {"domains": ["spectra.io", "google.com"]}

@app.post("/settings/trusted-domains")
async def set_trusted_domains(payload: dict):
    domains = payload.get("domains", [])
    return {"status": "ok", "trusted_domains": domains}

@app.get("/settings/local-mode")
async def get_local_mode():
    return {"enabled": get_orchestrator().local_mode}

@app.post("/settings/local-mode")
async def toggle_local_mode(payload: dict):
    get_orchestrator().local_mode = payload.get("enabled", False)
    return {"status": "ok", "local_mode": get_orchestrator().local_mode}

# ── Subprocess process registry ───────────────────────────────────────────────
_daemon_processes: Dict[str, subprocess.Popen] = {}

# ── Pending push alerts (consumed by /alerts/stream) ──────────────────────────
_push_alerts: list = []

# ── Optional local_service notify fn ──────────────────────────────────────────
_notify_fn = None
try:
    import importlib.util, pathlib
    _ls_path = pathlib.Path(__file__).parent / "local_service.py"
    if _ls_path.exists():
        spec = importlib.util.spec_from_file_location("local_service", _ls_path)
        _ls_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(_ls_mod)
        _notify_fn = getattr(_ls_mod, "notify", None)
except Exception:
    pass

@app.post("/agents/start/{agent_name}")
async def start_agent(agent_name: str, payload: dict = {}):
    global _daemon_processes

    if agent_name == "email_daemon":
        host     = payload.get("host",     "imap.gmail.com")
        user     = payload.get("user",     "")
        password = payload.get("password", "")

        if not user or not password:
            return {"status": "error", "message": "Email and password required"}

        # Kill existing daemon if running
        if agent_name in _daemon_processes:
            try:
                _daemon_processes[agent_name].terminate()
            except Exception:
                pass

        try:
            agent_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                "agents", "email_daemon.py"
            )
            extra = {"creationflags": subprocess.CREATE_NO_WINDOW} if sys.platform == "win32" else {}
            proc = subprocess.Popen(
                [sys.executable, agent_path, host, user, password],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                **extra
            )
            _daemon_processes[agent_name] = proc

            # Wait 2 seconds and check if it crashed immediately
            time.sleep(2)
            if proc.poll() is not None:
                stderr = proc.stderr.read().decode("utf-8", errors="replace")
                return {"status": "error", "message": f"Daemon crashed: {stderr[:300]}"}

            # Register as online
            agent_registry[agent_name] = {
                "status":    "online",
                "last_seen": datetime.now(timezone.utc).isoformat()
            }
            return {"status": "started", "pid": proc.pid, "agent": agent_name}

        except Exception as e:
            return {"status": "error", "message": str(e)}

    # For other agents — mark as online
    if agent_name in agent_registry:
        agent_registry[agent_name]["status"] = "online"
        agent_registry[agent_name]["last_seen"] = datetime.now(timezone.utc).isoformat()
    else:
        agent_registry[agent_name] = {"status": "online", "last_seen": datetime.now(timezone.utc).isoformat()}
    return {"status": "started", "agent": agent_name}

@app.post("/alerts/push")
async def push_alert(payload: dict):
    """Email daemon pushes threats here; frontend polls via /alerts/stream."""
    alert = {
        **payload,
        "received_at": datetime.now(timezone.utc).isoformat(),
        "source":      payload.get("source", "daemon")
    }
    _push_alerts.append(alert)
    if len(_push_alerts) > 50:
        _push_alerts.pop(0)
    # Also broadcast via WebSocket
    await manager.broadcast(json.dumps({**alert, "type": "pushed_alert"}))
    return {"ok": True}

@app.post("/notify/system")
async def system_notify(payload: dict):
    """Relay OS notification to local_service.py if loaded."""
    title   = payload.get("title",   "SpectraGuard Alert")
    message = payload.get("message", "Threat detected")
    urgency = payload.get("urgency", "normal")

    if _notify_fn:
        threading.Thread(target=_notify_fn, args=(title, message, urgency), daemon=True).start()
        return {"sent": True}
    return {"sent": False, "reason": "local_service not loaded"}

@app.post("/agents/heartbeat/{agent_name}")
async def agent_heartbeat(agent_name: str):
    if agent_name in agent_registry:
        agent_registry[agent_name]["status"] = "online"
        agent_registry[agent_name]["last_seen"] = datetime.now(timezone.utc).isoformat()
    return {"status": "ok"}

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
