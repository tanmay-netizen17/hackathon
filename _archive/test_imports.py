print("[*] Testing imports for main.py...")
import sys

try:
    print("[1/15] Importing asyncio...")
    import asyncio
    print("[2/15] Importing json...")
    import json
    print("[3/15] Importing os...")
    import os
    print("[4/15] Importing datetime...")
    from datetime import datetime, timezone
    print("[5/15] Importing typing...")
    from typing import List, Optional, Dict, Any
    
    print("[6/15] Importing fastapi...")
    from fastapi import FastAPI, File, UploadFile, Form, BackgroundTasks, HTTPException, WebSocket, WebSocketDisconnect
    print("[7/15] Importing fastapi.middleware.cors...")
    from fastapi.middleware.cors import CORSMiddleware
    print("[8/15] Importing fastapi.responses...")
    from fastapi.responses import JSONResponse
    print("[9/15] Importing pydantic...")
    from pydantic import BaseModel
    print("[10/15] Importing uvicorn...")
    import uvicorn
    
    print("[11/15] Importing slowapi...")
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded
    from starlette.middleware.base import BaseHTTPMiddleware
    
    print("[12/15] Importing orchestrator...")
    from orchestrator import Orchestrator
    
    print("[13/15] Importing utils...")
    from utils.mitre_mapper import mitre_mapper
    from utils.sanitiser import Sanitiser
    from utils.audit_logger import AuditLogger
    from utils.surge_detector import SurgeDetector
    from utils.feedback_logger import FeedbackLogger
    
    print("[14/15] Importing red_team...")
    from red_team.robustness_evaluator import RobustnessEvaluator
    from red_team.model_health import ModelHealthMonitor
    
    print("[15/15] ALL IMPORTS SUCCESSFUL")
except Exception as e:
    print(f"[!] FAILED: {e}")
    import traceback
    traceback.print_exc()
except SystemExit as e:
    print(f"[!] SYSTEM EXIT: {e}")
