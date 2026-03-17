import sys

def log(msg):
    print(msg)
    sys.stdout.flush()

log("[*] Testing imports for main.py (FLUSHED)...")

try:
    log("[1/15] Importing asyncio...")
    import asyncio
    log("[2/15] Importing json...")
    import json
    log("[3/15] Importing os...")
    import os
    log("[4/15] Importing datetime...")
    from datetime import datetime, timezone
    log("[5/15] Importing typing...")
    from typing import List, Optional, Dict, Any
    
    log("[6/15] Importing fastapi...")
    from fastapi import FastAPI, File, UploadFile, Form, BackgroundTasks, HTTPException, WebSocket, WebSocketDisconnect
    log("[7/15] Importing fastapi.middleware.cors...")
    from fastapi.middleware.cors import CORSMiddleware
    log("[8/15] Importing fastapi.responses...")
    from fastapi.responses import JSONResponse
    log("[9/15] Importing pydantic...")
    from pydantic import BaseModel
    log("[10/15] Importing uvicorn...")
    import uvicorn
    
    log("[11/15] Importing slowapi...")
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.util import get_remote_address
    log("[12/15] Importing orchestrator...")
    from orchestrator import Orchestrator
    
    log("[13/15] Importing utils...")
    from utils.mitre_mapper import mitre_mapper
    from utils.sanitiser import Sanitiser
    
    log("[14/15] Importing red_team...")
    from red_team.robustness_evaluator import RobustnessEvaluator
    
    log("[15/15] ALL IMPORTS SUCCESSFUL")
except Exception as e:
    log(f"[!] FAILED: {e}")
    import traceback
    traceback.print_exc()
except SystemExit as e:
    log(f"[!] SYSTEM EXIT: {e}")
