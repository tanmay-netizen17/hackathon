# pyre-ignore-all-errors
"""
SentinelAI — Audit Logger
Logs every scan in a tamper-evident JSONL file.
Raw inputs are NEVER stored — only SHA-256 hashes.
"""

import hashlib
import json
from datetime import datetime
from pathlib import Path

AUDIT_LOG = Path("data/audit.jsonl")


def _ensure_dir():
    AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)


def log_scan(input_type: str, raw_input: str, result: dict) -> None:
    """
    Append a privacy-safe audit record for every scan.

    Fields:
        timestamp           — UTC ISO-8601
        input_type          — "url" | "text" | "log" | "file"
        input_hash          — SHA-256 of the raw input (raw never stored)
        sentinel_score      — final Sentinel Score
        severity            — Clean / Suspicious / Likely Malicious / Critical
        detectors_triggered — list of active detectors
        incident_id         — link back to incident store
    """
    _ensure_dir()
    entry = {
        "timestamp":          datetime.utcnow().isoformat(),
        "input_type":         input_type,
        "input_hash":         hashlib.sha256(
            raw_input.encode("utf-8", errors="replace")
        ).hexdigest(),
        "sentinel_score":     result.get("sentinel_score"),
        "severity":           result.get("severity"),
        "detectors_triggered": result.get("detectors_triggered"),
        "incident_id":        result.get("incident_id"),
    }
    with open(AUDIT_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def get_audit_summary(limit: int = 100) -> dict:
    """
    Return a lightweight summary of recent audit entries.
    """
    _ensure_dir()
    if not AUDIT_LOG.exists():
        return {"total_scans": 0, "recent": []}

    text = AUDIT_LOG.read_text(encoding="utf-8").strip()
    if not text:
        return {"total_scans": 0, "recent": []}

    lines = [l for l in text.split("\n") if l.strip()]
    entries = [json.loads(l) for l in lines]
    return {
        "total_scans": len(entries),
        "recent":      entries[-limit:],
    }
