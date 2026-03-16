"""
SentinelAI — Responsible AI: Feedback Logger & Model Health
Analyst corrections feed a retraining queue; provides live health stats.
"""

import json
from datetime import datetime
from pathlib import Path

FEEDBACK_LOG = Path("data/feedback_queue.jsonl")


def _ensure_dir():
    FEEDBACK_LOG.parent.mkdir(parents=True, exist_ok=True)


def log_feedback(incident_id: str, verdict: str, analyst_note: str = "") -> dict:
    """
    Record analyst verdict on a specific incident.

    verdict:
        "true_positive"  — alert was correct
        "false_positive" — alert was wrong
        "unsure"         — analyst is uncertain
    """
    _ensure_dir()
    entry = {
        "incident_id":   incident_id,
        "verdict":       verdict,
        "analyst_note":  analyst_note,
        "timestamp":     datetime.utcnow().isoformat(),
    }
    with open(FEEDBACK_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
    return entry


def get_feedback_entries() -> list:
    """Return all feedback entries as a list of dicts."""
    _ensure_dir()
    if not FEEDBACK_LOG.exists():
        return []
    text = FEEDBACK_LOG.read_text(encoding="utf-8").strip()
    if not text:
        return []
    return [json.loads(line) for line in text.split("\n") if line.strip()]


def get_model_health_stats() -> dict:
    """
    Compute live model health metrics from the feedback log.
    """
    entries = get_feedback_entries()
    total = len(entries)

    if total == 0:
        return {
            "total_feedback":    0,
            "false_positive_rate": 0.0,
            "true_positive_rate":  0.0,
            "pending_retraining":  0,
            "unsure_count":        0,
        }

    fp = sum(1 for e in entries if e["verdict"] == "false_positive")
    tp = sum(1 for e in entries if e["verdict"] == "true_positive")
    un = sum(1 for e in entries if e["verdict"] == "unsure")

    return {
        "total_feedback":     total,
        "false_positive_rate": round(fp / total, 3),
        "true_positive_rate":  round(tp / total, 3),
        "pending_retraining":  fp + tp,
        "unsure_count":        un,
        # Calibration colour hint for the frontend
        "health_status": (
            "healthy"   if fp / total < 0.1
            else "warning" if fp / total < 0.25
            else "degraded"
        ),
    }
