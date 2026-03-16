"""
SentinelAI — Threat Surge Detector
Detects bursts of high-severity incidents within a rolling 5-minute window.
"""

from collections import deque
from datetime import datetime, timedelta

# Shared in-process ring buffer (last 50 scans)
_recent_scores: deque = deque(maxlen=50)

SURGE_THRESHOLD_COUNT = 3     # Number of critical hits to trigger surge
SURGE_WINDOW_MINUTES  = 5     # Rolling window in minutes
CRITICAL_SCORE_FLOOR  = 81    # Scores ≥ this are "critical" for surge purposes


def check_surge(new_score: int) -> dict:
    """
    Record the new score and check whether a threat surge is occurring.

    Returns a dict with:
        surge   — bool
        message — human-readable alert string (if surge)
        level   — "surge" | "normal"
        critical_in_window — count of critical hits in the last 5 min
    """
    _recent_scores.append({
        "score": new_score,
        "time":  datetime.utcnow(),
    })

    cutoff = datetime.utcnow() - timedelta(minutes=SURGE_WINDOW_MINUTES)
    recent = [r for r in _recent_scores if r["time"] > cutoff]
    critical_count = sum(1 for r in recent if r["score"] >= CRITICAL_SCORE_FLOOR)

    if critical_count >= SURGE_THRESHOLD_COUNT:
        return {
            "surge":               True,
            "type":                "surge_alert",
            "message":             (
                f"⚠️ THREAT SURGE DETECTED: {critical_count} critical threats "
                f"in the last {SURGE_WINDOW_MINUTES} minutes"
            ),
            "level":               "surge",
            "critical_in_window":  critical_count,
        }

    return {
        "surge":              False,
        "level":              "normal",
        "critical_in_window": critical_count,
    }


def get_surge_stats() -> dict:
    """Return the current state of the surge buffer (for diagnostics)."""
    cutoff = datetime.utcnow() - timedelta(minutes=SURGE_WINDOW_MINUTES)
    recent = [r for r in _recent_scores if r["time"] > cutoff]
    return {
        "buffer_size":         len(_recent_scores),
        "recent_5min_count":   len(recent),
        "critical_in_window":  sum(1 for r in recent if r["score"] >= CRITICAL_SCORE_FLOOR),
        "surge_threshold":     SURGE_THRESHOLD_COUNT,
    }
