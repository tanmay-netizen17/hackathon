# pyre-ignore-all-errors
from collections import defaultdict
from datetime import datetime

class ModelHealthTracker:
    def __init__(self):
        self.feedback_log       = []
        self.adversarial_log    = []
        self.confidence_buckets = defaultdict(int)

    def record_feedback(self, incident_id, verdict, score):
        self.feedback_log.append({
            "incident_id": incident_id,
            "verdict":     verdict,
            "score":       score,
            "timestamp":   datetime.utcnow().isoformat()
        })
        self.confidence_buckets[int(score * 10) * 10] += 1

    def record_adversarial_result(self, result):
        self.adversarial_log.append({
            **result,
            "timestamp": datetime.utcnow().isoformat()
        })

    def get_health_report(self):
        total    = len(self.feedback_log)
        fp_count = sum(1 for f in self.feedback_log if f["verdict"] == "false_positive")
        fp_rate  = round(fp_count / total * 100 if total > 0 else 0, 1)

        adv_total   = sum(r.get("attacks_total", 0)  for r in self.adversarial_log)
        adv_caught  = sum(r.get("attacks_caught", 0) for r in self.adversarial_log)
        resilience  = round(adv_caught / adv_total * 100 if adv_total > 0 else 100, 1)

        scores   = [f["score"] for f in self.feedback_log]
        avg_conf = round(sum(scores) / len(scores) * 100 if scores else 0, 1)

        return {
            "total_feedback":         total,
            "false_positive_rate":    fp_rate,
            "adversarial_resilience": resilience,
            "average_confidence":     avg_conf,
            "confidence_histogram":   dict(self.confidence_buckets),
            "total_red_team_runs":    len(self.adversarial_log),
            "health_status": (
                "Healthy"  if fp_rate < 10 and resilience > 75 else
                "Degraded" if fp_rate < 20 or  resilience > 50 else
                "Critical"
            )
        }

health_tracker = ModelHealthTracker()
