# pyre-ignore-all-errors
"""
SentinelAI - Orchestrator
Routes each incoming payload to the correct set of detectors (local or cloud),
then fuses results and attaches XAI explanations.
"""

import asyncio
from datetime import datetime, timezone
from typing import Optional

from detectors.nlp_detector import NLPDetector
from detectors.url_detector import URLDetector
from detectors.deepfake_detector import DeepfakeDetector
from detectors.anomaly_detector import AnomalyDetector
from fusion_engine import FusionEngine
from xai_synthesiser import XAISynthesiser
from utils.mitre_mapper import mitre_mapper
from utils.response_generator import ResponseGenerator


class Orchestrator:
    """
    Routes each incoming payload to the correct set of detectors,
    then fuses results and attaches XAI explanations.
    """

    def __init__(self):
        # Cloud models
        self.nlp = NLPDetector()
        self.url = URLDetector()
        
        # Shared models (Deepfake and Anomaly aren't local-only restricted in this hackathon setup)
        self.deepfake = DeepfakeDetector()
        self.anomaly = AnomalyDetector()
        
        self.fusion = FusionEngine()
        self.xai = XAISynthesiser()
        self.responder = ResponseGenerator()
        
        # Local inference models
        from detectors.local_runner import LocalNLPDetector, LocalURLDetector
        self.local_nlp = LocalNLPDetector()
        self.local_url = LocalURLDetector()
        
        # Environment settings (controlled via Settings endpoints in main.py)
        self.local_mode = False
        self.threshold = 40.0

    async def run(
        self,
        url: Optional[str] = None,
        text: Optional[str] = None,
        log_data: Optional[str] = None,
        file_bytes: Optional[bytes] = None,
        filename: Optional[str] = None,
        email_headers: Optional[dict] = None,
        source: str = "manual",
    ) -> dict:
        """
        Main entry point. Returns a full SentinelAI incident dict.
        """
        detector_results = {}
        tasks = []

        # -- Fan-out based on what's provided ----------------------------------

        # URL analysis
        if url:
            if self.local_mode:
                tasks.append(("url", self.local_url.score(url)))
            else:
                tasks.append(("url", self.url.score(url)))

        # NLP - phishing, prompt injection, AI-generated content
        if text:
            if self.local_mode:
                tasks.append(("nlp", self.local_nlp.analyse(text)))
            else:
                tasks.append(("nlp", self.nlp.analyse(text)))

        # Behaviour anomaly - from log data
        if log_data:
            tasks.append(("anomaly", self.anomaly.detect(log_data)))

        # Deepfake - file-based
        if file_bytes and filename:
            tasks.append(("deepfake", self.deepfake.analyse(file_bytes, filename)))

        # If we have text that might also be a URL in email context
        if text and url:
            # For simplicity, fallback to heuristic or basic cloud detection for ai-gen
            tasks.append(("aigen", self.nlp.detect_ai_generated(text)))

        # Run all detectors concurrently — some local runners return dicts, not coroutines
        async def _wrap(val):
            if asyncio.iscoroutine(val):
                return await val
            return val

        results = await asyncio.gather(*[_wrap(t[1]) for t in tasks], return_exceptions=True)
        for (name, _), result in zip(tasks, results):
            if isinstance(result, Exception):
                detector_results[name] = {"score": 0.0, "error": str(result)}
            else:
                detector_results[name] = result

        # -- Gather context signals for ContextModifier ---------------------
        context_signals = {
            "domain_age_new": False,
            "spf_dkim_fail": False,
            "digit_substitution": False,
            "new_geo": False,
            "after_hours": False,
        }

        if url and "url" in detector_results:
            url_r = detector_results["url"]
            domain_age = int(url_r.get("domain_age_days", 999) or 999)
            context_signals["domain_age_new"] = 0 <= domain_age < 7
            context_signals["digit_substitution"] = bool(url_r.get("has_digit_substitution", False))
            # New signals from url_detector v2.0
            context_signals["homoglyph_spoofing"] = bool(url_r.get("has_homoglyph", False))
            context_signals["idn_domain"] = bool(url_r.get("is_idn", False))
            context_signals["dangerous_scheme"] = bool(url_r.get("dangerous_scheme", False))

        if email_headers:
            spf = str(email_headers.get("received-spf", "")).lower()
            dkim = str(email_headers.get("dkim-signature", ""))
            context_signals["spf_dkim_fail"] = "fail" in spf or dkim == ""

        hour = datetime.now(timezone.utc).hour
        context_signals["after_hours"] = hour < 7 or hour > 20  # outside 7am-8pm UTC

        # -- Fusion Engine - compute Sentinel Score -------------------------
        fusion_result = self.fusion.compute(detector_results, context_signals)

        # -- XAI - generate explanations -----------------------------------
        evidence = {}
        for det_name, det_result in detector_results.items():
            if det_result.get("score", 0) > 0.1:
                evidence[det_name] = self.xai.extract_evidence(det_name, det_result)

        threat_brief = await self.xai.generate_brief(
            evidence=evidence,
            score=fusion_result["sentinel_score"],
            severity=fusion_result["severity"],
        )

        # -- MITRE mapping -------------------------------------------------
        primary_threat = self._identify_primary_threat(detector_results, url, text, log_data, file_bytes)
        mitre_info = mitre_mapper.get_mapping(primary_threat)

        # -- Recommended action ---------------------------------------------
        action = self.responder.recommend(
            severity=fusion_result["severity"],
            threat_type=primary_threat,
            evidence=evidence,
        )

        # Extract risk_category from URL detector if available
        url_risk_category = (
            detector_results.get("url", {}).get("risk_category", "")
            if "url" in detector_results else ""
        )

        return {
            "incident_id": "",  # filled by caller
            "sentinel_score": fusion_result["sentinel_score"],
            "severity": fusion_result["severity"],
            "detectors_triggered": fusion_result["detectors_triggered"],
            "coordination_multiplier": fusion_result["coordination_multiplier"],
            "context_modifiers": fusion_result["context_modifiers"],
            "context_modifier_total": fusion_result["context_modifier_total"],
            "threat_brief": threat_brief,
            "evidence": evidence,
            "mitre_tactic": mitre_info.get("tactic_id", ""),
            "mitre_label": mitre_info.get("tactic_name", ""),
            "mitre_phase": mitre_info.get("phase", ""),
            "mitre_description": mitre_info.get("description", ""),
            "mitre_mitigations": mitre_info.get("mitigations", []),
            "recommended_action": action,
            "primary_threat": primary_threat,
            "url_risk_category": url_risk_category,
            "auto_detected": source != "manual",
            "ingestion_source": source,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def _identify_primary_threat(self, detector_results, url, text, log_data, file_bytes) -> str:
        """Pick the most likely threat label for MITRE mapping."""
        scores = {k: v.get("score", 0) for k, v in detector_results.items()}
        if not scores:
            return "unknown"

        # Highest-score detector wins
        top = max(scores, key=lambda k: scores[k])

        mapping = {
            "nlp": "phishing",
            "url": "url_malicious",
            "deepfake": "deepfake",
            "anomaly": "behaviour_anomaly",
            "aigen": "ai_generated",
        }

        # Sub-classify NLP outputs
        if top == "nlp" and "nlp" in detector_results:
            nlp_r = detector_results["nlp"]
            if nlp_r.get("prompt_injection_score", 0) > nlp_r.get("phishing_score", 0):
                return "prompt_injection"

        return mapping.get(top, "unknown")
