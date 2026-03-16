"""
SentinelAI — XAI Synthesiser
Generates human-readable explanations for every detection:
  1. Token highlights (NLP)
  2. SHAP feature importance (URL)
  3. Grad-CAM regions (Deepfake)
  4. Anomaly deviation map (Behaviour)
  5. GPT-4o-mini plain English brief
"""

from __future__ import annotations

import os
import json
from typing import Optional

try:
    from openai import AsyncOpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

try:
    import shap
    import numpy as np
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False

GPT_PROMPT_TEMPLATE = """You are a cybersecurity explainer. A threat detection system has flagged an input.
Raw detection output: {json_evidence}
Sentinel Score: {score}/100  Severity: {severity}
Write exactly 3 sentences:
1. What was detected and confidence level
2. The top 2-3 specific evidence features that made it suspicious
3. The exact action the user should take right now
Keep language clear enough for a non-technical user. Be specific, not generic."""


class XAISynthesiser:
    """
    Produces explainability artifacts for every detection.
    """

    def __init__(self):
        self._openai: Optional[AsyncOpenAI] = None
        api_key = os.getenv("OPENAI_API_KEY", "")
        if api_key and OPENAI_AVAILABLE:
            self._openai = AsyncOpenAI(api_key=api_key)

    def extract_evidence(self, detector_name: str, detector_result: dict) -> dict:
        """
        Convert raw detector output into structured XAI evidence.
        Each detector type has its own evidence schema.
        """
        if detector_name == "nlp":
            return self._nlp_evidence(detector_result)
        elif detector_name == "url":
            return self._url_evidence(detector_result)
        elif detector_name == "deepfake":
            return self._deepfake_evidence(detector_result)
        elif detector_name == "anomaly":
            return self._anomaly_evidence(detector_result)
        elif detector_name == "aigen":
            return self._aigen_evidence(detector_result)
        return {"score": detector_result.get("score", 0), "raw": detector_result}

    async def generate_brief(self, evidence: dict, score: int, severity: str) -> str:
        """
        Generate GPT-4o-mini plain English explanation.
        Falls back to template-based brief if OpenAI is unavailable.
        """
        if self._openai:
            try:
                prompt = GPT_PROMPT_TEMPLATE.format(
                    json_evidence=json.dumps(evidence, indent=2)[:2000],
                    score=score,
                    severity=severity,
                )
                response = await self._openai.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=200,
                    temperature=0.3,
                )
                return response.choices[0].message.content.strip()
            except Exception:
                pass

        # Fallback: rule-based brief
        return self._generate_fallback_brief(evidence, score, severity)

    # ── Evidence extractors ───────────────────────────────────────────────────

    @staticmethod
    def _nlp_evidence(r: dict) -> dict:
        return {
            "score": r.get("score", 0),
            "phishing_score": r.get("phishing_score", 0),
            "prompt_injection_score": r.get("prompt_injection_score", 0),
            "top_tokens": r.get("top_tokens", []),
            "model_used": r.get("model_used", "heuristic"),
            "header_verdict": r.get("header_verdict", "N/A"),
            "char_count": r.get("char_count", 0),
            "explanation": XAISynthesiser._nlp_explain(r),
        }

    @staticmethod
    def _nlp_explain(r: dict) -> str:
        tokens = r.get("top_tokens", [])
        score = r.get("score", 0)
        if score > 0.7:
            return f"High-confidence phishing signal. Key triggering words: {', '.join(tokens[:3]) or 'none'}."
        elif score > 0.4:
            return f"Moderate phishing/injection signal. Suspicious terms: {', '.join(tokens[:3]) or 'none'}."
        return "Low-confidence signal. Content patterns match known threat vocabulary slightly."

    @staticmethod
    def _url_evidence(r: dict) -> dict:
        return {
            "score": r.get("score", 0),
            "score_pct": r.get("score_pct", 0),
            "url": r.get("url", ""),
            "label": r.get("label", ""),
            "method": r.get("method", ""),
            "registrable_domain": r.get("registrable_domain", ""),
            "full_host": r.get("full_host", ""),
            "feature_importance": r.get("feature_importance", []),
            "evidence_notes": r.get("evidence_notes", []),
            "risk_category": r.get("risk_category", ""),
        }

    @staticmethod
    def _url_explain(r: dict) -> str:
        parts = []
        if r.get("dangerous_scheme"):
            parts.append("dangerous URL scheme (e.g. javascript:, data:)")
        if r.get("is_ip_address"):
            parts.append("raw IP address used instead of domain name")
        if r.get("has_homoglyph"):
            parts.append("Unicode homoglyph spoofing detected (visually identical but different characters)")
        if r.get("is_idn"):
            parts.append("Internationalized Domain Name (IDN / Punycode) — potential visual spoofing")
        if r.get("has_digit_substitution"):
            parts.append("digit-for-letter substitution (e.g. g00gle, payp4l)")
        if r.get("uses_shortener"):
            parts.append("URL shortener masking the true destination")
        if r.get("suspicious_tld"):
            parts.append("suspicious top-level domain often abused in phishing")
        if r.get("has_at_in_url"):
            parts.append("@ sign in URL — browser may redirect to a different host")
        age = r.get("domain_age_days", -1)
        if 0 <= age < 7:
            parts.append(f"domain registered only {age} day(s) ago")
        elif 0 <= age < 30:
            parts.append(f"recently registered domain ({age} days old)")
        risk_cat = r.get("risk_category", "")
        if parts:
            suffix = f" [Risk category: {risk_cat}]" if risk_cat else ""
            return f"URL flagged for: {'; '.join(parts)}.{suffix}"
        return (
            f"URL scored {r.get('score', 0):.0%} malicious by lexical feature analysis"
            + (f" [{risk_cat}]" if risk_cat else ".")
        )

    @staticmethod
    def _deepfake_evidence(r: dict) -> dict:
        return {
            "score": r.get("score", 0),
            "score_pct": r.get("score_pct", 0),
            "label": r.get("label", ""),
            "method": r.get("method", ""),
            "signals": r.get("signals", {}),
            "evidence_notes": r.get("evidence_notes", []),
            "frames_analysed": r.get("frames_analysed", 1),
            "consistency": r.get("consistency", 0.0),
        }

    @staticmethod
    def _deepfake_explain(r: dict) -> str:
        score = r.get("score", 0)
        if score > 0.7:
            return "Strong deepfake indicators: spatial inconsistencies and temporal frame anomalies detected."
        elif score > 0.4:
            return "Moderate deepfake signals: compression artifacts and region inconsistencies noted."
        return "Low deepfake probability. Content appears authentic."

    @staticmethod
    def _anomaly_evidence(r: dict) -> dict:
        deviations = r.get("deviation_map", {})
        anomalous = r.get("anomalous_features", [])
        return {
            "score": r.get("score", 0),
            "anomalous_features": anomalous,
            "deviation_map": deviations,
            "log_lines_parsed": r.get("log_lines_parsed", 0),
            "model_used": r.get("model_used", "isolation-forest"),
            "explanation": XAISynthesiser._anomaly_explain(r),
        }

    @staticmethod
    def _anomaly_explain(r: dict) -> str:
        anomalous = r.get("anomalous_features", [])
        if anomalous:
            return f"Behaviour anomaly: {', '.join(anomalous[:3])} deviate significantly from baseline."
        return "Behaviour patterns slightly abnormal but within threshold."

    @staticmethod
    def _aigen_evidence(r: dict) -> dict:
        return {
            "score": r.get("score", 0),
            "perplexity_estimate": r.get("perplexity_estimate", 0),
            "ai_markers_found": r.get("ai_markers_found", []),
            "explanation": XAISynthesiser._aigen_explain(r),
        }

    @staticmethod
    def _aigen_explain(r: dict) -> str:
        markers = r.get("ai_markers_found", [])
        score = r.get("score", 0)
        if score > 0.6 and markers:
            return f"Content likely AI-generated. Markers found: {', '.join(markers[:3])}."
        elif score > 0.3:
            return "Content shows stylometric patterns common in AI-generated text."
        return "Content appears human-authored."

    @staticmethod
    def _compute_shap_values(features: dict) -> list[dict]:
        """
        Compute SHAP-style feature importance for URL features.
        Uses calibrated proxy weights (aligned with v2.0 feature set).
        Negative weights denote features that *reduce* risk.
        """
        importance_weights = {
            # High-certainty hard signals
            "dangerous_scheme":         0.40,
            "is_ip_address":            0.35,
            "has_homoglyph":            0.32,
            "has_digit_sub":            0.28,
            "has_double_ext":           0.25,
            "has_at_in_url":            0.22,
            "is_idn":                   0.20,
            "uses_shortener":           0.20,
            "suspicious_tld":           0.18,
            # Medium signals
            "domain_has_phishing_kw":   0.15,
            "has_b64_payload":          0.13,
            "url_entropy":              0.12,
            "redirect_count":           0.10,
            "has_hex_encoding":         0.09,
            "num_subdomains":           0.08,
            # Soft contextual
            "url_length":               0.02,
            "hyphen_ratio_domain":      0.06,
            # Risk-reducing
            "is_https":                -0.08,
        }
        results = []
        for feat, weight in importance_weights.items():
            val = features.get(feat, 0)
            contribution = weight * float(val)
            results.append({
                "feature": feat,
                "value": round(float(val), 4),
                "shap_value": round(contribution, 4),
            })
        results.sort(key=lambda x: abs(x["shap_value"]), reverse=True)
        return results[:12]

    @staticmethod
    def _generate_fallback_brief(evidence: dict, score: int, severity: str) -> str:
        """Template-based brief when GPT-4o-mini is unavailable."""
        active = list(evidence.keys())
        if not active:
            return (
                f"SentinelAI scored this input {score}/100 ({severity}). "
                "No specific threat signatures were identified with high confidence. "
                "Exercise caution and verify with your security team."
            )

        det_names = {"nlp": "phishing/injection", "url": "malicious URL", "deepfake": "deepfake media",
                     "anomaly": "behaviour anomaly", "aigen": "AI-generated content"}
        threats = [det_names.get(d, d) for d in active[:2]]
        threat_str = " and ".join(threats)

        top_evidence = []
        for det in active[:2]:
            ev = evidence.get(det, {})
            exp = ev.get("explanation", "")
            if exp:
                top_evidence.append(exp)

        action = "Block and report this immediately." if score > 80 else \
                 "Do not interact — escalate to your security team." if score > 60 else \
                 "Treat with caution and verify with IT."

        s1 = f"SentinelAI detected {threat_str} with {score}% confidence ({severity} severity)."
        s2 = " ".join(top_evidence[:2]) or "Multiple threat indicators were identified."
        s3 = action
        return f"{s1} {s2} {s3}"
