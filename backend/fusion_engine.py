"""
SentinelAI — FUSION ENGINE
===========================
Implements the **Sentinel Score** — a fully custom, weighted multi-detector
threat scoring algorithm designed for multi-vector cyber attack detection.

Algorithm Reference:
--------------------
    SentinelScore = Σ(wᵢ × pᵢ) × CoordinationMultiplier × (1 + ContextModifier)

Where:
    wᵢ  = per-detector weight (configurable below)
    pᵢ  = probability output from each triggered detector (0.0 – 1.0)
    CoordinationMultiplier = amplifier when multiple detectors fire (coordinated attack signal)
    ContextModifier = additive bonus from environmental threat signals

Final score is scaled to 0–100 and placed in 4 severity bands:
    0–30   → CLEAN
    31–60  → SUSPICIOUS
    61–80  → LIKELY MALICIOUS
    81–100 → CRITICAL
"""

from __future__ import annotations

# ── Detector weights ───────────────────────────────────────────────────────────
# These reflect the relative reliability and threat-signal strength of each detector.
# nlp is highest because phishing/prompt-injection are the most common AI-powered attacks.
DETECTOR_WEIGHTS: dict[str, float] = {
    "nlp": 0.30,       # Phishing, prompt injection, AI-generated text
    "url": 0.25,       # Malicious URL (LightGBM lexical model)
    "deepfake": 0.20,  # Deepfake audio/video (EfficientNet + LSTM)
    "anomaly": 0.15,   # Behaviour anomaly (Isolation Forest)
    "aigen": 0.10,     # AI-generated content (RoBERTa stylometric)
}

# ── Coordination multipliers ──────────────────────────────────────────────────
# When multiple detectors fire simultaneously, it signals a coordinated attack.
# A single misfiring detector has no amplification.
COORDINATION_MULTIPLIERS: dict[int, float] = {
    0: 1.00,  # Nothing triggered
    1: 1.00,  # Single detector — no coordination signal
    2: 1.25,  # Two detectors — coordinated attack likely
    3: 1.50,  # Three or more — multi-vector assault, treat as near-certain
}
MAX_COORDINATION_KEY = 3  # Keys above this use the same multiplier as key=3

# ── Context modifier increments ───────────────────────────────────────────────
# Environmental signals that independently raise threat probability.
# Additive, capped at +0.20 total.
CONTEXT_MODIFIER_MAP: dict[str, float] = {
    "domain_age_new":     0.08,  # Domain registered < 7 days ago
    "spf_dkim_fail":      0.06,  # Email SPF/DKIM authentication failure
    "digit_substitution": 0.05,  # URL contains digit-for-letter substitutions (e.g. g00gle.com)
    "new_geo":            0.07,  # First-time login from unrecognised geographic location
    "after_hours":        0.04,  # Access during unusual hours (outside 7am–8pm UTC)
    "homoglyph_spoofing": 0.07,  # Unicode homoglyph characters used in domain (e.g. Cyrillic 'а')
    "idn_domain":         0.05,  # Internationalised Domain Name / Punycode detected
    "dangerous_scheme":   0.09,  # Dangerous URL scheme (javascript:, data:, vbscript:)
}
CONTEXT_MODIFIER_CAP = 0.20  # Max additional risk from context alone

# ── Severity bands ─────────────────────────────────────────────────────────────
SEVERITY_BANDS = [
    (81, 100, "Critical"),
    (61, 80,  "Likely Malicious"),
    (31, 60,  "Suspicious"),
    (0,  30,  "Clean"),
]


class FusionEngine:
    """
    Computes the Sentinel Score from individual detector outputs and context signals.
    Fully deterministic — no black-box library calls.
    """

    def compute(
        self,
        detector_results: dict[str, dict],
        context_signals: dict[str, bool],
    ) -> dict:
        """
        Parameters
        ----------
        detector_results : dict
            Keys are detector names (nlp, url, deepfake, anomaly, aigen).
            Each value must have a 'score' key (float 0.0–1.0).
        context_signals : dict
            Boolean flags for each context modifier (see CONTEXT_MODIFIER_MAP).

        Returns
        -------
        dict with keys:
            sentinel_score, severity, detectors_triggered,
            coordination_multiplier, context_modifiers, context_modifier_total,
            raw_weighted_sum
        """

        # ── Step 1: Weighted sum Σ(wᵢ × pᵢ) ────────────────────────────────
        weighted_sum = 0.0
        detectors_triggered = []

        for det_name, weight in DETECTOR_WEIGHTS.items():
            result = detector_results.get(det_name, {})
            prob = float(result.get("score", 0.0))
            prob = max(0.0, min(1.0, prob))  # Clamp to [0, 1]

            if prob > 0.0:
                weighted_sum += weight * prob
                detectors_triggered.append(det_name)

        # ── Step 2: CoordinationMultiplier ───────────────────────────────────
        n_triggered = len(detectors_triggered)
        multiplier_key = min(n_triggered, MAX_COORDINATION_KEY)
        coordination_multiplier = COORDINATION_MULTIPLIERS[multiplier_key]

        # ── Step 3: ContextModifier ──────────────────────────────────────────
        active_modifiers = []
        context_total = 0.0

        for signal_name, increment in CONTEXT_MODIFIER_MAP.items():
            if context_signals.get(signal_name, False):
                active_modifiers.append(signal_name)
                context_total += increment

        # Apply cap — no single environmental cluster can push score > cap
        context_total = min(context_total, CONTEXT_MODIFIER_CAP)

        # ── Step 4: Apply formula ────────────────────────────────────────────
        #   raw = Σ(wᵢ × pᵢ) × CoordinationMultiplier × (1 + ContextModifier)
        raw_score = weighted_sum * coordination_multiplier * (1 + context_total)

        # Clamp final raw to [0.0, 1.0] before scaling to 0–100
        raw_score = max(0.0, min(1.0, raw_score))

        # ── High Confidence Override ─────────────────────────────────────────
        # If any detector is >= 0.90 confidence, ensure base critical severity
        if any(float(detector_results.get(det, {}).get("score", 0.0)) >= 0.90 for det in detectors_triggered):
            raw_score = max(raw_score, 0.85)

        # Scale to 0–100 integer
        sentinel_score = int(round(raw_score * 100))

        # ── Step 5: Map to severity band ─────────────────────────────────────
        severity = self._map_severity(sentinel_score)

        return {
            "sentinel_score": sentinel_score,
            "severity": severity,
            "detectors_triggered": detectors_triggered,
            "coordination_multiplier": coordination_multiplier,
            "context_modifiers": active_modifiers,
            "context_modifier_total": round(context_total, 3),
            "raw_weighted_sum": round(weighted_sum, 4),
        }

    @staticmethod
    def _map_severity(score: int) -> str:
        """Maps 0–100 integer score to a severity label."""
        for low, high, label in SEVERITY_BANDS:
            if low <= score <= high:
                return label
        return "Unknown"
