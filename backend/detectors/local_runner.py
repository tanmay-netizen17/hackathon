"""
SentinelAI — Local ONNX Inference Runners
Used when LOCAL_MODE=true so zero data leaves the device.
"""

import numpy as np


class LocalNLPDetector:
    """
    Runs NLP threat detection fully on-device via ONNX Runtime.
    Drop-in replacement for NLPDetector when LOCAL_MODE is active.
    """

    def __init__(self, model_path: str = "models/nlp_detector.onnx"):
        try:
            import onnxruntime as ort
            self.session = ort.InferenceSession(
                model_path, providers=["CPUExecutionProvider"]
            )
            self._available = True
            print(f"[LocalMode] NLP ONNX model loaded from {model_path}")
        except Exception as e:
            self._available = False
            print(f"[LocalMode] NLP ONNX load failed ({e}). Using fallback scoring.")

    def predict(self, input_ids, attention_mask) -> float:
        """Returns probability [0,1] that the input is malicious."""
        if not self._available:
            return 0.0
        outputs = self.session.run(
            None,
            {
                "input_ids":      input_ids if isinstance(input_ids, np.ndarray) else input_ids.numpy(),
                "attention_mask": attention_mask if isinstance(attention_mask, np.ndarray) else attention_mask.numpy(),
            },
        )
        logits = outputs[0]
        prob = 1 / (1 + np.exp(-logits[0][1]))  # sigmoid on malicious class
        return float(prob)

    async def analyse(self, text: str) -> dict:
        """
        Async wrapper matching the interface of cloud NLPDetector.
        Uses a basic keyword heuristic when model is unavailable.
        """
        if not self._available:
            return await self._heuristic_analyse(text)

        try:
            from transformers import AutoTokenizer
            tokenizer = AutoTokenizer.from_pretrained("distilbert-base-uncased")
            enc = tokenizer(text, return_tensors="np", truncation=True, max_length=512)
            phishing_score = self.predict(enc["input_ids"], enc["attention_mask"])
            return {
                "score":               phishing_score,
                "phishing_score":      phishing_score,
                "prompt_injection_score": 0.0,
                "local_mode":          True,
            }
        except Exception:
            return await self._heuristic_analyse(text)

    async def _heuristic_analyse(self, text: str) -> dict:
        """Simple keyword heuristic fallback."""
        phishing_keywords = [
            "verify your account", "click here immediately", "urgent action",
            "password expired", "bank account", "suspended", "limited time",
        ]
        lower = text.lower()
        hits = sum(1 for kw in phishing_keywords if kw in lower)
        score = min(hits * 0.2, 0.9)
        return {
            "score":               score,
            "phishing_score":      score,
            "prompt_injection_score": 0.0,
            "local_mode":          True,
            "heuristic_fallback":  True,
        }


class LocalURLDetector:
    """
    Runs URL threat detection fully on-device via ONNX Runtime.
    Drop-in replacement for URLDetector when LOCAL_MODE is active.
    """

    def __init__(self, model_path: str = "models/url_detector.onnx"):
        try:
            import onnxruntime as ort
            self.session = ort.InferenceSession(
                model_path, providers=["CPUExecutionProvider"]
            )
            self._available = True
            print(f"[LocalMode] URL ONNX model loaded from {model_path}")
        except Exception as e:
            self._available = False
            print(f"[LocalMode] URL ONNX load failed ({e}). Using feature heuristic.")

    def predict(self, feature_vector: np.ndarray) -> float:
        """Returns probability [0,1] that the URL is malicious."""
        if not self._available:
            return 0.0
        outputs = self.session.run(
            None, {"float_input": feature_vector.reshape(1, -1).astype(np.float32)}
        )
        # outputs[1] is the probability dict from sklearn pipeline
        return float(outputs[1][0][1])

    async def score(self, url: str) -> dict:
        """
        Async wrapper matching the interface of cloud URLDetector.
        """
        features, meta = self._extract_features(url)
        if not self._available:
            score = self._heuristic_score(url)
        else:
            try:
                score = self.predict(features)
            except Exception:
                score = self._heuristic_score(url)
        return {
            "score":              score,
            "url_score":          score,
            "local_mode":         True,
            **meta,
        }

    def _extract_features(self, url: str):
        """Extract a 50-dim feature vector from the URL."""
        import re
        feat = np.zeros(50, dtype=np.float32)
        feat[0] = len(url)
        feat[1] = url.count(".")
        feat[2] = url.count("-")
        feat[3] = url.count("/")
        feat[4] = url.count("?")
        feat[5] = url.count("=")
        feat[6] = url.count("@")
        feat[7] = url.count("_")
        feat[8] = 1.0 if url.startswith("https") else 0.0
        feat[9] = len(re.findall(r"\d", url))
        # Check for common phishing patterns
        feat[10] = 1.0 if re.search(r"(login|verify|secure|account|bank|paypal|apple)", url, re.I) else 0.0
        feat[11] = 1.0 if re.search(r"\d+\.\d+\.\d+\.\d+", url) else 0.0  # IP in URL
        meta = {
            "has_digit_substitution": bool(re.search(r"[0-9]", url)),
            "domain_age_days":        999,  # Unknown without DNS lookup in local mode
        }
        return feat, meta

    def _heuristic_score(self, url: str) -> float:
        """Simple rule-based scoring."""
        import re
        score = 0.0
        if re.search(r"(login|verify|secure|account|bank|paypal|apple)", url, re.I):
            score += 0.3
        if "@" in url:
            score += 0.3
        if re.search(r"\d+\.\d+\.\d+\.\d+", url):
            score += 0.4
        if len(url) > 100:
            score += 0.1
        if url.count("-") > 3:
            score += 0.1
        return min(score, 1.0)
