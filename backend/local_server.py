# pyre-ignore-all-errors
"""
SentinelAI Local Server
Run: python local_server.py
Serves inference on localhost:8001 — no internet required
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import uvicorn, os, math

app = FastAPI(title="SentinelAI Local", docs_url=None)

app.add_middleware(CORSMiddleware,
    allow_origins=["*"],   # localhost only anyway
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Try loading ONNX models — gracefully degrade if not exported yet ──────────
nlp_session = None
url_session  = None
tokenizer    = None

try:
    import onnxruntime as ort
    from transformers import RobertaTokenizer
    import numpy as np

    NLP_PATH = os.path.join(os.path.dirname(__file__), "models/onnx/nlp_detector.onnx")
    URL_PATH = os.path.join(os.path.dirname(__file__), "models/onnx/url_detector.onnx")

    if os.path.exists(NLP_PATH):
        nlp_session = ort.InferenceSession(NLP_PATH, providers=["CPUExecutionProvider"])
        tokenizer   = RobertaTokenizer.from_pretrained("roberta-base")
        print("✓ NLP detector loaded")
    else:
        print("⚠ NLP model not found at models/onnx/nlp_detector.onnx — using heuristic fallback")

    if os.path.exists(URL_PATH):
        url_session = ort.InferenceSession(URL_PATH, providers=["CPUExecutionProvider"])
        print("✓ URL detector loaded")
    else:
        print("⚠ URL model not found at models/onnx/url_detector.onnx — using heuristic fallback")

except ImportError:
    print("⚠ onnxruntime not installed — all detectors using heuristic fallback")
    print("  Run: pip install onnxruntime transformers")

print("\n🛡  SentinelAI Local Server ready")
print("   http://localhost:8001")
print("   Zero data leaves this machine\n")

# ── Heuristic fallbacks (work even without ONNX models) ──────────────────────

PHISHING_KEYWORDS = [
    'suspended','verify','immediately','account','password','click here',
    'urgent','confirm','update','limited','expire','unusual activity',
    'login','credentials','bank','paypal','amazon','apple'
]

def heuristic_text_score(text: str) -> float:
    text_lower = text.lower()
    hits = sum(1 for kw in PHISHING_KEYWORDS if kw in text_lower)
    return min(hits / 5.0, 1.0)

def heuristic_url_score(url: str) -> float:
    import re
    score = 0.0
    if not url.startswith('https'): score += 0.2
    if len(url) > 100:              score += 0.15
    if url.count('.') > 4:          score += 0.2
    if url.count('-') > 3:          score += 0.15
    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url): score += 0.4
    if any(c in url.lower() for c in ['paypa1','amaz0n','g00gle','micosoft']): score += 0.5
    if re.search(r'[a-z0-9]{20,}\.', url): score += 0.2
    return min(score, 1.0)

# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/local/health")
async def health():
    return {
        "status": "running",
        "mode": "local",
        "data_left_device": False,
        "nlp_model":  "onnx" if nlp_session else "heuristic",
        "url_model":  "onnx" if url_session  else "heuristic",
    }

@app.post("/local/analyse/text")
async def analyse_text(payload: dict):
    text = payload.get("text", "").strip()
    if not text:
        raise HTTPException(400, "text field required")

    if nlp_session and tokenizer:
        import numpy as np
        enc    = tokenizer(text, return_tensors="np", max_length=128,
                          padding="max_length", truncation=True)
        logits = nlp_session.run(None, {
            "input_ids":      enc["input_ids"].astype(np.int64),
            "attention_mask": enc["attention_mask"].astype(np.int64),
        })[0]
        prob = float(1 / (1 + math.exp(-logits[0][1])))
        method = "onnx"
    else:
        prob   = heuristic_text_score(text)
        method = "heuristic"

    return {
        "score":             round(prob, 4),
        "label":             "malicious" if prob >= 0.5 else "clean",
        "method":            method,
        "mode":              "local",
        "data_left_device":  False,
    }

@app.post("/local/analyse/url")
async def analyse_url(payload: dict):
    url = payload.get("url", "").strip()
    if not url:
        raise HTTPException(400, "url field required")

    if url_session:
        import numpy as np
        features = extract_url_features(url)
        prob     = float(url_session.run(None, {"float_input": features})[1][0][1])
        method   = "onnx"
    else:
        prob   = heuristic_url_score(url)
        method = "heuristic"

    return {
        "score":             round(prob, 4),
        "label":             "malicious" if prob >= 0.5 else "clean",
        "method":            method,
        "mode":              "local",
        "data_left_device":  False,
    }

def extract_url_features(url: str):
    import re, numpy as np
    f = [
        len(url), url.count('.'), url.count('-'), url.count('_'),
        url.count('/'), url.count('?'), url.count('='), url.count('@'),
        url.count('%'), int(url.startswith('https')),
        len(re.findall(r'\d', url)),
        int(bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url))),
        int(any(c in url for c in ['paypa1','g00gle','amaz0n'])),
    ]
    f.extend([0] * (50 - len(f)))
    return np.array([f], dtype=np.float32)

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8001, log_level="warning")
