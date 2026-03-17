from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from detectors.local_runner import LocalNLPDetector, LocalURLDetector

app = FastAPI(title="SpectraGuard Local Inference Server")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

nlp = LocalNLPDetector()
url_detector = LocalURLDetector()

@app.get("/health")
@app.get("/local/health")
async def health():
    return {"status": "ok", "mode": "local"}

@app.post("/analyse/url")
async def analyse_url(data: dict):
    url = data.get("url")
    return url_detector.score(url)

@app.post("/analyse/text")
async def analyse_text(data: dict):
    text = data.get("text")
    return nlp.analyse(text)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)
