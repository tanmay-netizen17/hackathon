"""
SentinelAI - Browser Relay
Bridges the Chrome extension to the backend multi-model engine.
"""
import asyncio
import json
from datetime import datetime

try:
    import requests
    _REQUESTS_OK = True
except ImportError:
    requests = None  # type: ignore[assignment]
    _REQUESTS_OK = False


class BrowserRelay:
    def __init__(self, backend_url: str = "http://localhost:8000"):
        self.backend_url = backend_url
        self.agent_name = "browser_extension"

    async def start(self):
        print(f"[*] Starting {self.agent_name} relay...")
        while True:
            if _REQUESTS_OK:
                try:
                    requests.post(  # type: ignore[union-attr]
                        f"{self.backend_url}/agents/heartbeat/{self.agent_name}",
                        timeout=3,
                    )
                except Exception:
                    pass
            await asyncio.sleep(30)

    def relay_url(self, url: str) -> dict:
        if not _REQUESTS_OK:
            return {"error": "requests library not available"}
        payload = {"url": url, "source": self.agent_name}
        try:
            return requests.post(  # type: ignore[union-attr]
                f"{self.backend_url}/analyse",
                json=payload,
                timeout=10,
            ).json()
        except Exception as e:
            return {"error": str(e)}


if __name__ == "__main__":
    relay = BrowserRelay()
    asyncio.run(relay.start())
