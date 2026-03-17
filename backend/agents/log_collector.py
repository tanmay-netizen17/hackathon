import asyncio
import requests
import argparse
import random

class LogCollector:
    def __init__(self, backend_url="http://localhost:8000", log_type="auth"):
        self.backend_url = backend_url
        self.log_type = log_type
        self.agent_name = "log_collector"

    async def stream_logs(self):
        print(f"[*] {self.agent_name} tailing {self.log_type} logs...")
        while True:
            # Heartbeat
            try:
                requests.post(f"{self.backend_url}/agents/heartbeat/{self.agent_name}")
            except Exception:
                pass
            
            # Simulate log ingestion if something "interesting" happens
            if random.random() > 0.8:
                log_line = f"Mar 17 06:14:58 spectra-srv sshd[1234]: Failed password for root from 192.168.1.100"
                try:
                    requests.post(f"{self.backend_url}/analyse", json={
                        "input": log_line,
                        "type": "log",
                        "source": f"log_collector:{self.log_type}"
                    })
                except Exception:
                    pass

            await asyncio.sleep(10)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--type", default="auth")
    parser.add_argument("--url", default="http://localhost:8000")
    args = parser.parse_args()

    collector = LogCollector(backend_url=args.url, log_type=args.type)
    asyncio.run(collector.stream_logs())
