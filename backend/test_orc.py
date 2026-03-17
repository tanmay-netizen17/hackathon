import asyncio
from orchestrator import Orchestrator

async def test():
    print("[*] Initializing Orchestrator...")
    orc = Orchestrator()
    print("[*] Orchestrator ready.")
    print("[*] Running dummy URL scan...")
    res = await orc.run(url="http://example.com")
    print(f"[*] Result: {res['sentinel_score']}")
    print("[*] Test complete.")

if __name__ == "__main__":
    asyncio.run(test())
