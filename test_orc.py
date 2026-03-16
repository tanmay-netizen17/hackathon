import asyncio
import json
import sys

# Ensure backend modules are loaded
sys.path.append("backend")

from orchestrator import Orchestrator

async def main():
    orc = Orchestrator()
    
    url = "https://paypal.com.security-update-login.xyz/confirm"
    print(f"Testing URL: {url}")
    
    result = await orc.run(url=url)
    
    # Dump the evidence dict to ensure feature importance is present
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    asyncio.run(main())
