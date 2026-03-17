from fastapi import FastAPI
print("[*] Importing dependencies...")
from orchestrator import Orchestrator
print("[*] Dependencies imported.")

app = FastAPI()
print("[*] FastAPI instance created.")

@app.on_event("startup")
async def startup():
    print("[*] Startup event running...")
    orc = Orchestrator()
    print("[*] Orchestrator initialized.")

if __name__ == "__main__":
    print("[*] Script test complete.")
