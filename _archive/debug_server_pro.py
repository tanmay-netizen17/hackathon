import sys
import traceback
import os

print("[*] Starting pro-debug script...")
try:
    print("[*] Importing main...")
    import main
    print("[*] Main imported. App object exists:", hasattr(main, "app"))
    
    import uvicorn
    print("[*] Starting uvicorn on port 8005...")
    uvicorn.run(main.app, host="127.0.0.1", port=8005, log_level="debug")
    print("[*] Uvicorn finished normally.")
except Exception as e:
    print(f"[!] CAUGHT EXCEPTION: {e}")
    traceback.print_exc()
finally:
    print("[*] Debug script exiting.")
