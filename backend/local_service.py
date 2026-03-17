"""
SpectraGuard - Local Protection Service
System tray app + OS notifications for threats detected even when dashboard is closed.
Polls /incidents every 5s and fires OS notifications for new threats >= 61.

Usage:
    pip install pystray pillow plyer
    python local_service.py
"""
import time
import threading
import json
import requests
import sys
import os

# ─── Try to import notification / tray libs ───────────────────────────────────
try:
    from plyer import notification as plyer_notify
    PLYER_OK = True
except ImportError:
    PLYER_OK = False

try:
    from pystray import Icon, MenuItem, Menu
    from PIL import Image, ImageDraw
    TRAY_OK = True
except ImportError:
    TRAY_OK = False

BACKEND_URL = "http://localhost:8000"
DASHBOARD_URL = "http://localhost:5173"
POLL_INTERVAL = 5  # seconds
SCORE_THRESHOLD = 61

# ─── Track which incidents we've already notified about ───────────────────────
_seen_ids: set = set()
_running = True

# ─── OS notification helper ───────────────────────────────────────────────────
def notify(title: str, message: str, urgency: str = "normal"):
    """Fire a native OS notification. Called from main.py /notify/system endpoint."""
    if PLYER_OK:
        try:
            timeout = 10 if urgency == "critical" else 6
            plyer_notify.notify(
                title=title,
                message=message,
                app_name="SpectraGuard",
                timeout=timeout,
                app_icon=os.path.join(os.path.dirname(__file__), "icons", "shield.ico") 
                         if os.path.exists(os.path.join(os.path.dirname(__file__), "icons", "shield.ico")) 
                         else "",
            )
        except Exception as e:
            print(f"[local_service] notify error: {e}")
    else:
        # Windows fallback via PowerShell balloon
        if sys.platform == "win32":
            try:
                import subprocess
                script = f"""
Add-Type -AssemblyName System.Windows.Forms
$notify = New-Object System.Windows.Forms.NotifyIcon
$notify.Icon = [System.Drawing.SystemIcons]::Shield
$notify.BalloonTipIcon = 'Warning'
$notify.BalloonTipTitle = '{title.replace("'", "")}'
$notify.BalloonTipText = '{message.replace("'", "").replace(chr(10), " ")}'
$notify.Visible = $true
$notify.ShowBalloonTip(6000)
Start-Sleep -Seconds 7
$notify.Dispose()
"""
                subprocess.Popen(
                    ["powershell", "-WindowStyle", "Hidden", "-Command", script],
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
            except Exception as e:
                print(f"[local_service] PowerShell notify error: {e}")
        else:
            # macOS / Linux fallback
            try:
                import subprocess
                if sys.platform == "darwin":
                    subprocess.run(["osascript", "-e", f'display notification "{message}" with title "{title}"'])
                else:
                    subprocess.run(["notify-send", title, message])
            except Exception:
                pass

# ─── Incident polling loop ────────────────────────────────────────────────────
def poll_incidents():
    global _seen_ids, _running
    print("[local_service] Polling for new threats...")
    while _running:
        try:
            r = requests.get(f"{BACKEND_URL}/incidents", timeout=5)
            if r.ok:
                data = r.json()
                incidents = data.get("incidents", [])
                for inc in incidents:
                    iid   = inc.get("incident_id", "")
                    score = inc.get("sentinel_score", 0)
                    sev   = inc.get("severity", "Unknown")
                    if iid and iid not in _seen_ids and score >= SCORE_THRESHOLD:
                        _seen_ids.add(iid)
                        notify(
                            title=f"SpectraGuard — {sev} Threat",
                            message=f"Score: {score}/100\n{inc.get('threat_brief', '')[:120]}",
                            urgency="critical" if score >= 81 else "normal",
                        )
                        print(f"[local_service] Notified: {iid} score={score}")
        except requests.exceptions.ConnectionError:
            pass  # Backend offline — silently wait
        except Exception as e:
            print(f"[local_service] poll error: {e}")
        time.sleep(POLL_INTERVAL)

# ─── System tray icon ─────────────────────────────────────────────────────────
def create_shield_icon():
    """Generate a simple shield icon PIL image."""
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    # Shield shape
    d.polygon([(32,4),(60,16),(60,36),(32,60),(4,36),(4,16)], fill="#0066FF")
    d.polygon([(32,10),(54,20),(54,38),(32,56),(10,38),(10,20)], fill="#003399")
    d.ellipse([22,22,42,42], fill="white")
    return img

def open_dashboard(icon, item):
    import webbrowser
    webbrowser.open(DASHBOARD_URL)

def quit_service(icon, item):
    global _running
    _running = False
    icon.stop()

def run_tray():
    if not TRAY_OK:
        print("[local_service] pystray not installed — running without tray icon.")
        print("[local_service] Install: pip install pystray pillow")
        return

    try:
        img = create_shield_icon()
    except Exception:
        from PIL import Image
        img = Image.new("RGBA", (64, 64), (0, 102, 255, 255))

    icon = Icon(
        "SpectraGuard",
        img,
        "SpectraGuard Active",
        menu=Menu(
            MenuItem("Open Dashboard", open_dashboard, default=True),
            MenuItem("Quit SpectraGuard", quit_service),
        )
    )
    icon.run()

# ─── Entry point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 50)
    print("  SpectraGuard Local Protection Service")
    print(f"  Monitoring: {BACKEND_URL}")
    print(f"  Dashboard:  {DASHBOARD_URL}")
    print(f"  Threshold:  score >= {SCORE_THRESHOLD}")
    print("=" * 50)

    # Start polling in a background thread
    poll_thread = threading.Thread(target=poll_incidents, daemon=True)
    poll_thread.start()

    # Run tray (blocks until quit)
    run_tray()

    # If tray not available, just stay alive
    if not TRAY_OK:
        try:
            while _running:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[local_service] Stopping.")
            _running = False
