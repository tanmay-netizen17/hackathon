"""
SpectraGuard - Email Daemon
Monitors IMAP/SMTP streams for phishing and spear-phishing attempts.
Supports both simulation mode and real IMAP mode.
"""
import asyncio
import time
import random
import sys
import email as email_lib   # use alias — never shadow stdlib with plain 'email'

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    requests = None
    REQUESTS_OK = False
    print("[email_daemon] requests not installed — HTTP calls disabled")

BACKEND_URL = "http://localhost:8000"
AGENT_NAME  = "email_daemon"

# ─── Simulated phishing emails for demo mode ──────────────────────────────────
SAMPLE_PHISH = [
    {
        "from":    "security@paypai-alerts.com",
        "subject": "Your account has been limited",
        "body":    "Your PayPal account has been limited. Click here to restore: http://paypal-secure.evil.com/restore",
    },
    {
        "from":    "it-helpdesk@microsoft-corp.net",
        "subject": "Urgent: Password Reset Required",
        "body":    "Your Microsoft password expires today. Reset now at https://microsoft-reset.xyz",
    },
    {
        "from":    "noreply@amazon-security-team.co",
        "subject": "URGENT: Unauthorized access detected",
        "body":    "Someone tried to log into your Amazon account. Verify here: http://amaz0n-secure.ru/verify",
    },
]

def heartbeat():
    if not REQUESTS_OK:
        return
    try:
        requests.post(f"{BACKEND_URL}/agents/heartbeat/{AGENT_NAME}", timeout=3)
    except Exception:
        pass

def analyse_email(email: dict) -> dict | None:
    """Send email content to SpectraGuard for analysis."""
    if not REQUESTS_OK:
        return None
    body_text = f"Subject: {email['subject']}\nFrom: {email['from']}\n\n{email['body']}"
    try:
        r = requests.post(f"{BACKEND_URL}/analyse", json={
            "input":  body_text,
            "type":   "text",
            "source": "email_daemon",
        }, timeout=10)
        if r.ok:
            return r.json()
    except Exception as e:
        print(f"[email_daemon] analyse error: {e}")
    return None

def push_alert(incident: dict):
    """Push alert to SSE stream for the dashboard."""
    if not REQUESTS_OK:
        return
    try:
        requests.post(f"{BACKEND_URL}/alerts/push", json=incident, timeout=3)
    except Exception:
        pass

def trigger_os_notification(incident: dict):
    """Tell local_service.py to fire an OS notification immediately."""
    if not REQUESTS_OK:
        return
    score = incident.get("sentinel_score", 0)
    try:
        requests.post(f"{BACKEND_URL}/notify/system", json={
            "title":   f"SpectraGuard — {incident.get('severity', 'Threat')} Email",
            "message": f"From: {incident.get('from', 'unknown')[:50]}\nScore: {score}/100",
            "urgency": "critical" if score >= 81 else "normal",
        }, timeout=2)
    except Exception:
        pass

def run_daemon(imap_host: str = "", email_user: str = "", email_pass: str = ""):
    """Main daemon loop. Falls back to simulation if no credentials given."""
    real_mode = bool(imap_host and email_user and email_pass)
    print(f"[email_daemon] Starting in {'REAL IMAP' if real_mode else 'SIMULATION'} mode...")
    
    seen_ids: set = set()

    while True:
        heartbeat()

        if real_mode:
            # ── Real IMAP polling ──────────────────────────────────────────────
            try:
                import imaplib
                mail = imaplib.IMAP4_SSL(imap_host)
                mail.login(email_user, email_pass)
                mail.select("INBOX")
                _, data = mail.search(None, "UNSEEN")
                ids = data[0].split()
                for uid in ids[-5:]:  # Only check last 5 unseen
                    uid_str = uid.decode() if isinstance(uid, bytes) else str(uid)
                    if uid_str in seen_ids:
                        continue
                    seen_ids.add(uid_str)
                    _, raw = mail.fetch(uid, "(RFC822)")
                    
                    # Safe message parsing — handle bytes or str
                    raw_data = raw[0][1]
                    if isinstance(raw_data, bytes):
                        msg = email_lib.message_from_bytes(raw_data)
                    elif isinstance(raw_data, str):
                        msg = email_lib.message_from_string(raw_data)
                    else:
                        msg = email_lib.message_from_bytes(bytes(raw_data))
                    
                    body = ""
                    if msg.is_multipart():
                        for part in msg.walk():
                            if part.get_content_type() == "text/plain":
                                raw_payload = part.get_payload(decode=True)
                                if isinstance(raw_payload, bytes):
                                    body = raw_payload.decode("utf-8", errors="replace")
                                break
                    else:
                        raw_payload = msg.get_payload(decode=True)
                        if isinstance(raw_payload, bytes):
                            body = raw_payload.decode("utf-8", errors="replace")
                    
                    email_data = {
                        "from":    str(msg["From"]),
                        "subject": str(msg["Subject"]),
                        "body":    body[:2000],
                    }
                    result = analyse_email(email_data)
                    if result and result.get("sentinel_score", 0) >= 60:
                        incident = {**result, "from": email_data["from"], "subject": email_data["subject"]}
                        push_alert(incident)
                        trigger_os_notification(incident)
                        print(f"[email_daemon] THREAT detected from {email_data['from']}: score={result.get('sentinel_score')}")

                mail.logout()
            except Exception as e:
                print(f"[email_daemon] IMAP error: {e}")
        else:
            # ── Simulation mode: occasionally fire a fake phish ────────────────
            if random.random() > 0.85:
                sample = random.choice(SAMPLE_PHISH)
                print(f"[email_daemon] Simulating phishing email from {sample['from']} ...")
                result = analyse_email(sample)
                if result:
                    score = result.get("sentinel_score", 0)
                    incident = {**result, "from": sample["from"], "subject": sample["subject"]}
                    push_alert(incident)
                    if score >= 60:
                        trigger_os_notification(incident)
                    print(f"[email_daemon] Score={score}")

        # Poll every 30 seconds
        time.sleep(30)


if __name__ == "__main__":
    if len(sys.argv) == 4:
        # Called by main.py subprocess: host, user, password
        run_daemon(sys.argv[1], sys.argv[2], sys.argv[3])
    elif len(sys.argv) == 1:
        # Called standalone — simulation mode
        run_daemon()
    else:
        print("Usage: python email_daemon.py [<imap_host> <email> <password>]")
        sys.exit(1)
