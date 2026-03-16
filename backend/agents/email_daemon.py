# pyre-ignore-all-errors
"""
SentinelAI Email Daemon
Monitors INBOX via IMAP IDLE, scores each email, alerts on threats.
Only logs incidents for score >= 40. Only triggers alerts for score >= 61.
"""

import imaplib, email, time, requests, threading, json, re
from email.header import decode_header
from datetime import datetime

# ── Configuration ─────────────────────────────────────────────────────────────
BACKEND_URL   = "http://localhost:8000"
CHECK_INTERVAL = 30   # seconds between inbox polls (IMAP IDLE fallback)

# ── Trusted sender domains — skip scoring entirely ────────────────────────────
# Add domains you trust. Emails FROM these domains are never flagged.
TRUSTED_DOMAINS = {
    # Google services
    "google.com", "gmail.com", "classroom.google.com",
    "drive-shares-dm-noreply@google.com",
    # Social / productivity
    "pinterest.com", "inspire.pinterest.com", "discover.pinterest.com",
    "canva.com", "engage.canva.com",
    "openai.com", "tm.openai.com",
    "github.com", "microsoft.com", "linkedin.com",
    "amazon.com", "apple.com", "netflix.com",
    "notion.so", "slack.com", "zoom.us",
    # Add your college/org domains
    "gnims.com",
}

# ── Scoring thresholds ─────────────────────────────────────────────────────────
THRESHOLD_LOG   = 40   # minimum score to save as incident
THRESHOLD_ALERT = 61   # minimum score to trigger browser notification
THRESHOLD_CRIT  = 81   # critical — immediate popup

# ── Feature extraction ─────────────────────────────────────────────────────────

STRONG_PHISHING_SIGNALS = [
    # Credential harvesting
    r'\bverify your (account|identity|email|password)\b',
    r'\bconfirm your (account|identity|email|password)\b',
    r'\bupdate your (payment|billing|credit card)\b',
    r'\b(account|card|service) (suspended|disabled|blocked|locked)\b',
    r'\bclick here to (verify|confirm|activate|restore|unlock)\b',
    r'\bunusual (activity|sign.?in|login) (detected|found)\b',
    r'\byour account (will be|has been) (suspended|closed|terminated)\b',
    r'\b(limited|restricted) access\b',
    r'\bimmediate(ly)? (action|attention|response) required\b',
    r'\bsecurity (alert|warning|breach|incident)\b',
    # URL manipulation
    r'https?://[^\s]*(\d{1,3}\.){3}\d{1,3}',   # IP address in URL
    r'https?://[^\s]*(paypa1|g00gle|amaz0n|micros0ft|app1e)',  # typosquat
    # Urgency + money
    r'\b(win|winner|won|prize|reward|gift card)\b',
    r'\byour (account|card).{0,30}(expired|expiring)\b',
    r'\bsend (your )?(password|credentials|ssn|social security)\b',
]

WEAK_SIGNALS = [
    r'\bpassword\b', r'\bclick\b', r'\blogin\b', r'\baccount\b',
    r'\burgent\b', r'\bexpire\b', r'\bsuspend\b', r'\bverify\b',
    r'\bconfirm\b', r'\bupdate\b', r'\bsecurity\b',
]

def extract_sender_domain(from_header: str) -> str:
    """Extract domain from From: header."""
    match = re.search(r'@([\w\.\-]+)', from_header)
    return match.group(1).lower() if match else ""

def is_trusted_sender(from_header: str) -> bool:
    """Return True if the sender domain is in the trusted list."""
    domain = extract_sender_domain(from_header)
    # Check exact match and parent domain match
    for trusted in TRUSTED_DOMAINS:
        if domain == trusted or domain.endswith("." + trusted):
            return True
    return False

def score_email(subject: str, body: str, from_header: str) -> dict:
    """
    Score an email for phishing risk.
    Returns { score: 0-100, signals: [...], verdict: str }
    """
    full_text = f"{subject} {body}".lower()
    signals   = []
    raw_score = 0.0

    # Strong signals — each worth 0.25
    for pattern in STRONG_PHISHING_SIGNALS:
        if re.search(pattern, full_text, re.IGNORECASE):
            signals.append(pattern)
            raw_score += 0.25

    # Weak signals — each worth 0.05, max contribution 0.20
    weak_hits = sum(1 for p in WEAK_SIGNALS if re.search(p, full_text, re.IGNORECASE))
    raw_score += min(weak_hits * 0.05, 0.20)

    # SPF/DKIM-style heuristics on sender
    domain = extract_sender_domain(from_header)
    if re.search(r'\d{4,}', domain):        raw_score += 0.15   # numbers in domain
    if domain.count('-') >= 3:              raw_score += 0.10   # lots of hyphens
    if len(domain.split('.')[0]) > 30:      raw_score += 0.10   # very long subdomain

    # Cap at 1.0
    raw_score = min(raw_score, 1.0)
    score_int = round(raw_score * 100)

    verdict = ("Critical"         if score_int >= 81 else
               "Likely Malicious" if score_int >= 61 else
               "Suspicious"       if score_int >= 40 else
               "Clean")

    return {
        "score":    score_int,
        "signals":  signals[:5],   # top 5 signals
        "verdict":  verdict,
    }

# ── Email parsing ──────────────────────────────────────────────────────────────

def decode_str(s):
    """Decode encoded email header."""
    if s is None:
        return ""
    parts = decode_header(s)
    decoded = []
    for part, enc in parts:
        if isinstance(part, bytes):
            decoded.append(part.decode(enc or "utf-8", errors="replace"))
        else:
            decoded.append(str(part))
    return " ".join(decoded)

def extract_body(msg) -> str:
    """Extract plain text body from email message."""
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp  = str(part.get("Content-Disposition", ""))
            if ctype == "text/plain" and "attachment" not in disp:
                try:
                    body += part.get_payload(decode=True).decode("utf-8", errors="replace")
                except Exception:
                    pass
    else:
        try:
            body = msg.get_payload(decode=True).decode("utf-8", errors="replace")
        except Exception:
            pass
    return body[:3000]   # first 3000 chars is enough for scoring

# ── Backend communication ──────────────────────────────────────────────────────

def send_heartbeat():
    """Tell backend this agent is alive."""
    try:
        url = os.environ.get("SENTINEL_API_URL", BACKEND_URL)
        requests.post(f"{url}/agents/checkin",
                     json={"agent": "email_daemon"}, timeout=2)
    except Exception:
        pass

def sync_trusted_domains():
    """Fetch additional trusted domains from the server whitelist."""
    global TRUSTED_DOMAINS
    try:
        url = os.environ.get("SENTINEL_API_URL", BACKEND_URL)
        res = requests.get(f"{url}/settings/trusted-domains", timeout=3)
        if res.status_code == 200:
            extra = res.json().get("domains", [])
            for dm in extra:
                TRUSTED_DOMAINS.add(dm)
    except Exception:
        pass

def submit_incident(incident: dict):
    """POST incident to backend only if score >= THRESHOLD_LOG."""
    if incident["sentinel_score"] < THRESHOLD_LOG:
        print(f"[EmailDaemon] ✓ Clean ({incident['sentinel_score']}) — "
              f"from {incident['from'][:50]} — not logged")
        return

    try:
        url = os.environ.get("SENTINEL_API_URL", BACKEND_URL)
        res = requests.post(f"{url}/ingest/email", json=incident, timeout=5)
        print(f"[EmailDaemon] ⚠ THREAT ({incident['sentinel_score']}) logged — "
              f"from {incident['from'][:50]}")
        return res.json()
    except Exception as e:
        print(f"[EmailDaemon] Error submitting incident: {e}")

def trigger_alert(incident: dict):
    """
    Trigger a browser notification via the backend SSE/WS alert channel.
    Only called for score >= THRESHOLD_ALERT.
    """
    try:
        url = os.environ.get("SENTINEL_API_URL", BACKEND_URL)
        requests.post(f"{url}/alerts/push", json={
            "type":     "email_threat",
            "severity": incident["severity"],
            "score":    incident["sentinel_score"],
            "from":     incident["from"],
            "subject":  incident["subject"],
            "incident_id": incident.get("incident_id"),
        }, timeout=3)
        print(f"[EmailDaemon] 🚨 ALERT PUSHED — score {incident['sentinel_score']}")
    except Exception as e:
        print(f"[EmailDaemon] Alert push failed: {e}")

# ── Main daemon loop ───────────────────────────────────────────────────────────

def process_email(msg_data, seen_ids: set) -> bool:
    """Process one raw email. Returns True if it was new and processed."""
    try:
        msg = email.message_from_bytes(msg_data)

        # Dedup by Message-ID
        msg_id = msg.get("Message-ID", "")
        if msg_id and msg_id in seen_ids:
            return False
        if msg_id:
            seen_ids.add(msg_id)

        from_header = decode_str(msg.get("From", ""))
        subject     = decode_str(msg.get("Subject", ""))
        body        = extract_body(msg)

        # Skip trusted senders entirely
        if is_trusted_sender(from_header):
            print(f"[EmailDaemon] ✓ Trusted sender — skipping: {from_header[:60]}")
            return True

        # Score the email
        result = score_email(subject, body, from_header)
        score  = result["score"]

        print(f"[EmailDaemon] Scored {score:3d} | {from_header[:55]}")

        # Build incident payload
        incident = {
            "incident_id":     f"INC-EMAIL-{int(time.time()*1000)}",
            "sentinel_score":  score,
            "severity":        result["verdict"],
            "from":            from_header,
            "subject":         subject,
            "signals":         result["signals"],
            "threat_type":     "phishing",
            "ingestion_source":"email_daemon",
            "timestamp":       datetime.utcnow().isoformat() + "Z",
        }

        # Only log if score is meaningful
        submit_incident(incident)

        # Push alert if genuinely suspicious
        if score >= THRESHOLD_ALERT:
            trigger_alert(incident)

        return True

    except Exception as e:
        print(f"[EmailDaemon] Error processing email: {e}")
        return False


def run_daemon(imap_host: str, username: str, password: str):
    seen_ids = set()
    print(f"[EmailDaemon] Connecting to {imap_host} as {username}...")

    while True:
        try:
            mail = imaplib.IMAP4_SSL(imap_host)
            mail.login(username, password)
            mail.select("INBOX")

            print(f"[EmailDaemon] Connected as {username}. Monitoring INBOX...")
            send_heartbeat()

            # Heartbeat thread
            def hb():
                while True:
                    send_heartbeat()
                    sync_trusted_domains()
                    time.sleep(15)
            threading.Thread(target=hb, daemon=True).start()

            last_uid = None

            while True:
                # Search for recent unseen emails
                _, data = mail.search(None, "UNSEEN")
                uid_list = data[0].split()

                for uid in uid_list:
                    if uid == last_uid:
                        continue
                    _, msg_data = mail.fetch(uid, "(RFC822)")
                    if msg_data and msg_data[0]:
                        process_email(msg_data[0][1], seen_ids)
                    last_uid = uid

                time.sleep(CHECK_INTERVAL)

        except imaplib.IMAP4.error as e:
            print(f"[EmailDaemon] IMAP error: {e} — retrying in 30s")
            time.sleep(30)
        except Exception as e:
            print(f"[EmailDaemon] Unexpected error: {e} — retrying in 30s")
            time.sleep(30)


if __name__ == "__main__":
    import sys, os
    
    imap_host = os.environ.get("EMAIL_IMAP_HOST")
    username  = os.environ.get("EMAIL_USER")
    password  = os.environ.get("EMAIL_APP_PASSWORD")
    
    # Fallback to sys.argv for manual testing if env not set
    if not username and len(sys.argv) >= 4:
        imap_host = sys.argv[1]
        username  = sys.argv[2]
        password  = sys.argv[3]
        
    if not username or not password:
        print("Error: Missing credentials in environment variables (EMAIL_USER, EMAIL_APP_PASSWORD).")
        sys.exit(1)
        
    run_daemon(imap_host or "imap.gmail.com", username, password)
