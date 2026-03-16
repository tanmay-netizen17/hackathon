# pyre-ignore-all-errors
"""
SentinelAI — Input Sanitisation
Protects every endpoint against malformed, malicious, or oversized inputs.
"""

import re
from html import unescape


def sanitise_text_input(raw: str) -> str:
    """
    Sanitise free-text / email content before passing to detectors.

    Steps:
    1. Strip HTML tags
    2. Unescape HTML entities
    3. Remove null bytes
    4. Truncate to a safe maximum length
    """
    if not isinstance(raw, str):
        raw = str(raw)
    # Strip HTML tags
    clean = re.sub(r"<[^>]+>", "", raw)
    # Unescape HTML entities (&amp; → &, etc.)
    clean = unescape(clean)
    # Remove null bytes (can cause downstream issues)
    clean = clean.replace("\x00", "")
    # Truncate to 10 000 chars — prevents DoS via enormous payloads
    return clean[:10000].strip()


def sanitise_url_input(raw: str) -> str:
    """
    Sanitise a URL string before passing to the URL detector.

    Strips characters that are not valid in URLs to prevent injection.
    """
    if not isinstance(raw, str):
        raw = str(raw)
    # Allow only RFC-3986 characters
    clean = re.sub(r"[^\w\-._~:/?#\[\]@!$&'()*+,;=%]", "", raw)
    # Truncate to 2 048 chars — standard browser limit
    return clean[:2048].strip()


def sanitise_log_input(raw: str) -> str:
    """
    Sanitise log data. More permissive than URL, but still bounded.
    """
    if not isinstance(raw, str):
        raw = str(raw)
    # Remove null bytes
    clean = raw.replace("\x00", "")
    return clean[:50000].strip()
