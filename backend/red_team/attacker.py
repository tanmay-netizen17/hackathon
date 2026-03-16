# pyre-ignore-all-errors
import re, random

HOMOGLYPHS = {
    'a': ['а','ɑ','@'], 'e': ['е','ë','3'], 'i': ['і','1','l'],
    'o': ['о','0','ο'], 's': ['ѕ','$','5'], 'c': ['с','ϲ'],
    'p': ['р','ρ'], 'x': ['х','х'],
}

SYNONYM_MAP = {
    'suspended': ['paused','frozen','disabled'],
    'immediately': ['now','at once','right away'],
    'verify': ['confirm','validate','authenticate'],
    'account': ['profile','membership','access'],
    'click': ['tap','select','press'],
    'password': ['credentials','passphrase'],
    'urgent': ['important','time-sensitive','critical'],
    'expire': ['lapse','end','terminate'],
}

def homoglyph_attack(text, rate=0.15):
    chars = list(text)
    for i, ch in enumerate(chars):
        if ch.lower() in HOMOGLYPHS and random.random() < rate:
            chars[i] = random.choice(HOMOGLYPHS[ch.lower()])
    return ''.join(chars)

def synonym_substitution(text):
    for kw, syns in SYNONYM_MAP.items():
        text = re.sub(re.escape(kw), random.choice(syns), text, flags=re.IGNORECASE)
    return text

def whitespace_injection(text):
    zwsp = '\u200b'
    return ' '.join(
        w[:len(w)//2] + zwsp + w[len(w)//2:] if len(w) > 4 else w
        for w in text.split()
    )

def case_randomisation(text):
    return ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in text)

def generate_text_attacks(original_text):
    return [
        {
            "attack_type": "homoglyph",
            "description": "Replaced characters with Unicode lookalikes (е instead of e, 0 instead of o)",
            "perturbed_text": homoglyph_attack(original_text)
        },
        {
            "attack_type": "synonym_substitution",
            "description": "Swapped high-signal phishing keywords with neutral synonyms",
            "perturbed_text": synonym_substitution(original_text)
        },
        {
            "attack_type": "whitespace_injection",
            "description": "Injected zero-width spaces to break tokenisation boundaries",
            "perturbed_text": whitespace_injection(original_text)
        },
        {
            "attack_type": "combined",
            "description": "All three attacks applied simultaneously — maximum evasion attempt",
            "perturbed_text": whitespace_injection(
                synonym_substitution(homoglyph_attack(original_text))
            )
        },
    ]

def generate_url_attacks(original_url):
    from urllib.parse import urlparse, urlunparse
    parsed = urlparse(original_url)
    domain = parsed.netloc
    token  = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=8))
    attacks = [
        {
            "attack_type": "subdomain_padding",
            "description": "Added legitimate-looking subdomain prefix to obscure malicious domain",
            "perturbed_url": original_url.replace(domain, f"secure.login.{domain}", 1)
        },
        {
            "attack_type": "path_randomisation",
            "description": "Randomised URL path segments to reduce entropy detection signal",
            "perturbed_url": urlunparse(parsed._replace(path=f"/verify/{token}{parsed.path}"))
        },
        {
            "attack_type": "https_masking",
            "description": "Forced HTTPS scheme to appear as a trusted secure connection",
            "perturbed_url": urlunparse(parsed._replace(scheme='https'))
        },
    ]
    return attacks
