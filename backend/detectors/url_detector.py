"""
SentinelAI URL Detector
LightGBM classifier with 25 lexical features.
Correctly identifies the registrable domain (not the full hostname).
"""

import re, math, os, urllib.parse
import numpy as np

# Try loading LightGBM model
_lgb_model = None
MODEL_PATH  = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "..", "models", "url_lgbm.txt")
MODEL_PATH  = os.path.normpath(MODEL_PATH)

def _load_lgb():
    global _lgb_model
    if _lgb_model is not None:
        return _lgb_model
    if os.path.exists(MODEL_PATH):
        try:
            import lightgbm as lgb
            _lgb_model = lgb.Booster(model_file=MODEL_PATH)
            print(f"[URLDetector] ✅ LightGBM model loaded")
            return _lgb_model
        except Exception as e:
            print(f"[URLDetector] ⚠ Model load failed: {e}")
    else:
        print(f"[URLDetector] ⚠ Model file not found: {MODEL_PATH}")
    return None

_load_lgb()   # load at import time

# ── Domain extraction helpers ─────────────────────────────────────────────────

# Common multi-part TLDs
MULTI_TLDS = {
    'com.au','com.br','com.cn','com.mx','com.sg','com.uk',
    'co.uk','co.in','co.nz','co.za','net.au','org.au',
    'ac.uk','gov.uk','edu.au',
}

SUSPICIOUS_TLDS = {
    'xyz','tk','ml','ga','cf','gq','pw','top','click','link',
    'online','site','website','info','biz','ws','cc','su',
    'icu','cam','vip','win','bid','loan','work','party','trade'
}

LEGIT_BRANDS = [
    'paypal','google','apple','microsoft','amazon','facebook',
    'netflix','instagram','twitter','linkedin','dropbox','adobe',
    'chase','wellsfargo','bankofamerica','citibank','hsbc',
    'whatsapp','telegram','discord','steam','roblox','spotify'
]

def get_registrable_domain(url: str) -> str:
    """
    Extract the actual registrable domain — the part that identifies who OWNS the URL.
    
    Example:
      paypal.com.security-update-login.xyz  →  security-update-login.xyz
      secure.login.google.com               →  google.com
      192.168.1.1                           →  192.168.1.1  (IP)
    """
    try:
        parsed = urllib.parse.urlparse(url)
        host   = parsed.netloc.lower().split(':')[0]   # strip port
        
        # If it's an IP address, return as-is
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host):
            return host
        
        parts = host.split('.')
        if len(parts) < 2:
            return host
        
        # Check for multi-part TLD (e.g., co.uk)
        if len(parts) >= 3 and f"{parts[-2]}.{parts[-1]}" in MULTI_TLDS:
            return f"{parts[-3]}.{parts[-2]}.{parts[-1]}"
        
        # Standard: last two parts = registrable domain
        return f"{parts[-2]}.{parts[-1]}"
    except Exception:
        return url

def brand_in_subdomain(url: str) -> tuple[bool, str]:
    """
    Check if a known brand name appears in the SUBDOMAIN (not the registrable domain).
    This is the PayPal trick: paypal.com.evil.xyz — paypal is in the subdomain.
    Returns (is_present, brand_found)
    """
    try:
        parsed  = urllib.parse.urlparse(url)
        host    = parsed.netloc.lower().split(':')[0]
        reg_dom = get_registrable_domain(url)
        
        # Subdomain = everything before the registrable domain
        subdomain = host.replace(reg_dom, '').rstrip('.')
        
        for brand in LEGIT_BRANDS:
            if brand in subdomain:
                return True, brand
        return False, ""
    except Exception:
        return False, ""

# ── Feature extraction ─────────────────────────────────────────────────────────

def extract_features(url: str) -> list:
    """
    Extract 25 features from a URL.
    CRITICAL: The registrable domain is used for domain-level features,
    NOT the full hostname. This catches paypal.com.evil.xyz correctly.
    """
    try:
        parsed     = urllib.parse.urlparse(url)
        full_host  = parsed.netloc.lower().split(':')[0]
        reg_domain = get_registrable_domain(url)
        reg_tld    = reg_domain.split('.')[-1] if '.' in reg_domain else ''
        path       = parsed.path.lower()
        query      = parsed.query.lower()
        full_url   = url.lower()
        
        brand_subdomain, brand_found = brand_in_subdomain(url)
        
        features = [
            # --- URL length features ---
            len(url),                                                         # 1
            len(full_host),                                                   # 2
            len(path),                                                        # 3
            len(query),                                                       # 4
            
            # --- Character count features ---
            url.count('.'),                                                   # 5
            url.count('-'),                                                   # 6
            url.count('/'),                                                   # 7
            url.count('?'),                                                   # 8
            url.count('='),                                                   # 9
            url.count('@'),                                                   # 10
            len(re.findall(r'\d', url)),                                     # 11
            
            # --- Security features ---
            int(url.startswith('https')),                                    # 12
            int(bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', full_host))),   # 13: IP as host
            
            # --- REGISTRABLE DOMAIN features (critical) ---
            int(reg_tld in SUSPICIOUS_TLDS),                                 # 14: suspicious TLD
            len(reg_domain),                                                  # 15: reg domain length
            reg_domain.count('-'),                                            # 16: hyphens in reg domain
            
            # --- Brand impersonation (the key fix) ---
            int(brand_subdomain),                                             # 17: brand in subdomain
            int(any(brand in reg_domain and reg_domain != f"{brand}.com"
                    for brand in LEGIT_BRANDS)),                             # 18: brand typo in domain
            
            # --- Path/query phishing signals ---
            int(bool(re.search(
                r'(verify|confirm|secure|login|update|suspend|account'
                r'|credential|password|signin|authenticate|validate)',
                path + ' ' + query))),                                       # 19: phishing path words
            
            # --- Domain entropy (high entropy = random/generated domain) ---
            sum(-p * math.log2(p)
                for c in set(reg_domain)
                if (p := reg_domain.count(c) / len(reg_domain)) > 0)
            if reg_domain else 0,                                             # 20: domain entropy
            
            # --- URL entropy ---
            sum(-p * math.log2(p)
                for c in set(url)
                if (p := url.count(c) / len(url)) > 0)
            if url else 0,                                                    # 21: url entropy
            
            # --- Subdomain depth ---
            max(0, full_host.count('.') - reg_domain.count('.')),           # 22: subdomain levels
            
            # --- Known bad patterns ---
            int(bool(re.search(r'(security.update|account.verify|'
                               r'login.confirm|update.login|'
                               r'secure.access|verify.now)', full_url))),   # 23: combined patterns
            
            # --- Digit substitution in domain (paypa1, g00gle) ---
            int(bool(re.search(r'(paypa1|g00gle|amaz0n|micros0ft|'
                               r'app1e|faceb00k|1nstagram|tw1tter)',
                               full_url))),                                  # 24: digit substitution
            
            # --- Number of subdomains ---
            len(full_host.split('.')) - len(reg_domain.split('.')),         # 25: extra subdomain count
        ]
        
        return [float(f) for f in features]
        
    except Exception as e:
        print(f"[URLDetector] Feature extraction error: {e}")
        return [0.0] * 25


def get_feature_names() -> list:
    return [
        "url_length", "host_length", "path_length", "query_length",
        "dot_count", "hyphen_count", "slash_count", "question_count",
        "equals_count", "at_count", "digit_count",
        "is_https", "is_ip_host",
        "suspicious_tld", "reg_domain_length", "reg_domain_hyphens",
        "brand_in_subdomain", "brand_typo_in_domain",
        "phishing_path_words", "domain_entropy", "url_entropy",
        "subdomain_levels", "combined_phishing_pattern",
        "digit_substitution", "extra_subdomain_count"
    ]


# ── Heuristic fallback (used when model not loaded) ────────────────────────────

def heuristic_score(url: str) -> float:
    """
    Rule-based scoring used when LightGBM model is unavailable.
    Returns 0.0–1.0.
    """
    score = 0.0
    features = extract_features(url)
    names    = get_feature_names()
    feat     = dict(zip(names, features))
    
    if feat["is_ip_host"]:            score += 0.45
    if feat["suspicious_tld"]:        score += 0.35
    if feat["brand_in_subdomain"]:    score += 0.50   # PayPal trick
    if feat["brand_typo_in_domain"]:  score += 0.40
    if feat["digit_substitution"]:    score += 0.45
    if feat["combined_phishing_pattern"]: score += 0.30
    if feat["phishing_path_words"]:   score += 0.15
    if feat["subdomain_levels"] > 2:  score += 0.20
    if feat["extra_subdomain_count"] > 2: score += 0.15
    if feat["domain_entropy"] > 3.5:  score += 0.10
    if not feat["is_https"]:          score += 0.10
    
    return min(score, 1.0)


# ── Public interface ───────────────────────────────────────────────────────────

class URLDetector:
    def __init__(self):
        self.model = _load_lgb()

    async def analyse(self, url: str) -> dict:
        features     = extract_features(url)
        feature_names = get_feature_names()
        model        = self.model or _load_lgb()
        
        if model is not None:
            score  = float(model.predict(np.array([features]))[0])
            method = "lightgbm"
        else:
            score  = heuristic_score(url)
            method = "heuristic"
        
        # Build SHAP-style feature importance for XAI
        # Use the raw feature values as importance proxies when SHAP unavailable
        feature_importance = []
        brand_sub, brand   = brand_in_subdomain(url)
        reg_domain         = get_registrable_domain(url)
        
        # Collect the features that actually fired (non-zero signal)
        for name, val in zip(feature_names, features):
            if val > 0 and name in [
                "suspicious_tld", "brand_in_subdomain", "brand_typo_in_domain",
                "digit_substitution", "combined_phishing_pattern",
                "phishing_path_words", "is_ip_host", "subdomain_levels",
                "extra_subdomain_count"
            ]:
                feature_importance.append({
                    "feature": name.replace("_", " ").title(),
                    "value":   round(val, 3),
                    "impact":  "high" if val > 0.5 else "medium"
                })
        
        # Sort by value descending
        feature_importance.sort(key=lambda x: x["value"], reverse=True)
        
        # Build human-readable evidence
        evidence_notes = []
        if brand_sub:
            evidence_notes.append(
                f"Brand impersonation: '{brand}' appears in subdomain, "
                f"but real domain is '{reg_domain}'"
            )
        parsed_tld = reg_domain.split('.')[-1] if '.' in reg_domain else ''
        if parsed_tld in SUSPICIOUS_TLDS:
            evidence_notes.append(f"Suspicious TLD: .{parsed_tld} is commonly used in phishing")
        if re.search(r'(verify|confirm|secure|login|update|suspend)',
                     urllib.parse.urlparse(url).path.lower()):
            evidence_notes.append("Path contains credential-harvesting keywords")
        if features[feature_names.index("extra_subdomain_count")] > 1:
            levels = int(features[feature_names.index("extra_subdomain_count")])
            evidence_notes.append(f"Excessive subdomain nesting: {levels} extra levels")
        
        return {
            "score":              round(score, 4),
            "score_pct":          round(score * 100),
            "label":              "malicious" if score >= 0.5 else "clean",
            "method":             method,
            "registrable_domain": reg_domain,
            "full_host":          urllib.parse.urlparse(url).netloc,
            "feature_importance": feature_importance[:6],   # top 6 for XAI
            "evidence_notes":     evidence_notes,
            "features_raw":       dict(zip(feature_names, [round(f, 3) for f in features]))
        }

    # Keep backwards compatibility with any code calling .score() or .predict()
    async def score(self, url: str) -> dict:
        return await self.analyse(url)

    async def predict(self, url: str) -> dict:
        return await self.analyse(url)
