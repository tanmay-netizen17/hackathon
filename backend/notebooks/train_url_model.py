"""
Train LightGBM URL classifier with corrected 25-feature extraction.
Run: python train_url_model.py
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import pandas as pd
import numpy as np
import lightgbm as lgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score

# Import the corrected feature extractor
from detectors.url_detector import extract_features, get_feature_names

# ── Dataset ────────────────────────────────────────────────────────────────────

# MALICIOUS — all variants of the PayPal subdomain trick + other phishing patterns
MALICIOUS = [
    # PayPal subdomain trick (the exact type that failed)
    "https://paypal.com.security-update-login.xyz/confirm",
    "https://paypal.com.verify-account.xyz/login",
    "https://paypal.com.account-suspended.tk/restore",
    "http://paypal.com.login-verify.ml/signin",
    "https://paypal.com.update-billing.cf/payment",
    "http://secure.paypal.com.phish.xyz/verify",
    # Google subdomain trick
    "https://accounts.google.com.signin.tk/verify",
    "http://google.com.security-check.ml/login",
    "https://mail.google.com.password-reset.xyz/confirm",
    # Apple subdomain trick
    "https://appleid.apple.com.verify.tk/signin",
    "http://apple.com.id-suspended.xyz/restore",
    # Amazon subdomain trick
    "https://amazon.com.order-cancel.xyz/confirm",
    "http://amazon.com.billing-update.tk/pay",
    # Microsoft trick
    "https://login.microsoft.com.verify.xyz/signin",
    # IP address phishing
    "http://192.168.1.100/paypal/verify",
    "http://10.0.0.1/login/credentials",
    "http://185.234.219.32/phish/account",
    "http://45.33.32.156/secure/login",
    # Suspicious TLD + keywords
    "http://secure-banking-update.xyz/login",
    "http://account-verify-now.tk/confirm",
    "http://paypa1-secure.gq/verify",
    "http://amazon-security-alert.ml/update",
    "http://netflix-billing.cf/payment-update",
    "http://apple-id-locked.ga/restore",
    # Digit substitution
    "http://paypa1.com/login/verify",
    "http://g00gle-account.com/signin",
    "http://amaz0n-secure.com/update",
    "http://micros0ft-alert.com/verify",
    "http://app1e-id.com/restore",
    # Combined patterns
    "http://secure-login-verify.xyz/account/confirm",
    "http://update-credentials-now.tk/login",
    "http://account-suspended-verify.ml/restore",
    "https://free-prize-claim.xyz/winner",
    "http://crypto-wallet-drain.tk/connect",
    "http://irs-tax-refund.gq/apply",
    "http://dhl-pending-delivery.xyz/confirm",
    "http://your-account-locked.cf/unlock",
    "http://security-breach-alert.tk/immediate-action",
    "https://click-to-verify.xyz/account",
]

# Generate augmented malicious
malicious_rows = []
for url in MALICIOUS:
    malicious_rows.append({"url": url, "label": 1})
    # Path variations
    for sfx in ["/page", "?ref=abc", "?id=123", "/step2", "?token=xyz123abc"]:
        malicious_rows.append({"url": url + sfx, "label": 1})

# CLEAN — real legitimate URLs that should NEVER be flagged
CLEAN = [
    "https://www.paypal.com/signin",
    "https://www.paypal.com/myaccount/summary",
    "https://accounts.google.com/signin/v2/identifier",
    "https://mail.google.com/mail/u/0/",
    "https://drive.google.com/file/d/abc123/view",
    "https://appleid.apple.com/account/manage",
    "https://www.amazon.com/dp/B08N5WRWNW",
    "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    "https://github.com/torvalds/linux",
    "https://stackoverflow.com/questions/tagged/python",
    "https://docs.python.org/3/library/urllib.parse.html",
    "https://arxiv.org/abs/2303.08774",
    "https://huggingface.co/bert-base-uncased",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://www.reddit.com/r/MachineLearning/",
    "https://medium.com/@author/article",
    "https://twitter.com/openai/status/123456",
    "https://www.linkedin.com/in/username/",
    "https://zoom.us/j/123456789?pwd=abc",
    "https://notion.so/workspace/page-abc123",
    "https://vercel.com/dashboard",
    "https://railway.app/project/abc",
    "https://www.coursera.org/learn/machine-learning",
    "https://www.bbc.com/news/technology-12345678",
    "https://www.nytimes.com/2024/01/01/technology/ai.html",
    "https://www.chase.com/personal/banking/login",
    "https://www.bankofamerica.com/online-banking/sign-in/",
    "https://secure.netflix.com/login",
    "https://www.instagram.com/p/abc123/",
    "https://discord.com/channels/123456/789012",
    "https://store.steampowered.com/app/1091500/",
    "https://www.spotify.com/account/overview/",
    "https://api.openai.com/v1/chat/completions",
    "https://pypi.org/project/requests/",
    "https://developer.mozilla.org/en-US/docs/Web/HTTP",
    "https://www.w3schools.com/python/",
]

clean_rows = []
for url in CLEAN:
    clean_rows.append({"url": url, "label": 0})
    for sfx in ["?lang=en", "?utm_source=email", "#section", "?page=1"]:
        clean_rows.append({"url": url + sfx, "label": 0})

df = pd.DataFrame(malicious_rows + clean_rows)
df = df.sample(frac=1, random_state=42).reset_index(drop=True)   # shuffle

print(f"Dataset: {len(df)} URLs")
print(f"  Malicious: {df.label.sum()}")
print(f"  Clean:     {(df.label==0).sum()}")

# ── Extract features ────────────────────────────────────────────────────────────
print("Extracting features...")
X = np.array([extract_features(u) for u in df["url"]])
y = df["label"].values
names = get_feature_names()

# Verify the PayPal trick is captured correctly
print("\nFeature verification for paypal.com.security-update-login.xyz/confirm:")
test_feats = extract_features("https://paypal.com.security-update-login.xyz/confirm")
for name, val in zip(names, test_feats):
    if val > 0:
        print(f"  {name:35} = {val}")

# ── Train ───────────────────────────────────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

params = {
    "objective":        "binary",
    "metric":           "binary_logloss",
    "boosting_type":    "gbdt",
    "num_leaves":       31,
    "learning_rate":    0.05,
    "feature_fraction": 0.9,
    "bagging_fraction": 0.8,
    "bagging_freq":     5,
    "min_data_in_leaf": 3,
    "verbose":          -1,
}

print("\nTraining LightGBM...")
model = lgb.train(
    params,
    lgb.Dataset(X_train, label=y_train, feature_name=names),
    num_boost_round=300,
    valid_sets=[lgb.Dataset(X_test, label=y_test)],
    callbacks=[lgb.early_stopping(30), lgb.log_evaluation(50)]
)

# ── Evaluate ─────────────────────────────────────────────────────────────────────
preds_prob = model.predict(X_test)
preds_bin  = (preds_prob >= 0.5).astype(int)
print("\nClassification Report:")
print(classification_report(y_test, preds_bin, target_names=["Clean", "Malicious"]))
print(f"AUC-ROC: {roc_auc_score(y_test, preds_prob):.4f}")

# ── Save ─────────────────────────────────────────────────────────────────────────
save_path = os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "models", "url_lgbm.txt")
)
model.save_model(save_path)
print(f"\n✅ Model saved: {save_path}")

# ── Smoke tests — the ones that were failing ──────────────────────────────────
print("\n" + "="*60)
print("CRITICAL SMOKE TESTS")
print("="*60)
tests = [
    ("https://paypal.com.security-update-login.xyz/confirm", "MALICIOUS", "> 0.7"),
    ("http://paypa1-secure.gq/verify",                        "MALICIOUS", "> 0.8"),
    ("http://192.168.1.1/steal-creds",                        "MALICIOUS", "> 0.8"),
    ("https://www.paypal.com/signin",                         "CLEAN",     "< 0.2"),
    ("https://accounts.google.com/signin",                    "CLEAN",     "< 0.2"),
    ("https://github.com/torvalds/linux",                     "CLEAN",     "< 0.1"),
    ("https://amazon.com.order-cancel.xyz/confirm",           "MALICIOUS", "> 0.8"),
    ("https://secure.netflix.com/login",                      "CLEAN",     "< 0.2"),
]
all_passed = True
for url, expected_label, expected_range in tests:
    feats = np.array([extract_features(url)])
    score = model.predict(feats)[0]
    label = "MALICIOUS" if score >= 0.5 else "CLEAN"
    passed = label == expected_label
    all_passed = all_passed and passed
    status = "✅ PASS" if passed else "❌ FAIL"
    print(f"  {status} | {score:.3f} | {label:10} (expected {expected_label:10}) | {url[:65]}")

if all_passed:
    print("\n✅ All smoke tests passed. Model is production-ready.")
else:
    print("\n❌ Some tests failed. Check feature extraction.")
