import os
import math
import pickle
import requests
import numpy as np
import tldextract

from urllib.parse import urlparse

# ==================================================
# External Threat Sources
# ==================================================
try:
    from virustotal_checker import check_virustotal
except:
    def check_virustotal(url):
        return "safe"

try:
    from urlhaus_checker import check_urlhaus
except:
    def check_urlhaus(url):
        return "safe"

# ==================================================
# Paths
# ==================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ML_PATH = os.path.join(BASE_DIR, "model.pkl")

# ==================================================
# Load ML Model
# ==================================================
try:
    with open(ML_PATH, "rb") as f:
        ml_model = pickle.load(f)
except:
    ml_model = None

# ==================================================
# Trusted Domains
# ==================================================
WHITELIST = [
    "facebook.com",
    "google.com",
    "github.com",
    "microsoft.com",
    "apple.com",
    "linkedin.com",
    "tripadvisor.com"
]

# ==================================================
# HTTPS Check
# ==================================================
def check_https_status(url):
    return {
        "uses_https": url.lower().startswith("https://")
    }

# ==================================================
# Blacklist Check
# ==================================================
def check_blacklist(url):
    extracted = tldextract.extract(url)
    domain = extracted.registered_domain.lower()

    suspicious_words = [
        "login", "secure", "verify", "update",
        "bank", "paypal", "account"
    ]

    for word in suspicious_words:
        if word in domain and not domain.endswith(".com"):
            return {
                "blacklisted": True,
                "matched": f"Suspicious keyword: {word}"
            }

    return {
        "blacklisted": False,
        "matched": None
    }

# ==================================================
# Redirect Check
# ==================================================
def check_redirects(url):
    result = {
        "redirect_count": 0,
        "redirect_chain": [url],
        "final_url": url,
        "suspicious": False,
        "note": ""
    }

    try:
        resp = requests.get(
            url,
            timeout=6,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0"}
        )

        chain = [r.url for r in resp.history] + [resp.url]

        result["redirect_chain"] = chain
        result["redirect_count"] = len(resp.history)
        result["final_url"] = resp.url

        if len(resp.history) > 2:
            result["suspicious"] = True
            result["note"] = "Long redirect chain"

        if resp.history:
            origin = tldextract.extract(url).registered_domain
            final = tldextract.extract(resp.url).registered_domain

            if origin != final:
                result["suspicious"] = True
                result["note"] += " | Cross-domain redirect"

    except:
        pass

    return result

# ==================================================
# Feature Engineering
# ==================================================
def url_entropy(url):
    prob = [float(url.count(c)) / len(url) for c in set(url)]
    return -sum([p * math.log2(p) for p in prob if p > 0])

def extract_features(url):
    features = []
    features.append(len(url))
    features.append(url.count("."))
    features.append(1 if "https" in url.lower() else 0)
    features.append(1 if "@" in url else 0)

    suspicious_words = ["login", "secure", "verify", "update"]
    found = any(word in url.lower() for word in suspicious_words)
    features.append(1 if found else 0)

    query = urlparse(url).query
    features.append(len(query.split("&")) if query else 0)

    extracted = tldextract.extract(url)
    features.append(len(extracted.domain))

    sub_count = len(extracted.subdomain.split(".")) if extracted.subdomain else 0
    features.append(sub_count)

    features.append(url_entropy(url))

    return np.array([features])

# ==================================================
# Main Hybrid Decision
# ==================================================
def hybrid_decision(url):

    domain_full = tldextract.extract(url).registered_domain.lower()

    https_info = check_https_status(url)
    blacklist_info = check_blacklist(url)
    redirect_info = check_redirects(url)

    # Whitelist = Safe Directly
    if domain_full in WHITELIST:
        return {
            "url": url,
            "score": 98,
            "risk_level": "Safe",
            "status_icon": "🟢",
            "details": {
                "HTTPS": {"uses_https": "Yes"},
                "Blacklist": {"blacklisted": "No", "matched": None},
                "Redirects": redirect_info
            },
            "final_verdict": "Safe"
        }

    # Force Malicious if HTTP or Blacklisted
    if not https_info["uses_https"] or blacklist_info["blacklisted"]:
        return {
            "url": url,
            "score": 35,
            "risk_level": "Malicious",
            "status_icon": "🔴",
            "details": {
                "HTTPS": {"uses_https": "Yes" if https_info["uses_https"] else "No"},
                "Blacklist": {
                    "blacklisted": "Yes" if blacklist_info["blacklisted"] else "No",
                    "matched": blacklist_info["matched"]
                },
                "Redirects": redirect_info
            },
            "final_verdict": "Malicious"
        }

    # Threat Intelligence
    vt_res = check_virustotal(url).lower()
    uh_res = check_urlhaus(url).lower()

    # ML Prediction
    ml_res = "Safe"
    if ml_model:
        try:
            feats = extract_features(url)
            pred = ml_model.predict(feats)[0]
            if pred in [1, "1", "bad", "malicious"]:
                ml_res = "Malicious"
        except:
            pass

    # Score Engine
    score = 99

    if vt_res == "malicious":
        score -= 40

    if ml_res == "Malicious":
        score -= 15

    if uh_res == "malicious":
        score -= 10

    if redirect_info["redirect_count"] > 1:
        score -= 10

    if redirect_info["suspicious"]:
        score -= 5

    if score < 0:
        score = 0

    # Final Verdict
    if score > 70:
        risk = "Safe"
        icon = "🟢"
    elif 50 <= score <= 70:
        risk = "Potential Risk"
        icon = "🟡"
    else:
        risk = "Malicious"
        icon = "🔴"

    return {
        "url": url,
        "score": score,
        "risk_level": risk,
        "status_icon": icon,
        "details": {
            "HTTPS": {"uses_https": "Yes" if https_info["uses_https"] else "No"},
            "Blacklist": {
                "blacklisted": "Yes" if blacklist_info["blacklisted"] else "No",
                "matched": blacklist_info["matched"]
            },
            "Redirects": redirect_info
        },
        "final_verdict": risk
    }