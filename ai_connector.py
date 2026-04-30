import requests
import tldextract
import math
import random
import re


def normalize_domain(url):
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}".lower()


WHITELIST = {
    "facebook.com",
    "github.com",
    "google.com",
    "microsoft.com",
    "apple.com",
    "linkedin.com",
    "tripadvisor.com"
}

def url_entropy(text):
    if not text:
        return 0
    prob = [text.count(c) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in prob if p > 0)


def is_suspicious_domain(domain):

    if re.search(r'\d{3,}', domain):
        return True

    if re.fullmatch(r'[a-z0-9]{10,}', domain):
        return True

    if url_entropy(domain) > 3.5:
        return True

    patterns = ["login", "secure", "verify", "bank", "update"]
    return any(p in domain for p in patterns)


def is_lookalike(domain):

    brands = ["google", "facebook", "github", "apple", "microsoft", "linkedin"]

    for b in brands:
        if b in domain and domain != b:
            return True

    return False


def is_new_domain(domain):
    return domain.endswith((".xyz", ".top", ".info", ".site", ".click"))


def check_redirects(url):

    try:
        session = requests.Session()

        resp = session.get(
            url,
            timeout=8,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0"}
        )

        return {
            "redirect_count": len(resp.history),
            "final_url": resp.url,
            "suspicious": len(resp.history) >= 1
        }

    except:
        return {
            "redirect_count": 1,
            "final_url": url,
            "suspicious": True,
            "note": "Request failed"
        }


def hybrid_decision(input_url):

    url = input_url.strip().lower()

    domain_full = normalize_domain(url)
    domain = tldextract.extract(url).domain.lower()

    redirect_info = check_redirects(url)
    redirect_count = redirect_info["redirect_count"]

    
    suspicious_domain = is_suspicious_domain(domain)
    lookalike = is_lookalike(domain)
    new_domain = is_new_domain(domain)

    
    if domain_full in WHITELIST:
        return {
            "url": url,
            "score": 95,
            "final_verdict": "Safe",
            "details": {
                "HTTPS": {"uses_https": url.startswith("https://")},
                "Blacklist": {"blacklisted": "No"},
                "Redirects": {
                    "redirect_count": 0,
                    "final_url": url,
                    "note": "Whitelisted domain - no analysis applied"
                }
            }
        }

    
    score = 100

    if not url.startswith("https://"):
        score -= 10

    if suspicious_domain:
        score -= 60

    if lookalike:
        score -= 70

    if new_domain:
        score -= 20

    if redirect_count >= 1:
        score -= 25

    if score < 0:
        score = random.randint(2, 10)

    if score > 99:
        score = 99



    if lookalike:
        verdict = "Malicious"
        score = min(score, 30)

    elif suspicious_domain:
        verdict = "Malicious"
        score = min(score, 40)

    elif redirect_count >= 1:
        verdict = "Potential Risk"
        score = max(40, min(score, 69))

    elif new_domain:
        verdict = "Potential Risk"
        score = max(40, min(score, 65))

    elif score >= 70:
        verdict = "Safe"

    elif score >= 40:
        verdict = "Potential Risk"

    else:
        verdict = "Malicious"

    
    return {
        "url": url,
        "score": score,
        "final_verdict": verdict,

        "details": {
            "HTTPS": {
                "uses_https": url.startswith("https://")
            },

            "Blacklist": {
                "blacklisted": "Yes" if (suspicious_domain or lookalike) else "No",
                "reason": (
                    "Lookalike domain" if lookalike else
                    "Suspicious pattern" if suspicious_domain else None
                )
            },

            "Redirects": {
                "redirect_count": redirect_count,
                "final_url": redirect_info["final_url"],
                "suspicious": "Yes" if redirect_count >= 1 else "No"
            }
        }
    }