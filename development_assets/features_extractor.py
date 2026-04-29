import re
import math
import tldextract
from urllib.parse import urlparse

def extract_features(url):
    features = []
    features.append(len(url))  # طول URL
    features.append(url.count('.'))  # عدد النقاط
    features.append(int('https' in url))  # https
    suspicious_words = ['login', 'secure', 'update', 'bank', 'verify', 'account']
    features.append(int(any(word in url.lower() for word in suspicious_words)))  # كلمات مشبوهة
    features.append(int('@' in url))  # وجود @
    query = urlparse(url).query
    features.append(len(query.split('&')) if query else 0)  # عدد الباراميترز
    domain = tldextract.extract(url).domain
    features.append(len(domain))  # طول الدومين
    subdomain = tldextract.extract(url).subdomain
    features.append(len(subdomain.split('.')) if subdomain else 0)  # عدد subdomains
    features.append(url_entropy(url))  # Entropy
    return features

def url_entropy(url):
    prob = [float(url.count(c)) / len(url) for c in set(url)]
    entropy = -sum([p * math.log2(p) for p in prob if p > 0])
    return entropy