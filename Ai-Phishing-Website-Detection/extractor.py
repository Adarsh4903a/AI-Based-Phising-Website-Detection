import math
import re
from urllib.parse import urlparse
import tldextract

# High-risk TLDs heavily abused by phishing kits
ABUSED_TLDS = {
    "xyz", "top", "cf", "tk", "ml", "ga", "gq", "icu", "fit", "buzz",
    "rest", "cam", "bid", "monster", "fun", "live", "club", "online"
}

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account", "banking",
    "confirm", "signin", "submit", "password", "support", "auth",
    "wallet", "token", "recovery", "alert"
]

COMMON_SAFE_SUBDOMAINS = {"www", "docs", "developer", "api", "support", "mail", "blog", "dev"}

def calculate_shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    entropy = 0.0
    for char in set(text):
        p = text.count(char) / len(text)
        entropy -= p * math.log2(p)
    return round(entropy, 4)

def extract_features(url: str) -> dict:
    raw_url = str(url).strip()
    if not raw_url.startswith(("http://", "https://")):
        raw_url = "http://" + raw_url

    parsed = urlparse(raw_url)
    ext = tldextract.extract(raw_url)

    hostname = parsed.netloc or ""
    path = parsed.path or ""

    is_ip = 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname) else 0

    subdomains = [s for s in ext.subdomain.split(".") if s]
    
    # Check if subdomain is a normal platform prefix (docs, www, api)
    subdomain_is_common = 1 if any(s in COMMON_SAFE_SUBDOMAINS for s in subdomains) else 0
    
    # Subdomain count penalty only for non-standard multi-level subdomains
    subdomain_count = len(subdomains)
    
    # Check if domain uses a high-abuse TLD
    has_abused_tld = 1 if ext.suffix.lower() in ABUSED_TLDS else 0

    url_lower = raw_url.lower()

    return {
        "url_length": len(raw_url),
        "hostname_length": len(hostname),
        "path_length": len(path),
        "count_dots": raw_url.count("."),
        "count_hyphens_domain": hostname.count("-"),  # Phishing domains abuse hyphens (e.g., paypal-secure-update)
        "count_at": raw_url.count("@"),
        "count_question": raw_url.count("?"),
        "count_equal": raw_url.count("="),
        "count_slash": raw_url.count("/"),
        "count_digits_domain": sum(c.isdigit() for c in hostname),
        "has_ip_address": is_ip,
        "is_https": 1 if parsed.scheme == "https" else 0,
        "subdomain_count": subdomain_count,
        "subdomain_is_common": subdomain_is_common,
        "has_abused_tld": has_abused_tld,
        "hostname_entropy": calculate_shannon_entropy(hostname),
        "suspicious_keyword_count": sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower),
        "has_brand_in_subdomain": 1 if any(b in ext.subdomain.lower() for b in ["paypal", "google", "apple", "microsoft", "chase"]) else 0
    }