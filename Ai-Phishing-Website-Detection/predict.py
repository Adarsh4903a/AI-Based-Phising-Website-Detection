import joblib
import pandas as pd
import tldextract
from extractor import extract_features

model = joblib.load("phishing_model.pkl")
feature_names = joblib.load("feature_names.pkl")

# Top Global Apex Domains (Whitelist)
GLOBAL_TRUSTED_DOMAINS = {
    "google.com", "oracle.com", "spring.io", "github.com", "microsoft.com",
    "apple.com", "amazon.com", "wikipedia.org", "mozilla.org", "docker.com",
    "stackoverflow.com", "linkedin.com", "cloudflare.com", "apache.org"
}

def scan(url: str):
    ext = tldextract.extract(url)
    registered_domain = f"{ext.domain}.{ext.suffix}".lower()
    
    # Check 1: Cyber Layer Whitelist Check
    if registered_domain in GLOBAL_TRUSTED_DOMAINS and ext.subdomain in {"", "www", "docs", "developer", "api", "projects", "support"}:
        print(f"\nTarget URL:  {url}")
        print(f"Verdict:     [SAFE / LEGITIMATE] (Verified Authority Domain)")
        print(f"Risk Score:  0.01% (Whitelisted root: {registered_domain})")
        return

    # Check 2: Machine Learning Prediction
    features = extract_features(url)
    df = pd.DataFrame([features])[feature_names]
    
    prob = float(model.predict_proba(df)[0][1])
    is_phishing = prob >= 0.5
    
    verdict = "[MALICIOUS / PHISHING]" if is_phishing else "[SAFE / LEGITIMATE]"
    print(f"\nTarget URL:  {url}")
    print(f"Verdict:     {verdict}")
    print(f"Risk Score:  {round(prob * 100, 2)}%")
    print(f"Signals:     Keywords={features['suspicious_keyword_count']}, "
          f"AbusedTLD={features['has_abused_tld']}, "
          f"HyphensDomain={features['count_hyphens_domain']}, "
          f"Entropy={features['hostname_entropy']}")

if __name__ == "__main__":
    # Legit enterprise sites
    scan("https://spring.io/projects/spring-boot")
    scan("https://docs.oracle.com/en/java/")
    
    # Real Phishing patterns
    scan("http://secure-paypal-login.update-alert.xyz/signin")
    scan("http://192.168.1.100/account-verify/chase/")
    scan("http://apple-id-verify.support-signin.cf/auth")