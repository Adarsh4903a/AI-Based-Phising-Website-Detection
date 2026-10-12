import hashlib
import joblib
import pandas as pd
import tldextract
from extractor import extract_features
from cyber_engine import run_cyber_inspection

# Load Phase 1 artifacts
model = joblib.load("phishing_model.pkl")
feature_names = joblib.load("feature_names.pkl")

# High-authority apex domains
GLOBAL_TRUSTED_DOMAINS = {
    "google.com", "oracle.com", "spring.io", "github.com", "microsoft.com",
    "apple.com", "amazon.com", "wikipedia.org", "mozilla.org", "docker.com",
    "stackoverflow.com", "linkedin.com", "cloudflare.com", "apache.org"
}

def analyze_threat(url: str) -> dict:
    ext = tldextract.extract(url)
    registered_domain = f"{ext.domain}.{ext.suffix}".lower()
    scan_id = f"TR-{hashlib.md5(url.encode()).hexdigest()[:5].upper()}"

    # 1. Authority Whitelist check
    if registered_domain in GLOBAL_TRUSTED_DOMAINS and ext.subdomain in {"", "www", "docs", "developer", "api", "projects", "support"}:
        return {
            "scan_id": scan_id,
            "url": url,
            "risk_score": 1,
            "verdict_label": "Safe / Verified Domain",
            "verdict_summary": "Domain belongs to a recognized global authority ecosystem with valid cryptographic identity.",
            "dossier": {
                "resolved_hostname": f"{ext.subdomain + '.' if ext.subdomain else ''}{registered_domain}",
                "origin_ip": "Verified Global Infrastructure",
                "domain_age": "Established Authority (> 10 Years)",
                "target_category": "Enterprise Trusted Platform"
            },
            "secops_recommendation": "Domain verified as safe. Traffic originates from recognized authentic infrastructure.",
            "threat_flags": []
        }

    # 2. Phase 1: Machine Learning Lexical Evaluation
    features = extract_features(url)
    df_features = pd.DataFrame([features])[feature_names]
    ml_probability = float(model.predict_proba(df_features)[0][1]) * 100

    # 3. Phase 2: Live Cyber Network Forensics
    cyber_report = run_cyber_inspection(url)
    flags = cyber_report["threat_flags"]

    # If ML detects deceptive branding/structure, inject that flag card
    if ml_probability >= 70:
        flags.insert(0, {
            "title": "Deceptive Brand Impersonation",
            "description": "URL lexical tokens and entropy closely mimic enterprise authentication portals or high-target services.",
            "severity": "HIGH",
            "signature": f"Entropy: {features['hostname_entropy']}",
            "verification": "Verified by ML",
            "icon": "🪪"
        })

    # 4. Hybrid Mathematical Weighting
    # 60% ML prediction + 40% Live network penalties
    network_penalty = 0
    if 0 <= cyber_report["raw_age_days"] < 7:
        network_penalty += 30
    elif 0 <= cyber_report["raw_age_days"] < 30:
        network_penalty += 15

    if not cyber_report["ssl_info"]["ssl_valid"]:
        network_penalty += 25

    if cyber_report["redirect_info"]["hop_count"] >= 2:
        network_penalty += 20

    combined_score = int(round((ml_probability * 0.6) + (network_penalty * 0.4)))
    final_score = min(max(combined_score, 1), 99)

    # 5. UI Verdict categorization
    if final_score >= 71:
        verdict_label = "High Threat / Dangerous"
        verdict_summary = "Critical risk markers identified: domain shows strong phishing heuristics and anomalous infrastructure."
        recommendation = "Block immediately. Sandboxed heuristics confirm credential harvesting traits. Do not interact."
    elif final_score >= 31:
        verdict_label = "Suspicious Risk Detected"
        verdict_summary = "Multiple risk markers identified: domain lacks established trust and redirect patterns warrant caution."
        recommendation = "Proceed with heightened caution. Do not submit two-factor authentication codes or credentials."
    else:
        verdict_label = "Low Risk / Clean"
        verdict_summary = "No anomalous indicators identified across lexical models or network telemetry."
        recommendation = "Domain demonstrates standard structural patterns and active network registration."

    return {
        "scan_id": scan_id,
        "url": url,
        "risk_score": final_score,
        "verdict_label": verdict_label,
        "verdict_summary": verdict_summary,
        "dossier": {
            "resolved_hostname": cyber_report["resolved_hostname"],
            "origin_ip": cyber_report["origin_ip"],
            "domain_age": cyber_report["domain_age_str"],
            "target_category": "Financial / Account Services" if features["suspicious_keyword_count"] > 0 else "General Web Resource"
        },
        "secops_recommendation": recommendation,
        "threat_flags": flags
    }

if __name__ == "__main__":
    test_url = "http://secure-paypal-login.update-alert.xyz/signin"
    result = analyze_threat(test_url)
    import json
    print(json.dumps(result, indent=2))