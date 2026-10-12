import datetime
import socket
import ssl
from urllib.parse import urlparse
import dns.resolver
import requests
import tldextract
import whois

def trace_redirects(url: str) -> dict:
    """Traces the HTTP redirect chain to identify hidden hops and obfuscation."""
    hops = []
    final_url = url
    try:
        session = requests.Session()
        # Set a realistic browser User-Agent
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        resp = session.get(url, headers=headers, timeout=6, allow_redirects=True, verify=False)
        
        for r in resp.history:
            hops.append(r.url)
        final_url = resp.url
    except Exception:
        pass

    hop_count = len(hops)
    return {
        "hop_count": hop_count,
        "is_redirected": hop_count > 0,
        "hops": hops,
        "final_url": final_url
    }

def get_dns_and_ip(hostname: str) -> dict:
    """Resolves DNS A records and mail server (MX) entries."""
    ip_address = "Unresolved"
    has_mx = False
    
    try:
        ip_address = socket.gethostbyname(hostname)
    except Exception:
        pass

    try:
        answers = dns.resolver.resolve(hostname, "MX", lifetime=3.0)
        has_mx = len(answers) > 0
    except Exception:
        pass

    return {
        "ip_address": ip_address,
        "has_mx_record": has_mx
    }

def get_whois_profile(registered_domain: str) -> dict:
    """Extracts domain registration date, age in days, and registrar."""
    try:
        w = whois.whois(registered_domain)
        creation_date = w.creation_date
        
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            age_days = (datetime.datetime.now() - creation_date).days
            formatted_date = creation_date.strftime("%Y-%m-%d")
            return {
                "age_days": max(0, age_days),
                "registered_date": formatted_date,
                "registrar": w.registrar or "Unknown"
            }
    except Exception:
        pass

    return {
        "age_days": -1,
        "registered_date": "Unknown / Masked",
        "registrar": "Private / Masked"
    }

def inspect_ssl(hostname: str) -> dict:
    """Inspects TLS/SSL certificate, issuer, and remaining validity days."""
    context = ssl.create_default_context()
    context.timeout = 4.0

    try:
        with socket.create_connection((hostname, 443), timeout=4.0) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                # Expiration parsing
                not_after_str = cert.get("notAfter")
                expiry_date = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry_date - datetime.datetime.now()).days

                # Issuer organization
                issuer_dict = dict(x[0] for x in cert.get("issuer", []))
                issuer = issuer_dict.get("organizationName", issuer_dict.get("commonName", "Unknown Issuer"))

                return {
                    "has_ssl": True,
                    "ssl_valid": True,
                    "issuer": issuer,
                    "days_left": days_left
                }
    except ssl.SSLCertVerificationError:
        return {"has_ssl": True, "ssl_valid": False, "issuer": "Self-Signed / Untrusted", "days_left": 0}
    except Exception:
        return {"has_ssl": False, "ssl_valid": False, "issuer": "None", "days_left": 0}

def run_cyber_inspection(url: str) -> dict:
    """Executes the full forensic suite and formats data for the UI."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    ext = tldextract.extract(url)
    registered_domain = f"{ext.domain}.{ext.suffix}".lower()
    hostname = parsed.netloc.split(":")[0]

    # Run cyber telemetry
    redirect_info = trace_redirects(url)
    dns_info = get_dns_and_ip(hostname)
    whois_info = get_whois_profile(registered_domain)
    ssl_info = inspect_ssl(hostname)

    # Compile threat flag cards for the UI
    flags = []

    # Check 1: Newly Registered Domain
    if 0 <= whois_info["age_days"] < 30:
        flags.append({
            "title": "Newly Registered Domain",
            "description": f"Domain registered {whois_info['age_days']} days ago. Lacks established passive DNS history or enterprise trust.",
            "severity": "HIGH" if whois_info["age_days"] < 7 else "MEDIUM",
            "signature": f"WHOIS Age: {whois_info['age_days']}d",
            "verification": f"Zone: .{ext.suffix}",
            "icon": "📅"
        })
    elif whois_info["age_days"] == -1:
        flags.append({
            "title": "Unverifiable Domain Profile",
            "description": "WHOIS registration records are hidden, missing, or rate-limited by registry.",
            "severity": "LOW",
            "signature": "WHOIS: Masked",
            "verification": f"Zone: .{ext.suffix}",
            "icon": "📅"
        })

    # Check 2: Redirect Chain
    if redirect_info["hop_count"] >= 2:
        flags.append({
            "title": "Unsafe Redirect Chain",
            "description": f"Target routed through {redirect_info['hop_count']} unindexed redirects before landing on final destination.",
            "severity": "MEDIUM",
            "signature": f"Hop Count: {redirect_info['hop_count']} Hops",
            "verification": "Obfuscated Origin",
            "icon": "🔀"
        })

    # Check 3: SSL Certificate Anomaly
    if not ssl_info["ssl_valid"]:
        flags.append({
            "title": "SSL Certificate Anomaly",
            "description": f"Certificate verification failed or missing. Issuer identified as: {ssl_info['issuer']}.",
            "severity": "HIGH" if not ssl_info["has_ssl"] else "MEDIUM",
            "signature": f"Issuer: {ssl_info['issuer']}",
            "verification": "Security Invalid",
            "icon": "🔒"
        })

    # Check 4: Missing Mail Server (MX)
    if not dns_info["has_mx_record"]:
        flags.append({
            "title": "Missing MX Infrastructure",
            "description": "Domain has no valid mail exchange records configured, typical of disposable lure landing sites.",
            "severity": "LOW",
            "signature": "DNS: No MX",
            "verification": "Autonomous Host",
            "icon": "✉"
        })

    return {
        "resolved_hostname": hostname,
        "registered_domain": registered_domain,
        "origin_ip": dns_info["ip_address"],
        "domain_age_str": f"{whois_info['age_days']} Days (Registered {whois_info['registered_date']})" if whois_info["age_days"] >= 0 else "Masked / Private",
        "raw_age_days": whois_info["age_days"],
        "ssl_info": ssl_info,
        "redirect_info": redirect_info,
        "threat_flags": flags
    }