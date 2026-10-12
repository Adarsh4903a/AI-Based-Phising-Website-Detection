from reportlab.lib.pagesizes import letter
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

def build_pdf(filename="Phase_1_AI_Phishing_Complete_Guide.pdf"):
    doc = SimpleDocTemplate(
        filename,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()
    
    # Professional Cybersecurity Color Palette
    primary_color = colors.HexColor("#0f172a")    # Slate 900
    accent_color = colors.HexColor("#0284c7")     # Sky 600
    accent_dark = colors.HexColor("#0369a1")      # Sky 700
    border_color = colors.HexColor("#cbd5e1")     # Slate 300
    bg_light = colors.HexColor("#f8fafc")         # Slate 50
    text_dark = colors.HexColor("#1e293b")        # Slate 800
    text_muted = colors.HexColor("#64748b")       # Slate 500

    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=18,
        leading=22,
        textColor=primary_color,
        spaceAfter=4
    )
    
    subtitle_style = ParagraphStyle(
        'DocSub',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=13,
        textColor=text_muted,
        spaceAfter=12
    )
    
    h1_style = ParagraphStyle(
        'Heading1_Custom',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=accent_dark,
        spaceBefore=10,
        spaceAfter=6,
        keepWithNext=True
    )
    
    body_style = ParagraphStyle(
        'Body_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=12,
        textColor=text_dark,
        spaceAfter=5
    )
    
    qa_title = ParagraphStyle(
        'QA_Title',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9,
        leading=12.5,
        textColor=primary_color,
        spaceBefore=5,
        spaceAfter=2,
        keepWithNext=True
    )
    
    qa_body = ParagraphStyle(
        'QA_Body',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=12,
        textColor=text_dark,
        spaceAfter=7
    )

    story = []

    # Title & Metadata
    story.append(Paragraph("AI Phishing Website Detection — Engineering & Interview Guide", title_style))
    story.append(Paragraph("Core Focus: Lexical Feature Pipeline &bull; XGBoost Ensemble &bull; 12 Technical Q&As (Basic to Advanced)", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1, color=border_color, spaceAfter=8))

    # Section 1: Executive Summary
    story.append(Paragraph("1. Phase 1 Architecture Summary", h1_style))
    p1_desc = (
        "Phase 1 delivers the core mathematical inference engine of the multi-tiered phishing detector. "
        "Operating as a zero-network lexical classifier, it processes raw URL strings into 17 distinct numerical "
        "and topological signals, feeding an Extreme Gradient Boosting (XGBoost) decision-tree ensemble. "
        "The model works alongside an Apex-Domain Authority Whitelist to guarantee near-zero latency (< 5ms) "
        "and prevent false alarms on enterprise platforms before launching subsequent forensic network sweeps."
    )
    story.append(Paragraph(p1_desc, body_style))

    # Section 2: Core Feature Engineering Matrix
    story.append(Paragraph("2. Lexical & Topological Feature Ledger (Selected)", h1_style))
    feature_data = [
        [Paragraph("<b>Feature</b>", body_style), Paragraph("<b>Type</b>", body_style), Paragraph("<b>Cybersecurity Attack Vector / Behavioral Significance</b>", body_style)],
        ["hostname_entropy", "Float", "Shannon entropy score. Identifies algorithmic generation (DGA) and obfuscated strings."],
        ["has_abused_tld", "Binary", "Detects high-abuse Top-Level Domains (.xyz, .top, .cf, .tk) preferred by cheap, disposable phishing kits."],
        ["count_hyphens_domain", "Integer", "Flags brand deception and impersonation structures (e.g., paypal-account-update.xyz)."],
        ["has_ip_address", "Binary", "Catches direct IP host access used to bypass domain name registration checks."],
        ["suspicious_keyword_count", "Integer", "Quantifies targeted credential lures (e.g., login, verify, auth, banking, secure)."],
        ["subdomain_is_common", "Binary", "Suppresses false alerts on legitimate enterprise infrastructure (e.g., docs, api, dev)."],
        ["digit_ratio", "Float", "Identifies the high numeric density characteristic of automated phishing URLs."]
    ]
    t_feat = Table(feature_data, colWidths=[125, 45, 360])
    t_feat.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), bg_light),
        ('BOX', (0, 0), (-1, -1), 0.5, border_color),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, border_color),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    story.append(t_feat)
    story.append(Spacer(1, 4))

    # Section 3: Empirical Validation Table
    story.append(Paragraph("3. Empirical Validation & Output Log", h1_style))
    val_data = [
        [Paragraph("<b>Evaluated Target URL</b>", body_style), Paragraph("<b>Type</b>", body_style), Paragraph("<b>Model Score</b>", body_style), Paragraph("<b>Verdict & Key Trigger Signals</b>", body_style)],
        ["https://spring.io/projects/spring-boot", "Legitimate", "0.01%", "SAFE (Verified Authority Domain)"],
        ["https://docs.oracle.com/en/java/", "Legitimate", "0.01%", "SAFE (Verified Authority Domain)"],
        ["http://secure-paypal-login.update-alert.xyz/signin", "Phishing", "98.00%", "MALICIOUS (Keywords=5, AbusedTLD=1, Hyphens=3)"],
        ["http://192.168.1.100/account-verify/chase/", "Phishing", "98.18%", "MALICIOUS (Direct IPv4 Host, Keywords=2)"],
        ["http://apple-id-verify.support-signin.cf/auth", "Phishing", "98.00%", "MALICIOUS (Keywords=4, AbusedTLD=1, Hyphens=3)"]
    ]
    t_val = Table(val_data, colWidths=[190, 60, 60, 220])
    t_val.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), bg_light),
        ('BOX', (0, 0), (-1, -1), 0.5, border_color),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, border_color),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    story.append(t_val)

    # Section 4: Interview Questions (Starts Page 2)
    story.append(PageBreak())
    story.append(Paragraph("4. Technical Interview Questions & Solutions", title_style))
    story.append(Paragraph("12 Questions categorized by complexity for Full-Stack, AI, and Cybersecurity roles.", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1, color=border_color, spaceAfter=8))

    interview_questions = [
        # Basic
        ("Q1 (Basic): What core problem does this project solve that traditional blacklists cannot?",
         "A: Static blacklists (e.g., Google Safe Browsing, PhishTank) depend on retroactive community reports. "
         "Modern phishing kits use automated domain generation to stay live for only 4 to 8 hours. By the time a URL is "
         "reported and indexed, the attack has succeeded. This system extracts immediate lexical indicators to detect "
         "unseen zero-day URLs in real time without prior indexing."),

        ("Q2 (Basic): What are the 4 core structural pillars of this complete system?",
         "A: (1) Frontend: A Chrome Extension / web dashboard that captures URLs and displays actionable risk scores. "
         "(2) Backend: An asynchronous API gateway (FastAPI/Spring Boot) handling rate limiting, data flows, and persistence. "
         "(3) Cyber Layer: Forensic network checkers (WHOIS age, SSL validity, DNS/MX resolution). "
         "(4) AI/ML Layer: The feature extractor and XGBoost classifier that score malicious intent from URL patterns."),

        ("Q3 (Basic): What is feature engineering in URL classification, and why is it necessary for XGBoost?",
         "A: Machine learning algorithms require fixed-length numerical vectors, not raw strings. Feature engineering "
         "parses the URL to compute meaningful indicators—such as hostname length, path depth, character entropy, "
         "hyphen counts, and suspicious keyword counts—transforming variable-length URLs into a structured numeric array."),

        ("Q4 (Basic): Why choose XGBoost over a Deep Learning architecture like LSTM or Transformer?",
         "A: (1) Latency: XGBoost executes in under 5ms on a standard CPU, vital for real-time web protection. "
         "(2) Tabular Performance: Tree-based gradient boosting consistently matches or beats deep networks on engineered "
         "tabular features. (3) Resource Cost: Transformers require large memory and GPU acceleration, making them expensive to scale."),

        # Intermediate
        ("Q5 (Intermediate): What is Shannon Entropy, and how does it detect malicious infrastructure?",
         "A: Shannon Entropy measures the statistical uncertainty/randomness of characters in a string: "
         "H(X) = -SUM(P(x) * log2(P(x))). Legitimate brand domains follow linguistic patterns with moderate entropy "
         "(2.2 to 3.2). Phishers and Domain Generation Algorithms (DGAs) generate random strings (e.g., a9f8x7-auth.xyz) "
         "with high entropy (> 4.0), making it an effective mathematical indicator of automated infrastructure."),

        ("Q6 (Intermediate): Explain the 'Path-Length False Positive' bug encountered during Phase 1 and how it was fixed.",
         "A: Problem: The initial model flagged legitimate sites (spring.io/projects/spring-boot) at 99.9% malicious probability. "
         "Root Cause: The training data paired clean bare hostnames (Tranco Top 1M root domains) with deep phishing links (/verify/auth.php). "
         "The decision trees learned that any URL containing a path was phishing. "
         "Remediation: We balanced the dataset with internal enterprise paths, separated domain-level hyphens from path hyphens, "
         "and added an apex-authority whitelist check."),

        ("Q7 (Intermediate): Why are specific TLDs (.xyz, .top, .cf) heavily flagged in this model?",
         "A: These TLDs are frequently offered for free or low cost with minimal registrar identity verification. "
         "Attackers buy them in bulk, deploy automated campaigns, and discard them once blocked. Adding an 'has_abused_tld' "
         "flag provides strong predictive signal on short-lived infrastructure."),

        ("Q8 (Intermediate): Why are lexical URL features alone insufficient to catch all phishing attacks?",
         "A: Attackers can host credential harvesting forms on trusted cloud providers (e.g., storage.googleapis.com, "
         "azurewebsites.net) or compromised WordPress sites. Lexically, these URLs appear legitimate. Detecting them "
         "requires live network forensics: checking domain age via WHOIS, verifying SSL issuers, checking DNS MX records, "
         "and scanning the page DOM structure."),

        # Advanced
        ("Q9 (Advanced): How would you integrate this Python model into an enterprise Java/Spring Boot backend?",
         "A: (1) Microservice: Expose the Python model via an asynchronous FastAPI service; the Spring Boot backend calls it "
         "via WebClient or gRPC. (2) In-Process ONNX Runtime: Export the XGBoost model to the ONNX standard (phishing_model.onnx) "
         "and run inference natively inside the JVM using Microsoft's ONNX Runtime Java API, achieving sub-millisecond latency "
         "with no cross-network overhead."),

        ("Q10 (Advanced): How could an attacker try to evade this feature extractor, and what is your defense?",
         "A: Evasion: Using URL shorteners (bit.ly), homoglyph/punycode spoofing (swapping Latin 'a' with Cyrillic 'a' -> xn--pypal-4ve.com), "
         "or open redirects. Defense: Resolve redirect chains to inspect final URLs, convert punycode to ASCII before evaluating "
         "brand distances, and treat shorteners as an intermediate state requiring recursive unrolling."),

        ("Q11 (Advanced): How do you detect and handle Concept Drift and Model Drift in production?",
         "A: Threat tactics change over time (e.g., new terminology or shifts to Web3 phishing). We address this with an automated MLOps pipeline: "
         "regularly ingest fresh feeds from OpenPhish/URLhaus, log production predictions with borderline confidence (40-60%), send them to an "
         "isolated sandbox for evaluation, and schedule periodic automated retraining and regression testing."),

        ("Q12 (Advanced): How do you design this architecture to handle millions of requests daily without bottlenecks?",
         "A: (1) Tiered Evaluation: Check an in-memory Bloom filter/Redis cache of known domains first. Run the fast lexical ML model next. "
         "Only trigger heavy network checks (WHOIS/SSL) on borderline scores. (2) Caching: Store WHOIS and DNS results in Redis with a 24-48h TTL. "
         "(3) Asynchronous Workers: Offload deep inspections to Celery/RabbitMQ background workers, returning fast preliminary verdicts to users immediately.")
    ]

    for q, a in interview_questions:
        item = [
            Paragraph(q, qa_title),
            Paragraph(a, qa_body)
        ]
        story.append(KeepTogether(item))

    doc.build(story)
    print(f"[+] Successfully generated: {filename}")

if __name__ == "__main__":
    build_pdf()