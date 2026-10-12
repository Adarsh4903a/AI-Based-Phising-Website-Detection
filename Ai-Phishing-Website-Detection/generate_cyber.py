from reportlab.lib.pagesizes import letter
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

def build_phase2_pdf(filename="Phase_2_Cyber_Forensics_Complete_Guide.pdf"):
    doc = SimpleDocTemplate(
        filename,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    # Cybersecurity Dark Theme Color Palette
    c_primary = colors.HexColor("#0f172a")     # Slate 900
    c_accent = colors.HexColor("#0284c7")      # Sky 600
    c_dark_accent = colors.HexColor("#0369a1") # Sky 700
    c_border = colors.HexColor("#cbd5e1")      # Slate 300
    c_bg_light = colors.HexColor("#f8fafc")    # Slate 50
    c_body = colors.HexColor("#334155")        # Slate 700

    title_style = ParagraphStyle(
        'DocTitle', parent=styles['Heading1'],
        fontName='Helvetica-Bold', fontSize=17, leading=21,
        textColor=c_primary, spaceAfter=3
    )

    subtitle_style = ParagraphStyle(
        'DocSubtitle', parent=styles['Normal'],
        fontName='Helvetica', fontSize=9, leading=13,
        textColor=colors.HexColor("#64748b"), spaceAfter=10
    )

    h1_style = ParagraphStyle(
        'H1_Custom', parent=styles['Heading2'],
        fontName='Helvetica-Bold', fontSize=11.5, leading=15,
        textColor=c_dark_accent, spaceBefore=8, spaceAfter=5,
        keepWithNext=True
    )

    body_style = ParagraphStyle(
        'Body_Custom', parent=styles['Normal'],
        fontName='Helvetica', fontSize=8.5, leading=12,
        textColor=c_body, spaceAfter=5
    )

    code_style = ParagraphStyle(
        'Code_Style', parent=styles['Normal'],
        fontName='Courier', fontSize=7.2, leading=9.5,
        textColor=colors.HexColor("#0f172a"),
        backColor=colors.HexColor("#f1f5f9"),
        borderPadding=6, spaceBefore=4, spaceAfter=8
    )

    qa_title = ParagraphStyle(
        'QA_Title', parent=styles['Normal'],
        fontName='Helvetica-Bold', fontSize=9, leading=12.5,
        textColor=c_primary, spaceBefore=5, spaceAfter=2,
        keepWithNext=True
    )

    qa_body = ParagraphStyle(
        'QA_Body', parent=styles['Normal'],
        fontName='Helvetica', fontSize=8.5, leading=12,
        textColor=c_body, spaceAfter=7
    )

    story = []

    # Title & Metadata
    story.append(Paragraph("Phase 2 Engineering Specification: Active Cyber Forensics & Hybrid Scoring", title_style))
    story.append(Paragraph("Domain: Digital Forensics &bull; Modules: cyber_engine.py & threat_analyzer.py &bull; Status: Production Verified", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1, color=c_border, spaceAfter=8))

    # SECTION 1: OBJECTIVES & TOOLS
    story.append(Paragraph("1. Phase 2 Purpose & Tools Used", h1_style))
    p1_desc = (
        "While Phase 1 evaluated lexical URL features statically, Phase 2 gathers live digital forensics over the network. "
        "Attackers can construct seemingly clean URLs by registering brand-new domains or using short-lived hosting services. "
        "Phase 2 interrogates domain registration age, certificate authority validity, routing hops, and mail servers to detect "
        "infrastructure anomalies without running untrusted JavaScript locally."
    )
    story.append(Paragraph(p1_desc, body_style))

    tools_data = [
        [Paragraph("<b>Library / Module</b>", body_style), Paragraph("<b>Function & Security Purpose</b>", body_style), Paragraph("<b>Data Extracted</b>", body_style)],
        ["python-whois", "Queries global registrar registries via WHOIS protocol.", "Domain creation date, age in days, registrar name."],
        ["dnspython", "Direct asynchronous DNS protocol queries.", "Host A-record IP resolution, Mail Exchange (MX) records."],
        ["socket & ssl", "Low-level TLS/SSL handshakes over port 443.", "Certificate issuer, validity status, expiration days remaining."],
        ["requests (Session)", "Traces HTTP redirect paths safely with custom User-Agent.", "Hop count, redirection trace, final target URL landing."],
        ["tldextract", "Accurate separation of subdomains, apex domains, and TLDs.", "Standardized registered domain format for registry lookups."]
    ]
    t_tools = Table(tools_data, colWidths=[100, 240, 200])
    t_tools.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), c_bg_light),
        ('BOX', (0, 0), (-1, -1), 0.5, c_border),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, c_border),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    story.append(t_tools)
    story.append(Spacer(1, 6))

    # SECTION 2: WORKFLOW & HYBRID MATHEMATICAL AGGREGATION
    story.append(Paragraph("2. Operational Workflow & Mathematical Fusion", h1_style))
    story.append(Paragraph(
        "Phase 2 fuses the machine learning output with live network indicators through a weighted scoring mechanism: "
        "<b>Final Risk = (ML Probability &times; 0.60) + (Cyber Network Penalties &times; 0.40)</b>. "
        "Network penalties are accumulated across distinct threat vectors:", body_style
    ))

    penalties_data = [
        [Paragraph("<b>Forensic Vector</b>", body_style), Paragraph("<b>Condition</b>", body_style), Paragraph("<b>Penalty Points Added</b>", body_style), Paragraph("<b>Triggered Threat Flag</b>", body_style)],
        ["WHOIS Age", "Age &lt; 7 Days", "+30 Points (High Risk)", "Newly Registered Domain (High Severity)"],
        ["WHOIS Age", "7 Days &le; Age &lt; 30 Days", "+15 Points (Medium Risk)", "Newly Registered Domain (Medium Severity)"],
        ["SSL / TLS", "Self-Signed, Expired, or None", "+25 Points", "SSL Certificate Anomaly (High Severity)"],
        ["HTTP Hops", "Redirect Count &ge; 2 Hops", "+20 Points", "Unsafe Redirect Chain (Medium Severity)"],
        ["DNS Checks", "No MX Records Configured", "Heuristic Indicator", "Missing MX Infrastructure (Low Severity)"]
    ]
    t_penalties = Table(penalties_data, colWidths=[80, 140, 120, 200])
    t_penalties.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), c_bg_light),
        ('BOX', (0, 0), (-1, -1), 0.5, c_border),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, c_border),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    story.append(t_penalties)
    story.append(Spacer(1, 6))

    # SECTION 3: ARCHITECTURAL PIPELINE DIAGRAM
    story.append(Paragraph("3. Phase 2 Forensic Architecture Diagram", h1_style))
    diagram_ascii = (
        "+-----------------------------------------------------------------------------------------+<br/>"
        "|                                     INPUT TARGET URL                                    |<br/>"
        "+-----------------------------------------------------------------------------------------+<br/>"
        "                                             │<br/>"
        "                      +----------------------+----------------------+<br/>"
        "                      │                                             │<br/>"
        "                      ▼                                             ▼<br/>"
        "      [ PHASE 1: ML LEXICAL ENGINE ]              [ PHASE 2: LIVE CYBER ENGINE ]<br/>"
        "      - 17 Feature Extractions                    - WHOIS Domain Age Lookup<br/>"
        "      - XGBoost Predict Proba                     - TLS/SSL Socket Handshake (Port 443)<br/>"
        "      - Output: ML Score (0 - 100%)               - DNS A-Record & MX-Record Lookups<br/>"
        "                      │                           - HTTP Redirect Hop-Count Tracer<br/>"
        "                      │                                             │<br/>"
        "                      +----------------------+----------------------+<br/>"
        "                                             │<br/>"
        "                                             ▼<br/>"
        "                         [ HYBRID RISK SCORING AGGREGATOR ]<br/>"
        "                      Score = (ML_Score * 0.6) + (Penalties * 0.4)<br/>"
        "                                             │<br/>"
        "                                             ▼<br/>"
        "                         [ ASSEMBLED UI JSON CONTRACT PAYLOAD ]<br/>"
        "      - Consensus Threat Index (Gauge Score 0 - 100)<br/>"
        "      - Target Inspection Dossier (Host, Origin IP, Domain Age, Category)<br/>"
        "      - Identified Threat Flags Cards (Impersonation, Newly Registered, SSL, Hops)<br/>"
        "      - Operational SecOps Recommendation<br/>"
    )
    story.append(Paragraph(diagram_ascii, code_style))

    # Page Break for Interview Sheet
    story.append(PageBreak())

    # SECTION 4: BASIC INTERVIEW QUESTIONS
    story.append(Paragraph("4. Technical Interview Questions & Answers (Phase 2)", title_style))
    story.append(Paragraph("Core Forensics, Network Telemetry, and Hybrid Risk Aggregation", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1, color=c_border, spaceAfter=8))

    interview_qa = [
        ("Q1: What is the primary limitation of relying exclusively on Phase 1 lexical features?",
         "A: Lexical analysis inspects URL string patterns only. An attacker can register a brand-new domain with a plausible, "
         "low-entropy name (e.g., cloud-verify-support.com) and host a phishing page that exhibits clean lexical features. "
         "Without live network telemetry (like detecting that the domain was registered 3 days ago), the system is vulnerable "
         "to zero-day infrastructure."),

        ("Q2: Why is domain age such a strong indicator in phishing detection?",
         "A: Phishing campaigns use disposable infrastructure. Attackers register domains, run campaigns for hours to days, and "
         "abandon them once flagged by security scanners. Legitimate enterprise platforms maintain established domains that are years "
         "or decades old. Flagging domains under 30 days old catches the vast majority of short-lived phishing sites."),

        ("Q3: Why do we inspect DNS MX (Mail Exchange) records in a web URL scanner?",
         "A: Authentic organizations use domains for multiple business functions, including email communication. Disposable phishing "
         "landing pages are typically set up with simple DNS A-records pointing to a web host and lack mail server infrastructure. "
         "The absence of an MX record serves as an auxiliary signal of disposable, single-use infrastructure."),

        ("Q4: How does Phase 2 inspect SSL certificates without executing untrusted web code?",
         "A: We perform a direct socket-level TLS handshake on port 443 using Python's built-in ssl library. This inspects the "
         "X.509 certificate headers, issuer identity, and validity dates directly from the cryptographic handshake, avoiding headless "
         "browsers or executing untrusted HTML/JavaScript."),

        ("Q5: Why does the system trace HTTP redirects, and how do attackers abuse them?",
         "A: Attackers use open redirects, URL shorteners, or multi-hop redirect chains to bypass static link crawlers and email gateways. "
         "The initial URL may look legitimate, but redirects ultimately land on a malicious site. Tracing the redirect chain allows the "
         "system to measure hop counts and evaluate the final landing domain.")
    ]

    for q, a in interview_qa:
        item = [
            Paragraph(q, qa_title),
            Paragraph(a, qa_body)
        ]
        story.append(KeepTogether(item))

    doc.build(story)
    print(f"[+] Successfully compiled: {filename}")

if __name__ == "__main__":
    build_phase2_pdf()