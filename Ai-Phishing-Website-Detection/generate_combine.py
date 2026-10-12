from reportlab.lib.pagesizes import letter
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

def build_combined_pdf(filename="AI_Phishing_Detection_Phase1_Phase2_Guide.pdf"):
    doc = SimpleDocTemplate(
        filename,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

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
        fontName='Helvetica', fontSize=8.5, leading=12,
        textColor=colors.HexColor("#64748b"), spaceAfter=10
    )

    h1_style = ParagraphStyle(
        'H1_Custom', parent=styles['Heading2'],
        fontName='Helvetica-Bold', fontSize=11, leading=15,
        textColor=c_dark_accent, spaceBefore=8, spaceAfter=5,
        keepWithNext=True
    )

    body_style = ParagraphStyle(
        'Body_Custom', parent=styles['Normal'],
        fontName='Helvetica', fontSize=8, leading=11.5,
        textColor=c_body, spaceAfter=4
    )

    code_style = ParagraphStyle(
        'Code_Style', parent=styles['Normal'],
        fontName='Courier', fontSize=6.8, leading=8.8,
        textColor=colors.HexColor("#0f172a"),
        backColor=colors.HexColor("#f1f5f9"),
        borderPadding=6, spaceBefore=4, spaceAfter=6
    )

    story = []

    # Title & Metadata
    story.append(Paragraph("Unified Engineering Specification: AI & Cyber Phishing Detection", title_style))
    story.append(Paragraph("Integrated Methodology &bull; Two-Tier Workflow &bull; 4-Phase End-to-End System Architecture", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1, color=c_border, spaceAfter=8))

    # SECTION 1: COMBINED METHODOLOGY
    story.append(Paragraph("1. Combined Methodology (Phase 1 AI + Phase 2 Cyber Forensics)", h1_style))
    p1_desc = (
        "Modern phishing attacks deploy fast-flux DNS and short-lived domains that render static blacklists obsolete. "
        "Our defense uses a <b>hybrid layered methodology</b>: combining zero-network lexical feature analysis "
        "with active network-layer digital forensics to catch deceptive zero-day attacks while suppressing false alarms."
    )
    story.append(Paragraph(p1_desc, body_style))

    methodology_table = [
        [Paragraph("<b>Layer</b>", body_style), Paragraph("<b>Methodology & Principles</b>", body_style), Paragraph("<b>Key Security Mechanics</b>", body_style)],
        ["Tier 0: Authority Whitelist", "Deterministic short-circuiting to bypass statistical anomalies on verified global ecosystems.", "Root apex matching against global authorities (spring.io, oracle.com, github.com)."],
        ["Tier 1: Lexical ML Engine (Phase 1)", "Probabilistic classification of raw URL structures without network calls (< 5ms latency).", "17 topological metrics: Shannon entropy, abused TLDs (.xyz, .top), direct IPv4 hosts, keyword tokens, and XGBoost."],
        ["Tier 2: Cyber Forensics (Phase 2)", "Active digital investigation of infrastructure to evaluate domain legitimacy.", "WHOIS domain creation age, TLS/SSL socket handshake (issuer, expiry), DNS MX presence, and HTTP redirect chains."],
        ["Tier 3: Hybrid Aggregator", "Mathematical scoring combining machine learning confidence and network penalties.", "Final Risk = (ML_Prob * 0.60) + (Network_Penalties * 0.40), constrained between 1 and 99."]
    ]
    t_method = Table(methodology_table, colWidths=[110, 230, 200])
    t_method.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), c_bg_light),
        ('BOX', (0, 0), (-1, -1), 0.5, c_border),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, c_border),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    story.append(t_method)
    story.append(Spacer(1, 6))

    # SECTION 2: END-TO-END OPERATIONAL WORKFLOW
    story.append(Paragraph("2. Integrated Operational Workflow (Phase 1 to Phase 2)", h1_style))
    workflow_data = [
        [Paragraph("<b>Step</b>", body_style), Paragraph("<b>Engine Phase</b>", body_style), Paragraph("<b>Action / Execution Step</b>", body_style), Paragraph("<b>Produced Output / Telemetry</b>", body_style)],
        ["1. Intake", "Ingestion", "Receive raw URL target via API or User Dashboard.", "Sanitized URL string (with protocol scheme)"],
        ["2. Filter", "Tier 0 Check", "Extract registered apex domain and verify against trusted authority registry.", "Immediate 'SAFE (0.01%)' verdict if matched"],
        ["3. Vectorize", "Phase 1 (AI)", "Parse string into 17 numerical values (entropy, TLD abuse, character ratios).", "Aligned 1x17 Feature Matrix"],
        ["4. Predict", "Phase 1 (AI)", "Pass vector through trained serialized XGBoost model.", "ML Malicious Probability (0% - 100%)"],
        ["5. Probe", "Phase 2 (Cyber)", "Query WHOIS registry for creation timestamp and registration age.", "Domain Age in Days (flags age < 30 days)"],
        ["6. Handshake", "Phase 2 (Cyber)", "Open TLS connection on port 443; extract X.509 certificate headers.", "SSL Issuer Identity & Expiry Status"],
        ["7. Resolve", "Phase 2 (Cyber)", "Resolve DNS A-records for Host IP and check for active MX mail records.", "Origin IP and Mail Server Profile"],
        ["8. Trace", "Phase 2 (Cyber)", "Follow HTTP 301/302 redirects with custom browser User-Agent header.", "Hop Count and Final Destination URL"],
        ["9. Aggregate", "Hybrid Fusion", "Fuse ML probability (60%) with accumulated network penalties (40%).", "Consensus Threat Index (Score 0 - 100)"],
        ["10. Render", "Phase 3/4 (UI)", "Map risk score, dossier, and threat flags to the frontend SOC interface.", "Dynamic Dashboard & Threat Cards"]
    ]
    t_work = Table(workflow_data, colWidths=[55, 80, 245, 160])
    t_work.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), c_bg_light),
        ('BOX', (0, 0), (-1, -1), 0.5, c_border),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, c_border),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 2.5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2.5),
    ]))
    story.append(t_work)

    # Page Break for Architecture Diagram
    story.append(PageBreak())

    # SECTION 3: COMPLETE STRUCTURAL ARCHITECTURE DIAGRAM (ALL 4 PHASES)
    story.append(Paragraph("3. Complete Structural Architecture Diagram (All 4 Phases)", title_style))
    story.append(Paragraph("System connectivity between Frontend, Backend Gateway, Cyber Forensics, and AI Model", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1, color=c_border, spaceAfter=6))

    diagram_ascii = (
        "+-------------------------------------------------------------------------------------------------------+<br/>"
        "|                                     PHASE 4: USER INTERFACE & BROWSER CLIENT                         |<br/>"
        "|  - Threat Dashboard (HTML5 / Tailwind CSS / SVG Consensus Gauge)                                      |<br/>"
        "|  - Chrome Extension (Manifest V3 - Intercepts active tabs via chrome.webNavigation)                  |<br/>"
        "+-------------------------------------------------------------------------------------------------------+<br/>"
        "                                                    │ HTTP POST /api/v1/scan<br/>"
        "                                                    ▼<br/>"
        "+-------------------------------------------------------------------------------------------------------+<br/>"
        "|                                       PHASE 3: BACKEND API GATEWAY                                    |<br/>"
        "|  - FastAPI / Uvicorn Server (main.py) with CORS middleware                                            |<br/>"
        "|  - Task Routing, Payload Validation (Pydantic), and In-Memory / Redis Caching                         |<br/>"
        "+-------------------------------------------------------------------------------------------------------+<br/>"
        "                                                    │<br/>"
        "                         +--------------------------+--------------------------+<br/>"
        "                         │                                                     │<br/>"
        "                         ▼                                                     ▼<br/>"
        "+--------------------------------------------------+  +--------------------------------------------------+<br/>"
        "|          PHASE 1: AI / ML INFERENCE CORE         |  |         PHASE 2: LIVE CYBER FORENSICS            |<br/>"
        "|  [extractor.py & phishing_model.pkl]             |  |  [cyber_engine.py]                               |<br/>"
        "|                                                  |  |                                                  |<br/>"
        "|  1. Apex Whitelist Evaluation (spring.io, etc.)  |  |  1. WHOIS Query: Domain Age Calculation (days)   |<br/>"
        "|  2. Lexical Feature Extraction (17 Metrics):     |  |  2. TLS/SSL Handshake: Port 443 Certificate      |<br/>"
        "|     - Shannon Entropy (> 4.0 DGA detection)      |  |     - Check Issuer, Validity, Expiration         |<br/>"
        "|     - Abused TLD Detection (.xyz, .top, .cf)     |  |  3. DNS Inquiries: A-Record Host IP & MX Record|<br/>"
        "|     - Direct IPv4 Host Pattern Matching          |  |  4. HTTP Redirect Tracer: Hop-count and final URL|<br/>"
        "|     - Credential Lures (login, verify, auth)     |  |                                                  |<br/>"
        "|  3. XGBoost Decision Tree Model Evaluation       |  |  Output: Network Telemetry & Accumulated         |<br/>"
        "|                                                  |  |          Forensic Penalties                      |<br/>"
        "|  Output: ML Malicious Probability (0 - 100%)     |  |                                                  |<br/>"
        "+--------------------------------------------------+  +--------------------------------------------------+<br/>"
        "                         │                                                     │<br/>"
        "                         +--------------------------+--------------------------+<br/>"
        "                                                    │<br/>"
        "                                                    ▼<br/>"
        "+-------------------------------------------------------------------------------------------------------+<br/>"
        "|                                    HYBRID RISK SCORING AGGREGATOR                                     |<br/>"
        "|                                         [threat_analyzer.py]                                          |<br/>"
        "|                                                                                                       |<br/>"
        "|      Formula: Combined Risk = (ML_Probability * 0.60) + (Network_Penalties * 0.40)                    |<br/>"
        "|                                                                                                       |<br/>"
        "|      Synthesizes:                                                                                     |<br/>"
        "|      - Consensus Threat Score (0 - 100) & Severity Level (Safe, Suspicious, Dangerous)                |<br/>"
        "|      - Target Inspection Dossier (Resolved Host, Origin IP, Domain Age, Target Category)             |<br/>"
        "|      - Identified Threat Flags (Brand Impersonation, Newly Registered, SSL Anomaly, Redirects)       |<br/>"
        "|      - Operational SecOps Recommendation                                                             |<br/>"
        "+-------------------------------------------------------------------------------------------------------+<br/>"
        "                                                    │<br/>"
        "                                                    ▼ Returned as JSON to Client<br/>"
        "+-------------------------------------------------------------------------------------------------------+<br/>"
        "|                                        FINAL USER PRESENTATION                                        |<br/>"
        "|  Renders the interactive SVG Threat Gauge, populates the Dossier table, and displays flagged cards.   |<br/>"
        "+-------------------------------------------------------------------------------------------------------+<br/>"
    )
    story.append(Paragraph(diagram_ascii, code_style))

    doc.build(story)
    print(f"[+] Successfully generated: {filename}")

if __name__ == "__main__":
    build_combined_pdf()