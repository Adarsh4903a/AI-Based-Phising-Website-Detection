from reportlab.lib.pagesizes import letter
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

def build_methodology_pdf(filename="Phase_1_Methodology_Workflow_Diagram.pdf"):
    doc = SimpleDocTemplate(
        filename,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    # Corporate Theme Palette
    c_primary = colors.HexColor("#0f172a")     # Slate 900
    c_accent = colors.HexColor("#0284c7")      # Sky 600
    c_dark_accent = colors.HexColor("#0369a1") # Sky 700
    c_border = colors.HexColor("#cbd5e1")      # Slate 300
    c_bg_light = colors.HexColor("#f8fafc")    # Slate 50
    c_body = colors.HexColor("#334155")        # Slate 700

    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=18,
        leading=22,
        textColor=c_primary,
        spaceAfter=3
    )

    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#64748b"),
        spaceAfter=10
    )

    h1_style = ParagraphStyle(
        'H1_Custom',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=c_dark_accent,
        spaceBefore=10,
        spaceAfter=6,
        keepWithNext=True
    )

    h2_style = ParagraphStyle(
        'H2_Custom',
        parent=styles['Heading3'],
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=14,
        textColor=c_primary,
        spaceBefore=6,
        spaceAfter=3,
        keepWithNext=True
    )

    body_style = ParagraphStyle(
        'Body_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=12,
        textColor=c_body,
        spaceAfter=5
    )

    diagram_style = ParagraphStyle(
        'Diagram_Style',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=7.2,
        leading=9.5,
        textColor=colors.HexColor("#0f172a"),
        backColor=colors.HexColor("#f1f5f9"),
        borderPadding=6,
        spaceBefore=4,
        spaceAfter=8
    )

    story = []

    # Document Header
    story.append(Paragraph("Phase 1 Engineering Specification: AI Phishing Detection Core", title_style))
    story.append(Paragraph("Methodology &bull; Operational Workflow &bull; Architectural Pipeline Diagram", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1, color=c_border, spaceAfter=8))

    # SECTION 1: METHODOLOGY
    story.append(Paragraph("1. Engineering Methodology", h1_style))
    method_text = (
        "The Phase 1 methodology adopts an empirical, multi-tiered defensive strategy focused entirely "
        "on <b>zero-network-latency lexical inference</b>. Traditional security mechanisms rely heavily on reactive "
        "blacklists that fail to mitigate fast-flux, disposable zero-day phishing domains. Our methodology addresses this gap "
        "via a four-stage mathematical framework:"
    )
    story.append(Paragraph(method_text, body_style))

    methodology_steps = [
        ("A. Data Engineering & Distribution Balancing",
         "Ingesting heterogeneous threat feeds (OpenPhish, URLhaus) combined with authority benchmarks (Tranco Top 1M). "
         "Applied empirical synthetic and real path balancing to prevent length-confounding and false-positive bias."),
        ("B. Deterministic Cyber-Lexical Transformation",
         "Converting arbitrary string representations into a 17-dimensional quantitative space spanning Shannon entropy, "
         "homoglyph markers, direct IPv4 host indicators, domain abuse TLD heuristics, and credential lures."),
        ("C. Gradient Boosted Decision Tree Ensemble",
         "Supervised classification using Extreme Gradient Boosting (XGBoost). XGBoost handles non-linear interactions, "
         "irregular tabular distributions, and provides sub-5ms local CPU execution without requiring external accelerators."),
        ("D. Dual-Layer Hybrid Decision Boundary",
         "A deterministic Apex Authority Whitelist guards against statistical anomalies on enterprise ecosystems "
         "prior to delegating evaluation to the probabilistic tree ensemble.")
    ]

    for title, desc in methodology_steps:
        story.append(Paragraph(f"<b>{title}:</b> {desc}", body_style))

    story.append(Spacer(1, 4))

    # SECTION 2: ARCHITECTURAL PIPELINE DIAGRAM
    story.append(Paragraph("2. High-Level Architectural Pipeline Diagram", h1_style))
    
    ascii_diagram = (
        "+-----------------------------------------------------------------------------------------+<br/>"
        "|                                   TARGET URL INPUT                                      |<br/>"
        "+-----------------------------------------------------------------------------------------+<br/>"
        "                                             │<br/>"
        "                                             ▼<br/>"
        "                    [ STAGE 1: APEX DOMAIN AUTHORITY VERIFICATION ]<br/>"
        "                                             │<br/>"
        "               +-----------------------------+-----------------------------+<br/>"
        "               │ Matched High-Reputation Root?                             │ No Match / Unrated<br/>"
        "               ▼ (e.g., google.com, spring.io)                             ▼<br/>"
        "   +-------------------------+                           +-----------------------------------+<br/>"
        "   |   IMMEDIATE SAFE PASS   |                           |  STAGE 2: URL FEATURE EXTRACTION  |<br/>"
        "   | Risk: 0.01% | Latency: 0|                           |       (17 Topological Metrics)    |<br/>"
        "   +-------------------------+                           +-----------------------------------+<br/>"
        "                                                                           │<br/>"
        "         +-----------------------------------------------------------------+<br/>"
        "         ▼                                 ▼                               ▼<br/>"
        "  [ LEXICAL SIGNALS ]            [ STRUCTURAL SIGNALS ]          [ ENTROPY & HEURISTICS ]<br/>"
        "  - Length & Path Depth          - Subdomain Count               - Shannon Entropy (&gt; 4.0)<br/>"
        "  - Hyphenation in Domain        - Abused TLD List (.xyz, etc.)  - Direct IPv4 Host Check<br/>"
        "  - Credential Keyword Count     - Subdomain Identity Whitelist  - Numerical Character Ratio<br/>"
        "         │                                 │                               │<br/>"
        "         +---------------------------------+-------------------------------+<br/>"
        "                                           │<br/>"
        "                                           ▼<br/>"
        "                    +---------------------------------------------+<br/>"
        "                    |  STAGE 3: XGBOOST INFERENCE ENGINE (Ensemble)|<br/>"
        "                    |   (Trained on PhishTank + Tranco Datasets)  |<br/>"
        "                    +---------------------------------------------+<br/>"
        "                                           │<br/>"
        "                                           ▼<br/>"
        "                    +---------------------------------------------+<br/>"
        "                    |     STAGE 4: STRUCTURED VERDICT PAYLOAD     |<br/>"
        "                    |  [VERDICT] [RISK PROBABILITY] [EXPLANATION] |<br/>"
        "                    +---------------------------------------------+<br/>"
    )
    story.append(Paragraph(ascii_diagram, diagram_style))

    # SECTION 3: STEP-BY-STEP OPERATIONAL WORKFLOW
    story.append(Paragraph("3. Operational Workflow", h1_style))

    workflow_table_data = [
        [Paragraph("<b>Stage</b>", body_style), Paragraph("<b>Action / Operations Executed</b>", body_style), Paragraph("<b>Technical Artifact / Output</b>", body_style)],
        ["01. Ingestion", "Download and clean verified malicious feeds (URLhaus, OpenPhish) alongside Tranco 1M legitimate links.", "data/dataset.csv (Balanced 50/50 distribution)"],
        ["02. Parsing", "Parse input URL into protocol, subdomain, registered apex domain, TLD suffix, path, and parameters using tldextract.", "Structured URL Components"],
        ["03. Authority Check", "Cross-reference apex domain and prefix against the high-authority whitelist.", "Immediate 'SAFE (0.01%)' short-circuit if verified"],
        ["04. Feature Vector", "Extract 17 lexical attributes: character counts, keyword occurrence, IP matching, and Shannon randomness.", "1x17 Float/Int Array matching training schema"],
        ["05. Scoring", "Pass aligned vector through the trained serialized model via predict_proba().", "Calculated Risk Score (0.00% to 100.00%)"],
        ["06. Reporting", "Generate final verdict label with associated explanatory threat signals.", "Standardized Decision JSON / Terminal Output"]
    ]

    t_workflow = Table(workflow_table_data, colWidths=[65, 275, 200])
    t_workflow.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), c_bg_light),
        ('BOX', (0, 0), (-1, -1), 0.5, c_border),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, c_border),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 3.5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3.5),
    ]))
    story.append(t_workflow)
    story.append(Spacer(1, 6))

    # SECTION 4: PRODUCTION VERIFICATION MATRIX
    story.append(Paragraph("4. Production Verification & Validation Log", h1_style))
    val_data = [
        [Paragraph("<b>Evaluated Target URL</b>", body_style), Paragraph("<b>Classification</b>", body_style), Paragraph("<b>Risk Score</b>", body_style), Paragraph("<b>Operational Path</b>", body_style)],
        ["https://spring.io/projects/spring-boot", "Legitimate", "0.01%", "Stage 1: Whitelist Short-Circuit"],
        ["https://docs.oracle.com/en/java/", "Legitimate", "0.01%", "Stage 1: Whitelist Short-Circuit"],
        ["http://secure-paypal-login.update-alert.xyz/signin", "Phishing", "98.00%", "Stage 3: XGBoost (Keywords=5, AbusedTLD=1)"],
        ["http://192.168.1.100/account-verify/chase/", "Phishing", "98.18%", "Stage 3: XGBoost (Direct IP Host, Keywords=2)"],
        ["http://apple-id-verify.support-signin.cf/auth", "Phishing", "98.00%", "Stage 3: XGBoost (Keywords=4, AbusedTLD=1)"]
    ]
    t_val = Table(val_data, colWidths=[185, 75, 60, 220])
    t_val.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), c_bg_light),
        ('BOX', (0, 0), (-1, -1), 0.5, c_border),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, c_border),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    story.append(t_val)

    doc.build(story)
    print(f"[+] Successfully compiled: {filename}")

if __name__ == "__main__":
    build_methodology_pdf()