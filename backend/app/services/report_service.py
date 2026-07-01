import io
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT


# ── Colour palette ──────────────────────────────────────────
DARK_BG     = colors.HexColor("#0f1117")
DARK_CARD   = colors.HexColor("#1a1d27")
ACCENT_BLUE = colors.HexColor("#1e90ff")
ACCENT_CYAN = colors.HexColor("#00c8c8")
TEXT_WHITE  = colors.HexColor("#f0f2f5")
TEXT_MUTED  = colors.HexColor("#8b8fa8")
DIVIDER     = colors.HexColor("#2a2d3e")


SEV_COLORS = {
    "CRITICAL": (colors.HexColor("#ff2d55"), colors.white),
    "HIGH":     (colors.HexColor("#ff6b35"), colors.white),
    "MEDIUM":   (colors.HexColor("#ffc107"), colors.HexColor("#1a1d27")),
    "LOW":      (colors.HexColor("#28a745"), colors.white),
    "INFO":     (colors.HexColor("#17a2b8"), colors.white),
}


PAGE_W, PAGE_H = A4
MARGIN = 18 * mm



def _styles():
    return {
        "title": ParagraphStyle(
            "title", fontName="Helvetica-Bold", fontSize=26,
            textColor=TEXT_WHITE, leading=32, spaceAfter=2
        ),
        "subtitle": ParagraphStyle(
            "subtitle", fontName="Helvetica", fontSize=11,
            textColor=ACCENT_CYAN, leading=16, spaceAfter=0
        ),
        "section": ParagraphStyle(
            "section", fontName="Helvetica-Bold", fontSize=13,
            textColor=ACCENT_BLUE, leading=18, spaceBefore=14, spaceAfter=6
        ),
        "label": ParagraphStyle(
            "label", fontName="Helvetica", fontSize=8,
            textColor=TEXT_MUTED, leading=12
        ),
        "value": ParagraphStyle(
            "value", fontName="Helvetica-Bold", fontSize=9,
            textColor=TEXT_WHITE, leading=13
        ),
        "body": ParagraphStyle(
            "body", fontName="Helvetica", fontSize=8.5,
            textColor=TEXT_WHITE, leading=13
        ),
        "muted": ParagraphStyle(
            "muted", fontName="Helvetica", fontSize=8,
            textColor=TEXT_MUTED, leading=12
        ),
        "code": ParagraphStyle(
            "code", fontName="Courier", fontSize=7.5,
            textColor=colors.HexColor("#a8ff78"),
            backColor=colors.HexColor("#0d1117"),
            leading=11, leftIndent=6, rightIndent=6,
            spaceBefore=3, spaceAfter=3,
            borderPad=4
        ),
        "finding_title": ParagraphStyle(
            "finding_title", fontName="Helvetica-Bold", fontSize=10,
            textColor=TEXT_WHITE, leading=14
        ),
        "footer": ParagraphStyle(
            "footer", fontName="Helvetica", fontSize=7.5,
            textColor=TEXT_MUTED, alignment=TA_CENTER
        ),
    }



def _header_table(scan, styles):
    """Dark full-width header block."""
    col_w = PAGE_W - 2 * MARGIN


    # ✅ Safe field access — works with any Scan model
    target      = getattr(scan, "target_url", None) or getattr(scan, "url", None) or getattr(scan, "target", None) or "N/A"
    domain      = getattr(scan, "domain", None) or getattr(scan, "domain_name", None) or "N/A"
    created     = getattr(scan, "created_at", None) or getattr(scan, "scan_date", None) or getattr(scan, "started_at", None)
    created_str = str(created)[:19] if created else "N/A"
    status      = getattr(scan, "status", None) or "N/A"
    score       = getattr(scan, "score", None)
    grade       = getattr(scan, "grade", None) or "?"


    left = [
        Paragraph("CyberINTEL-AI", styles["title"]),
        Paragraph("Security Assessment Report", styles["subtitle"]),
        Spacer(1, 6),
        Paragraph(f'<font color="#8b8fa8">Target  </font>{target}', styles["body"]),
        Paragraph(f'<font color="#8b8fa8">Domain  </font>{domain}', styles["body"]),
        Paragraph(f'<font color="#8b8fa8">Scanned </font>{created_str}', styles["body"]),
        Paragraph(f'<font color="#8b8fa8">Status  </font>{status}', styles["body"]),
    ]


    score_color = (
        "#ff2d55" if isinstance(score, (int, float)) and score < 50 else
        "#ff6b35" if isinstance(score, (int, float)) and score < 70 else
        "#ffc107" if isinstance(score, (int, float)) and score < 85 else
        "#28a745"
    )
    score_display = score if score is not None else "—"


    right = [
        Paragraph(
            f'<font color="{score_color}" size="36"><b>{grade}</b></font>',
            ParagraphStyle("sc", fontName="Helvetica-Bold", fontSize=36,
                           textColor=colors.HexColor(score_color),
                           alignment=TA_RIGHT, leading=40)
        ),
        Paragraph(
            f'<font color="#8b8fa8">{score_display}/100</font>',
            ParagraphStyle("sc2", fontName="Helvetica", fontSize=10,
                           textColor=TEXT_MUTED, alignment=TA_RIGHT, leading=14)
        ),
        Paragraph(
            "Security Score",
            ParagraphStyle("sc3", fontName="Helvetica", fontSize=8,
                           textColor=TEXT_MUTED, alignment=TA_RIGHT, leading=12)
        ),
    ]


    t = Table([[left, right]], colWidths=[col_w * 0.65, col_w * 0.35])
    t.setStyle(TableStyle([
        ("BACKGROUND",      (0, 0), (-1, -1), DARK_CARD),
        ("VALIGN",          (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING",     (0, 0), (-1, -1), 16),
        ("RIGHTPADDING",    (0, 0), (-1, -1), 16),
        ("TOPPADDING",      (0, 0), (-1, -1), 16),
        ("BOTTOMPADDING",   (0, 0), (-1, -1), 16),
    ]))
    return t


def _summary_table(findings, styles):
    """5-column severity summary bar."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = (f.severity or "INFO").upper()
        if sev in counts:
            counts[sev] += 1


    cells = []
    for sev, cnt in counts.items():
        bg, fg = SEV_COLORS[sev]
        cell = [
            Paragraph(str(cnt), ParagraphStyle(
                f"cnt_{sev}", fontName="Helvetica-Bold", fontSize=22,
                textColor=fg, alignment=TA_CENTER, leading=26
            )),
            Paragraph(sev, ParagraphStyle(
                f"sev_{sev}", fontName="Helvetica-Bold", fontSize=7,
                textColor=fg, alignment=TA_CENTER, leading=10
            )),
        ]
        cells.append(cell)


    col_w = (PAGE_W - 2 * MARGIN) / 5
    t = Table([cells], colWidths=[col_w] * 5)
    t.setStyle(TableStyle([
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("LINEAFTER",     (0, 0), (3, 0),   1, DIVIDER),
        ("BACKGROUND",    (0, 0), (0, 0), colors.HexColor("#ff2d5522")),
        ("BACKGROUND",    (1, 0), (1, 0), colors.HexColor("#ff6b3522")),
        ("BACKGROUND",    (2, 0), (2, 0), colors.HexColor("#ffc10722")),
        ("BACKGROUND",    (3, 0), (3, 0), colors.HexColor("#28a74522")),
        ("BACKGROUND",    (4, 0), (4, 0), colors.HexColor("#17a2b822")),
    ]))
    return t


def _finding_block(idx, finding, styles):
    """Renders one finding as a card."""
    sev = (finding.severity or "INFO").upper()
    bg_color, fg_color = SEV_COLORS.get(sev, (DARK_CARD, TEXT_WHITE))


    col_w = PAGE_W - 2 * MARGIN


    # Severity badge + title row
    badge = Table(
        [[Paragraph(sev, ParagraphStyle(
            "badge", fontName="Helvetica-Bold", fontSize=7.5,
            textColor=fg_color, alignment=TA_CENTER, leading=10
        ))]],
        colWidths=[55]
    )
    badge.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, -1), bg_color),
        ("TOPPADDING",   (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
        ("LEFTPADDING",  (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("ROUNDEDCORNERS", [4, 4, 4, 4]),
    ]))


    title_row = Table(
        [[badge, Paragraph(
            f"<b>{idx}. {finding.title or 'Unnamed Finding'}</b>",
            styles["finding_title"]
        )]],
        colWidths=[65, col_w - 65 - 32]
    )
    title_row.setStyle(TableStyle([
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING",  (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING",   (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 0),
    ]))


    # Meta info row — FIXED: use getattr for all fields to handle
    # both SQLAlchemy Finding model and Pydantic schemas safely
    check_id   = getattr(finding, "check_id", None) or getattr(finding, "vuln_id", None) or "—"
    category   = getattr(finding, "category", None) or "—"
    confidence = getattr(finding, "confidence", None) or "—"
    location   = getattr(finding, "location", None) or "—"


    meta_data = [
        [Paragraph("ID", styles["label"]),
         Paragraph("Category", styles["label"]),
         Paragraph("Confidence", styles["label"]),
         Paragraph("Location", styles["label"])],
        [Paragraph(str(check_id)[:60],   styles["value"]),
         Paragraph(str(category)[:60],   styles["value"]),
         Paragraph(str(confidence),      styles["value"]),
         Paragraph(str(location)[:60],   styles["value"])],
    ]
    meta_t = Table(meta_data, colWidths=[(col_w - 32) / 4] * 4)
    meta_t.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, -1), colors.HexColor("#12151f")),
        ("TOPPADDING",   (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
        ("LEFTPADDING",  (0, 0), (-1, -1), 8),
        ("LINEBELOW",    (0, 0), (-1, 0), 0.5, DIVIDER),
    ]))


    elements = [title_row, Spacer(1, 6), meta_t]


    # Description
    if getattr(finding, "description", None):
        elements += [
            Spacer(1, 5),
            Paragraph("<b>Description</b>", styles["muted"]),
            Paragraph(str(finding.description), styles["body"]),
        ]


    # Evidence
    if getattr(finding, "evidence", None):
        ev = str(finding.evidence)[:300]
        elements += [
            Spacer(1, 4),
            Paragraph("<b>Evidence</b>", styles["muted"]),
            Paragraph(ev, styles["code"]),
        ]


    # Remediation
    if getattr(finding, "remediation", None):
        elements += [
            Spacer(1, 4),
            Paragraph("<b>Remediation</b>", styles["muted"]),
            Paragraph(str(finding.remediation), styles["body"]),
        ]


    # Wrap in card
    card_content = [[
        Table([[e] for e in elements],
              colWidths=[col_w - 32])
    ]]
    card = Table(card_content, colWidths=[col_w])
    card.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, -1), DARK_CARD),
        ("TOPPADDING",   (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 12),
        ("LEFTPADDING",  (0, 0), (-1, -1), 16),
        ("RIGHTPADDING", (0, 0), (-1, -1), 16),
        ("LINEABOVE",    (0, 0), (-1, 0), 2, bg_color),
    ]))
    return KeepTogether([card, Spacer(1, 8)])



def _on_page(canvas, doc):
    """Dark background on every page + footer."""
    canvas.saveState()
    canvas.setFillColor(DARK_BG)
    canvas.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)


    # Footer line
    canvas.setStrokeColor(DIVIDER)
    canvas.setLineWidth(0.5)
    canvas.line(MARGIN, 14 * mm, PAGE_W - MARGIN, 14 * mm)


    # Footer text
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(TEXT_MUTED)
    canvas.drawString(MARGIN, 10 * mm, "CyberINTEL-AI Security Report  |  CONFIDENTIAL")
    page_num = f"Page {doc.page}"
    canvas.drawRightString(PAGE_W - MARGIN, 10 * mm, page_num)
    canvas.drawCentredString(PAGE_W / 2, 10 * mm,
                             datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"))
    canvas.restoreState()



def generate_pdf(scan, findings) -> io.BytesIO:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=MARGIN, bottomMargin=22 * mm,
        title="CyberINTEL-AI Security Report",
        author="CyberINTEL-AI",
    )


    S = _styles()
    story = []


    # ── Header ──────────────────────────────────────────────
    story.append(_header_table(scan, S))
    story.append(Spacer(1, 14))


    # ── Summary ─────────────────────────────────────────────
    story.append(Paragraph("Finding Summary", S["section"]))
    story.append(_summary_table(findings or [], S))
    story.append(Spacer(1, 16))


    # ── Find