import io
from datetime import datetime, timezone
from xml.sax.saxutils import escape
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from backend.app.models.entities import Incident, AIAnalysis


def _fmt(dt, default="N/A"):
    return dt.strftime('%Y-%m-%d %H:%M:%S UTC') if dt else default


def generate_incident_pdf(incident: Incident, rca: AIAnalysis) -> io.BytesIO:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontSize=18,
        textColor=colors.HexColor("#0f766e"),
        spaceAfter=6
    )
    section_style = ParagraphStyle(
        'SectionHead',
        parent=styles['Heading2'],
        fontSize=12,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=10,
        spaceAfter=4
    )
    body_style = ParagraphStyle(
        'BodyTextCustom',
        parent=styles['Normal'],
        fontSize=9,
        textColor=colors.HexColor("#334155"),
        leading=13
    )

    # Paragraph() reads its text as XML-like markup. Everything that comes from outside this function -
    # incident titles and notes typed by people, hostnames reported by agents, text written by the language
    # model - goes through text(), so "<b>" or "&" in it is printed, not interpreted (and cannot break
    # the whole report with a parse error). Only the fixed labels written below carry real markup.
    def text(value, default=""):
        return escape(str(value) if value not in (None, "") else default)

    def para(value, style=body_style, default=""):
        return Paragraph(text(value, default), style)

    story = []

    # Title & Metadata
    story.append(Paragraph("AI-ITMonitor Enterprise — Incident Post-Mortem Report", title_style))
    story.append(Paragraph(f"Generated on: {_fmt(datetime.now(timezone.utc))} | Confidential", body_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0f766e"), spaceAfter=12))

    # Incident Overview Table
    meta_data = [
        [Paragraph("<b>Incident Code:</b>", body_style), para(incident.incident_code), Paragraph("<b>Severity:</b>", body_style), para(incident.severity.value)],
        [Paragraph("<b>Target Node:</b>", body_style), para(incident.machine.hostname if incident.machine else None, default="N/A"), Paragraph("<b>Status:</b>", body_style), para(incident.status.value)],
        [Paragraph("<b>Trigger Time:</b>", body_style), para(_fmt(incident.created_at)), Paragraph("<b>Resolved Time:</b>", body_style), para(_fmt(incident.resolved_at, "Unresolved"))],
    ]
    t = Table(meta_data, colWidths=[90, 170, 90, 170])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('PADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(t)
    story.append(Spacer(1, 10))

    # Incident Description
    story.append(Paragraph("1. Incident Summary & Trigger Signature", section_style))
    story.append(para(incident.title))
    story.append(para(incident.description))
    story.append(Spacer(1, 10))

    # AI RCA Diagnostic Section
    story.append(Paragraph("2. AI Root Cause Analysis (Local LLM Diagnostic)", section_style))
    if rca:
        confidence = int((rca.confidence_score if rca.confidence_score is not None else 0) * 100)
        story.append(Paragraph(f"<b>Probable Root Cause (Confidence: {confidence}%):</b> {text(rca.probable_cause)}", body_style))
        story.append(Spacer(1, 4))
        story.append(Paragraph("<b>Observed Evidence:</b>", body_style))
        for fact in (rca.observed_facts or []):
            story.append(Paragraph(f"• {text(fact)}", body_style))
        story.append(Spacer(1, 4))
        story.append(Paragraph("<b>Recommended Remediation:</b>", body_style))
        for act in (rca.recommended_actions or []):
            story.append(Paragraph(f"- {text(act)}", body_style))
        if rca.model_name:
            story.append(Spacer(1, 4))
            story.append(Paragraph(f"<i>Produced by: {text(rca.model_name)}</i>", body_style))
    else:
        story.append(Paragraph("No automated AI analysis attached to this record.", body_style))
    story.append(Spacer(1, 10))

    # Engineering Resolution Notes
    story.append(Paragraph("3. Resolution & Corrective Action Audit Trail", section_style))
    story.append(para(incident.resolution_notes, default="Incident is currently open and undergoing remediation."))
    story.append(Spacer(1, 14))

    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cbd5e1"), spaceAfter=6))
    story.append(Paragraph("Generated automatically by AI-ITMonitor. The analysis is machine-written and has not been reviewed by a person.", ParagraphStyle('Footer', parent=styles['Italic'], fontSize=8, textColor=colors.HexColor("#64748b"))))

    doc.build(story)
    buffer.seek(0)
    return buffer
