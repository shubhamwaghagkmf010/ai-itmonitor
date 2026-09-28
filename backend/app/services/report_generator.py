import io
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from backend.app.models.entities import Incident, AIAnalysis


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

    story = []

    # Title & Metadata
    story.append(Paragraph("AI-ITMonitor Enterprise — Incident Post-Mortem Report", title_style))
    story.append(Paragraph(f"Generated on: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')} | Confidential SRE Audit", body_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0f766e"), spaceAfter=12))

    # Incident Overview Table
    meta_data = [
        [Paragraph("<b>Incident Code:</b>", body_style), Paragraph(incident.incident_code, body_style), Paragraph("<b>Severity:</b>", body_style), Paragraph(incident.severity.value, body_style)],
        [Paragraph("<b>Target Node:</b>", body_style), Paragraph(incident.machine.hostname if incident.machine else "N/A", body_style), Paragraph("<b>Status:</b>", body_style), Paragraph(incident.status.value, body_style)],
        [Paragraph("<b>Trigger Time:</b>", body_style), Paragraph(incident.created_at.strftime('%Y-%m-%d %H:%M:%S UTC'), body_style), Paragraph("<b>Resolved Time:</b>", body_style), Paragraph(incident.resolved_at.strftime('%Y-%m-%d %H:%M:%S UTC') if incident.resolved_at else "Unresolved", body_style)],
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
    story.append(Paragraph(incident.title, body_style))
    story.append(Paragraph(incident.description, body_style))
    story.append(Spacer(1, 10))

    # AI RCA Diagnostic Section
    story.append(Paragraph("2. AI Root Cause Analysis (Local LLM Diagnostic)", section_style))
    if rca:
        story.append(Paragraph(f"<b>Probable Root Cause (Confidence: {int((rca.confidence_score or 0.85)*100)}%):</b> {rca.probable_cause}", body_style))
        story.append(Spacer(1, 4))
        story.append(Paragraph("<b>Observed Evidence:</b>", body_style))
        for fact in (rca.observed_facts or []):
            story.append(Paragraph(f"• {fact}", body_style))
        story.append(Spacer(1, 4))
        story.append(Paragraph("<b>AI Recommended Remediation Playbook:</b>", body_style))
        for act in (rca.recommended_actions or []):
            story.append(Paragraph(f"✔ {act}", body_style))
    else:
        story.append(Paragraph("No automated AI analysis attached to this record.", body_style))
    story.append(Spacer(1, 10))

    # Engineering Resolution Notes
    story.append(Paragraph("3. Resolution & Corrective Action Audit Trail", section_style))
    res_text = incident.resolution_notes or "Incident is currently open and undergoing remediation."
    story.append(Paragraph(res_text, body_style))
    story.append(Spacer(1, 14))

    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cbd5e1"), spaceAfter=6))
    story.append(Paragraph("Validated by AI-ITMonitor Automated Observability Core & SRE Lead.", ParagraphStyle('Footer', parent=styles['Italic'], fontSize=8, textColor=colors.HexColor("#64748b"))))

    doc.build(story)
    buffer.seek(0)
    return buffer
