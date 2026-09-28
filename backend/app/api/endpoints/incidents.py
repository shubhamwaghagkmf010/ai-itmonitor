import uuid
from typing import List, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from backend.app.core.database import get_db
from backend.app.models.entities import (
    Incident, IncidentStatus, IncidentSeverity, MachineMetric, ProcessSnapshot, AIAnalysis, User
)
from backend.app.api.deps import get_current_user, require_permission, record_audit_event
from backend.app.ai.ollama_service import analyze_incident_with_ai
from backend.app.services.report_generator import generate_incident_pdf

router = APIRouter()


class IncidentResolveRequest(BaseModel):
    status: IncidentStatus
    resolution_notes: Optional[str] = None


@router.get("/", response_model=List[dict])
def list_incidents(
    machine_id: Optional[int] = Query(None, description="Filter incidents by machine ID"),
    db: Session = Depends(get_db), 
    current_user: User = Depends(require_permission("incidents.view"))
):
    query = db.query(Incident)
    if machine_id:
        query = query.filter(Incident.machine_id == machine_id)
        
    incidents = query.order_by(Incident.created_at.desc()).all()
    results = []
    for inc in incidents:
        results.append({
            "id": inc.id,
            "incident_code": inc.incident_code,
            "title": inc.title,
            "description": inc.description,
            "category": inc.category,
            "severity": inc.severity.value,
            "status": inc.status.value,
            "machine_id": inc.machine_id,
            "machine_hostname": inc.machine.hostname if inc.machine else "Unknown",
            "resolution_notes": inc.resolution_notes,
            "created_at": inc.created_at.isoformat(),
            "resolved_at": inc.resolved_at.isoformat() if inc.resolved_at else None,
            "has_ai_analysis": inc.ai_analysis is not None
        })
    return results


@router.post("/{incident_id}/analyze")
def trigger_ai_rca(
    incident_id: int, 
    request: Request,
    db: Session = Depends(get_db), 
    current_user: User = Depends(require_permission("incidents.analyze"))
):
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    machine = inc.machine
    latest_metric = db.query(MachineMetric).filter(
        MachineMetric.machine_id == machine.id
    ).order_by(MachineMetric.timestamp.desc()).first()

    processes = db.query(ProcessSnapshot).filter(
        ProcessSnapshot.machine_id == machine.id
    ).order_by(ProcessSnapshot.timestamp.desc()).limit(8).all()

    context = {
        "hostname": machine.hostname,
        "os_name": machine.os_name,
        "cpu_percent": latest_metric.cpu_percent if latest_metric else 0.0,
        "ram_percent": latest_metric.ram_percent if latest_metric else 0.0,
        "ram_used_gb": latest_metric.ram_used_gb if latest_metric else 0.0,
        "ram_total_gb": latest_metric.ram_total_gb if latest_metric else 0.0,
        "disk_percent": latest_metric.disk_percent if latest_metric else 0.0,
        "top_processes": [
            {"pid": p.pid, "name": p.name, "cpu_percent": p.cpu_percent, "memory_percent": p.memory_percent, "status": p.status}
            for p in processes
        ]
    }

    rca_result = analyze_incident_with_ai(context)

    existing_analysis = db.query(AIAnalysis).filter(AIAnalysis.incident_id == inc.id).first()
    if existing_analysis:
        existing_analysis.observed_facts = rca_result.get("observed_facts", [])
        existing_analysis.probable_cause = rca_result.get("probable_cause", "")
        existing_analysis.evidence = rca_result.get("evidence", [])
        existing_analysis.recommended_actions = rca_result.get("recommended_actions", [])
        existing_analysis.preventive_actions = rca_result.get("preventive_actions", [])
        existing_analysis.confidence_score = float(rca_result.get("confidence_score", 0.88))
        existing_analysis.model_name = rca_result.get("model_name", "qwen2.5:0.5b")
    else:
        new_analysis = AIAnalysis(
            incident_id=inc.id,
            observed_facts=rca_result.get("observed_facts", []),
            probable_cause=rca_result.get("probable_cause", ""),
            evidence=rca_result.get("evidence", []),
            recommended_actions=rca_result.get("recommended_actions", []),
            preventive_actions=rca_result.get("preventive_actions", []),
            confidence_score=float(rca_result.get("confidence_score", 0.88)),
            model_name=rca_result.get("model_name", "qwen2.5:0.5b")
        )
        db.add(new_analysis)

    db.commit()
    record_audit_event(
        db, 
        actor_email=current_user.email, 
        action="TRIGGER_AI_RCA", 
        target=inc.incident_code, 
        ip_address=request.client.host if request.client else None
    )
    return {"status": "AI RCA completed", "rca": rca_result}


@router.patch("/{incident_id}/status")
def update_incident_status(
    incident_id: int, 
    payload: IncidentResolveRequest,
    request: Request,
    db: Session = Depends(get_db), 
    current_user: User = Depends(require_permission("incidents.resolve"))
):
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    inc.status = payload.status
    if payload.resolution_notes:
        inc.resolution_notes = payload.resolution_notes

    if payload.status in [IncidentStatus.RESOLVED, IncidentStatus.CLOSED]:
        inc.resolved_at = datetime.now(timezone.utc)
    db.commit()

    record_audit_event(
        db,
        actor_email=current_user.email,
        action="INCIDENT_RESOLVED",
        target=inc.incident_code,
        ip_address=request.client.host if request.client else None,
        details={"status": inc.status.value, "notes": inc.resolution_notes}
    )

    return {
        "status": "updated", 
        "incident_id": inc.id, 
        "current_status": inc.status.value,
        "resolution_notes": inc.resolution_notes
    }


@router.get("/{incident_id}/export-pdf")
def export_incident_report(
    incident_id: int, 
    request: Request,
    db: Session = Depends(get_db), 
    current_user: User = Depends(require_permission("incidents.export"))
):
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    rca = db.query(AIAnalysis).filter(AIAnalysis.incident_id == inc.id).first()
    pdf_buffer = generate_incident_pdf(inc, rca)
    
    record_audit_event(
        db,
        actor_email=current_user.email,
        action="PDF_REPORT_EXPORTED",
        target=inc.incident_code,
        ip_address=request.client.host if request.client else None
    )

    filename = f"Incident_Report_{inc.incident_code}.pdf"
    return StreamingResponse(
        pdf_buffer, 
        media_type="application/pdf", 
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )
