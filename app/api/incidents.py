from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime
from ..database import get_db
from ..models import Incident, Brand
from ..schemas import IncidentResponse, IncidentCreate, IncidentStatusUpdate, TakedownRequest, TakedownLetterResponse
from ..core.takedown_generator import generate_takedown_notice

router = APIRouter(prefix="/api/incidents", tags=["Incident & Takedown Workflow"])

@router.get("/")
def list_incidents(
    brand_id: Optional[int] = None,
    status_filter: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Lists all security incidents with brand context."""
    query = db.query(Incident)
    if brand_id:
        query = query.filter(Incident.brand_id == brand_id)
    if status_filter and status_filter.upper() != "ALL":
        query = query.filter(Incident.status == status_filter.upper())

    incidents = query.order_by(Incident.created_at.desc()).all()
    
    result = []
    for inc in incidents:
        brand = db.query(Brand).filter(Brand.id == inc.brand_id).first()
        result.append({
            "id": inc.id,
            "brand_id": inc.brand_id,
            "brand_name": brand.company_name if brand else "Unknown Brand",
            "title": inc.title,
            "threat_url": inc.threat_url,
            "threat_type": inc.threat_type,
            "severity": inc.severity,
            "status": inc.status,
            "risk_score": inc.risk_score,
            "evidence_notes": inc.evidence_notes,
            "registrar": inc.registrar,
            "takedown_sent": inc.takedown_sent,
            "takedown_letter": inc.takedown_letter,
            "created_at": inc.created_at,
            "updated_at": inc.updated_at
        })
    return result

@router.post("/", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
def create_incident(inc_in: IncidentCreate, db: Session = Depends(get_db)):
    """Manually creates a new security incident."""
    brand = db.query(Brand).filter(Brand.id == inc_in.brand_id).first()
    if not brand:
        raise HTTPException(status_code=404, detail="Brand not found")

    incident = Incident(
        brand_id=inc_in.brand_id,
        title=inc_in.title,
        threat_url=inc_in.threat_url,
        threat_type=inc_in.threat_type,
        severity=inc_in.severity,
        status=inc_in.status,
        risk_score=inc_in.risk_score,
        evidence_notes=inc_in.evidence_notes,
        registrar=inc_in.registrar
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)
    return incident

@router.patch("/{incident_id}/status")
def update_incident_status(incident_id: int, payload: IncidentStatusUpdate, db: Session = Depends(get_db)):
    """Transitions an incident between OPEN -> INVESTIGATING -> RESOLVED -> FALSE_POSITIVE."""
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    valid_statuses = ["OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"]
    new_status = payload.status.upper()
    if new_status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {valid_statuses}")

    inc.status = new_status
    if payload.notes:
        inc.evidence_notes = f"{inc.evidence_notes or ''}\n[{datetime.utcnow().strftime('%Y-%m-%d %H:%M')}] Status update to {new_status}: {payload.notes}"
    
    inc.updated_at = datetime.utcnow()
    db.commit()
    return {"message": f"Incident #{incident_id} updated to {new_status}", "status": new_status}

@router.post("/{incident_id}/takedown", response_model=TakedownLetterResponse)
def generate_and_issue_takedown(
    incident_id: int,
    req: TakedownRequest,
    db: Session = Depends(get_db)
):
    """
    ⭐ 1-CLICK TAKEDOWN NOTICE GENERATOR
    Generates a formal DMCA / abuse takedown notice letter formatted for the hosting provider / registrar
    and marks the incident status as takedown initiated.
    """
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    brand = db.query(Brand).filter(Brand.id == inc.brand_id).first()
    brand_name = brand.company_name if brand else "Protected Brand"
    official_domain = brand.official_domain if brand else "official.com"

    notice = generate_takedown_notice(
        brand_name=brand_name,
        official_domain=official_domain,
        threat_url=inc.threat_url,
        threat_type=inc.threat_type,
        registrar=inc.registrar or "Cloudflare DNS / Hosting Provider",
        sender_name=req.sender_name or f"{brand_name} Brand Security Operations",
        sender_email=req.sender_email or brand.official_email or "abuse-response@brandshield.security",
        custom_notes=req.custom_notes or inc.evidence_notes
    )

    # Update incident state
    inc.takedown_sent = True
    inc.takedown_letter = notice["letter_body"]
    if inc.status == "OPEN":
        inc.status = "INVESTIGATING"
    inc.updated_at = datetime.utcnow()
    db.commit()

    return {
        "incident_id": inc.id,
        "recipient_email": notice["recipient_email"],
        "subject": notice["subject"],
        "letter_body": notice["letter_body"],
        "generated_at": notice["generated_at"]
    }
