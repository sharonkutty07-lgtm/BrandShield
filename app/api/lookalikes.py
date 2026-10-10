from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional
from ..database import get_db
from ..models import LookalikeDomain, Brand, Incident
from ..schemas import LookalikeResponse, LookalikeGenerateRequest
from ..core.typosquatting import generate_lookalikes

router = APIRouter(prefix="/api/lookalikes", tags=["Lookalike Hunter"])

@router.get("/", response_model=List[LookalikeResponse])
def get_lookalikes(brand_id: Optional[int] = None, db: Session = Depends(get_db)):
    """Retrieves all detected look-alike domains."""
    query = db.query(LookalikeDomain)
    if brand_id:
        query = query.filter(LookalikeDomain.brand_id == brand_id)
    return query.order_by(LookalikeDomain.similarity_score.desc()).all()

@router.post("/generate")
def generate_domain_variants(req: LookalikeGenerateRequest, db: Session = Depends(get_db)):
    """Generates on-the-fly look-alike permutations for any domain."""
    clean_domain = req.domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
    variants = generate_lookalikes(clean_domain, check_dns=req.check_dns, max_results=req.limit or 30)
    return {
        "original_domain": clean_domain,
        "total_generated": len(variants),
        "variants": variants
    }

@router.post("/{lookalike_id}/escalate")
def escalate_to_incident(lookalike_id: int, db: Session = Depends(get_db)):
    """Escalates a detected suspicious look-alike domain to an Active Incident for takedown."""
    lk = db.query(LookalikeDomain).filter(LookalikeDomain.id == lookalike_id).first()
    if not lk:
        raise HTTPException(status_code=404, detail="Lookalike domain not found")

    brand = db.query(Brand).filter(Brand.id == lk.brand_id).first()
    brand_name = brand.company_name if brand else "Monitored Brand"

    # Check if incident already exists
    existing = db.query(Incident).filter(Incident.threat_url.like(f"%{lk.domain_name}%")).first()
    if existing:
        return {"message": "Incident already exists for this domain", "incident_id": existing.id}

    incident = Incident(
        brand_id=lk.brand_id,
        title=f"Suspicious Lookalike Domain Active: {lk.domain_name}",
        threat_url=f"https://{lk.domain_name}",
        threat_type="LOOKALIKE_DOMAIN",
        severity="HIGH" if lk.similarity_score > 80 else "MEDIUM",
        status="OPEN",
        risk_score=int(lk.similarity_score),
        evidence_notes=f"Detected {lk.variation_type} variation of official brand domain ({brand.official_domain if brand else 'N/A'}). Similarity score: {lk.similarity_score}%. IP: {lk.ip_address or 'Pending DNS resolution'}",
        registrar="Public DNS / Hosting Provider"
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)

    return {"message": "Lookalike domain escalated to active incident", "incident_id": incident.id}
