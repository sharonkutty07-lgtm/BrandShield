import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Dict, Any
from ..database import get_db
from ..models import Brand, ScanHistory, Incident
from ..schemas import ScanRequest, ScanResponse
from ..core.url_scorer import score_url

router = APIRouter(prefix="/api/scan", tags=["Phishing URL Scanner"])

@router.post("/", response_model=ScanResponse)
def scan_target_url(payload: ScanRequest, db: Session = Depends(get_db)):
    """
    ⭐ INSTANT THREAT SCANNER
    Inspects any suspicious URL or domain against:
    - Registered brand database (checks if link impersonates a registered brand)
    - Structural anomaly detection (entropy, keywords, missing SSL, @-tricks, strange TLDs)
    - Returns explainable risk score (0-100), severity, and reasons.
    """
    target_url = payload.url.strip()
    if not target_url:
        raise HTTPException(status_code=400, detail="Target URL cannot be empty")

    # Fetch registered brands for context
    brands = db.query(Brand).all()
    brands_data = [
        {"company_name": b.company_name, "official_domain": b.official_domain}
        for b in brands
    ]

    result = score_url(target_url, registered_brands=brands_data)

    # Save to scan history
    scan_log = ScanHistory(
        target_url=result["target_url"],
        risk_score=result["risk_score"],
        risk_level=result["risk_level"],
        is_phishing=result["is_phishing"],
        matched_brand_name=result["matched_brand"],
        diagnostic_details=json.dumps(result["diagnostics"])
    )
    db.add(scan_log)
    db.commit()

    return result

@router.get("/history")
def get_recent_scans(limit: int = 15, db: Session = Depends(get_db)):
    """Retrieves recent scan records."""
    logs = db.query(ScanHistory).order_by(ScanHistory.scanned_at.desc()).limit(limit).all()
    
    items = []
    for l in logs:
        diags = []
        if l.diagnostic_details:
            try:
                diags = json.loads(l.diagnostic_details)
            except Exception:
                diags = []
        items.append({
            "id": l.id,
            "target_url": l.target_url,
            "risk_score": l.risk_score,
            "risk_level": l.risk_level,
            "is_phishing": l.is_phishing,
            "matched_brand_name": l.matched_brand_name,
            "scanned_at": l.scanned_at,
            "diagnostics_count": len(diags)
        })
    return items
