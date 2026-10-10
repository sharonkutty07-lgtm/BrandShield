from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime
from ..database import get_db
from ..models import Brand, Incident, LookalikeDomain, SocialImpersonation, CredentialLeak

router = APIRouter(prefix="/api/reports", tags=["Executive Audit Reports"])

@router.get("/brand/{brand_id}")
def generate_brand_audit_report(brand_id: int, db: Session = Depends(get_db)):
    """
    Generates a full structured executive audit report for a brand.
    """
    brand = db.query(Brand).filter(Brand.id == brand_id).first()
    if not brand:
        raise HTTPException(status_code=404, detail="Brand not found")

    lookalikes = db.query(LookalikeDomain).filter(LookalikeDomain.brand_id == brand_id).all()
    incidents = db.query(Incident).filter(Incident.brand_id == brand_id).all()
    impersonations = db.query(SocialImpersonation).filter(SocialImpersonation.brand_id == brand_id).all()
    leaks = db.query(CredentialLeak).filter(CredentialLeak.brand_id == brand_id).all()

    active_incidents = [i for i in incidents if i.status in ["OPEN", "INVESTIGATING"]]
    critical_threats = len([l for l in lookalikes if l.risk_level == "CRITICAL"]) + len([i for i in incidents if i.severity == "CRITICAL"])

    return {
        "report_metadata": {
            "report_id": f"BS-AUDIT-{brand.id:04d}-{int(datetime.utcnow().timestamp())}",
            "generated_at": datetime.utcnow().strftime("%B %d, %Y - %H:%M:%S UTC"),
            "compliance_standard": "ISO/IEC 27001 & NIST Digital Brand Protection Framework",
            "evaluator": "BrandShield Autonomous Risk Engine"
        },
        "brand_summary": {
            "company_name": brand.company_name,
            "official_domain": brand.official_domain,
            "official_email": brand.official_email,
            "industry": brand.industry,
            "monitored_since": brand.created_at.strftime("%Y-%m-%d"),
            "social_footprint": {
                "instagram": brand.instagram_handle,
                "twitter": brand.twitter_handle,
                "facebook": brand.facebook_handle,
                "linkedin": brand.linkedin_handle
            }
        },
        "threat_landscape": {
            "overall_health_rating": "CRITICAL RISK" if critical_threats > 2 else "ELEVATED RISK" if active_incidents else "SECURE",
            "total_lookalikes_identified": len(lookalikes),
            "critical_lookalikes_count": len([l for l in lookalikes if l.risk_level == "CRITICAL"]),
            "social_impersonators_detected": len(impersonations),
            "credential_leaks_found": len(leaks),
            "active_investigations_count": len(active_incidents)
        },
        "key_incidents": [
            {
                "id": inc.id,
                "title": inc.title,
                "threat_url": inc.threat_url,
                "severity": inc.severity,
                "status": inc.status,
                "takedown_sent": inc.takedown_sent
            }
            for inc in incidents[:5]
        ],
        "top_lookalikes": [
            {
                "domain_name": l.domain_name,
                "variation_type": l.variation_type,
                "similarity_score": l.similarity_score,
                "risk_level": l.risk_level,
                "dns_status": l.dns_status
            }
            for l in sorted(lookalikes, key=lambda x: x.similarity_score, reverse=True)[:6]
        ],
        "remediation_actions": [
            "Submit abuse notifications to registrars hosting high-similarity lookalike domains.",
            "Request account takedown for spoofed support profiles on social channels.",
            "Enforce immediate credential reset for employee emails exposed in breach logs.",
            "Enable DNS CAA records and DMARC enforcement policy to prevent email spoofing."
        ]
    }
