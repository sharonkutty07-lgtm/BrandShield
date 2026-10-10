from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import Brand, Incident, LookalikeDomain, SocialImpersonation, CredentialLeak, ScanHistory

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard Intelligence"])

@router.get("/summary")
def get_dashboard_summary(db: Session = Depends(get_db)):
    """
    Returns aggregated metrics and charts data for the executive risk dashboard.
    """
    brands_count = db.query(Brand).count()
    lookalikes_count = db.query(LookalikeDomain).count()
    impersonations_count = db.query(SocialImpersonation).count()
    leaks_count = db.query(CredentialLeak).count()
    scans_count = db.query(ScanHistory).count()

    incidents = db.query(Incident).all()
    total_incidents = len(incidents)
    active_incidents = len([i for i in incidents if i.status in ["OPEN", "INVESTIGATING"]])
    resolved_incidents = len([i for i in incidents if i.status == "RESOLVED"])

    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }
    threat_types = {
        "Phishing Gateways": 0,
        "Lookalike Domains": 0,
        "Social Impersonators": 0,
        "Credential Leaks": 0
    }

    total_score = 0
    for inc in incidents:
        sev = inc.severity.upper() if inc.severity else "MEDIUM"
        if sev in severity_counts:
            severity_counts[sev] += 1
        else:
            severity_counts["MEDIUM"] += 1
        total_score += inc.risk_score

    # Also factor lookalikes into severity breakdown
    critical_lookalikes = db.query(LookalikeDomain).filter(LookalikeDomain.risk_level == "CRITICAL").count()
    high_lookalikes = db.query(LookalikeDomain).filter(LookalikeDomain.risk_level == "HIGH").count()
    severity_counts["CRITICAL"] += critical_lookalikes
    severity_counts["HIGH"] += high_lookalikes

    threat_types["Phishing Gateways"] = len([i for i in incidents if i.threat_type == "PHISHING_URL"])
    threat_types["Lookalike Domains"] = lookalikes_count
    threat_types["Social Impersonators"] = impersonations_count
    threat_types["Credential Leaks"] = leaks_count

    avg_risk = round(total_score / total_incidents, 1) if total_incidents > 0 else 72.5

    # Fetch recent incidents
    recent_inc_models = db.query(Incident).order_by(Incident.created_at.desc()).limit(6).all()
    recent_incidents = []
    for inc in recent_inc_models:
        brand = db.query(Brand).filter(Brand.id == inc.brand_id).first()
        recent_incidents.append({
            "id": inc.id,
            "brand_name": brand.company_name if brand else "Brand",
            "title": inc.title,
            "threat_url": inc.threat_url,
            "threat_type": inc.threat_type,
            "severity": inc.severity,
            "status": inc.status,
            "risk_score": inc.risk_score,
            "takedown_sent": inc.takedown_sent,
            "created_at": inc.created_at.strftime("%b %d, %H:%M")
        })

    return {
        "monitored_brands_count": brands_count,
        "active_incidents_count": active_incidents,
        "total_threats_detected": lookalikes_count + impersonations_count + leaks_count + total_incidents,
        "resolved_incidents_count": resolved_incidents,
        "scans_performed": scans_count,
        "average_risk_score": avg_risk,
        "severity_breakdown": severity_counts,
        "threat_types_breakdown": threat_types,
        "recent_incidents": recent_incidents
    }
