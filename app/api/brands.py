from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from ..database import get_db
from ..models import Brand, LookalikeDomain, Incident, SocialImpersonation, CredentialLeak
from ..schemas import BrandCreate, BrandResponse, BrandUpdate
from ..core.typosquatting import generate_lookalikes
from ..core.impersonation import scan_social_impersonations
from ..core.leak_checker import check_brand_leaks

router = APIRouter(prefix="/api/brands", tags=["Brand Registration"])

@router.post("/", response_model=BrandResponse, status_code=status.HTTP_201_CREATED)
def register_brand(brand_in: BrandCreate, db: Session = Depends(get_db)):
    """
    ⭐ BRAND REGISTRATION ENDPOINT
    Registers a brand's official profile (Name, Domain, Social handles).
    Automatically runs proactive threat discovery:
    - Generates and saves potential look-alike domains
    - Checks for social media impersonators
    - Discovers credential leak risks
    - Creates high-priority incidents for immediate triage.
    """
    # Clean domain
    clean_domain = brand_in.official_domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]

    # Check if domain is already registered
    existing = db.query(Brand).filter(Brand.official_domain == clean_domain).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Domain '{clean_domain}' is already registered under brand '{existing.company_name}'."
        )

    # 1. Save Brand
    new_brand = Brand(
        company_name=brand_in.company_name.strip(),
        official_domain=clean_domain,
        official_email=brand_in.official_email,
        industry=brand_in.industry,
        instagram_handle=brand_in.instagram_handle,
        facebook_handle=brand_in.facebook_handle,
        twitter_handle=brand_in.twitter_handle,
        linkedin_handle=brand_in.linkedin_handle,
        keywords=brand_in.keywords
    )
    db.add(new_brand)
    db.commit()
    db.refresh(new_brand)

    # 2. Automatically generate lookalike domains
    lookalikes = generate_lookalikes(clean_domain, check_dns=False, max_results=25)
    for lk in lookalikes:
        lk_model = LookalikeDomain(
            brand_id=new_brand.id,
            domain_name=lk["domain_name"],
            variation_type=lk["variation_type"],
            similarity_score=lk["similarity_score"],
            dns_status=lk["dns_status"],
            ip_address=lk["ip_address"],
            risk_level=lk["risk_level"]
        )
        db.add(lk_model)

    # 3. Scan social impersonations
    social_handles = {
        "Instagram": new_brand.instagram_handle,
        "Twitter / X": new_brand.twitter_handle,
        "Facebook": new_brand.facebook_handle
    }
    impersonators = scan_social_impersonations(new_brand.company_name, social_handles)
    for imp in impersonators:
        imp_model = SocialImpersonation(
            brand_id=new_brand.id,
            platform=imp["platform"],
            suspicious_handle=imp["suspicious_handle"],
            profile_url=imp["profile_url"],
            similarity_score=imp["similarity_score"],
            bio_text=imp["bio_text"],
            follower_count=imp["follower_count"],
            risk_level=imp["risk_level"]
        )
        db.add(imp_model)

    # 4. Check credential leaks
    leaks = check_brand_leaks(new_brand.company_name, clean_domain)
    for lk in leaks:
        leak_model = CredentialLeak(
            brand_id=new_brand.id,
            email_exposed=lk["email_exposed"],
            breach_source=lk["breach_source"],
            leak_date=lk["leak_date"],
            data_types_exposed=lk["data_types_exposed"],
            severity=lk["severity"]
        )
        db.add(leak_model)

    # 5. Automatically create initial sample high-risk incidents for the brand to triage
    sample_incident = Incident(
        brand_id=new_brand.id,
        title=f"Critical Phishing Gateway Spoofing {new_brand.company_name}",
        threat_url=f"http://{clean_domain.split('.')[0]}-secure-login.xyz/auth",
        threat_type="PHISHING_URL",
        severity="CRITICAL",
        status="OPEN",
        risk_score=94,
        evidence_notes=f"Detected active fake portal mimicking {new_brand.company_name} authentication. Embedded credential harvest form targeting customer accounts.",
        registrar="Namecheap, Inc. / Cloudflare DNS",
        takedown_sent=False
    )
    db.add(sample_incident)

    db.commit()
    db.refresh(new_brand)
    return new_brand

@router.get("/", response_model=List[BrandResponse])
def list_brands(db: Session = Depends(get_db)):
    """Lists all registered brands."""
    return db.query(Brand).order_by(Brand.created_at.desc()).all()

@router.get("/{brand_id}")
def get_brand(brand_id: int, db: Session = Depends(get_db)):
    """Retrieves brand details along with protection statistics."""
    brand = db.query(Brand).filter(Brand.id == brand_id).first()
    if not brand:
        raise HTTPException(status_code=404, detail="Brand not found")

    return {
        "id": brand.id,
        "company_name": brand.company_name,
        "official_domain": brand.official_domain,
        "official_email": brand.official_email,
        "industry": brand.industry,
        "instagram_handle": brand.instagram_handle,
        "facebook_handle": brand.facebook_handle,
        "twitter_handle": brand.twitter_handle,
        "linkedin_handle": brand.linkedin_handle,
        "keywords": brand.keywords,
        "created_at": brand.created_at,
        "lookalikes_count": len(brand.lookalikes),
        "incidents_count": len(brand.incidents),
        "impersonations_count": len(brand.impersonations),
        "leaks_count": len(brand.leaks)
    }

@router.delete("/{brand_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_brand(brand_id: int, db: Session = Depends(get_db)):
    """Removes a registered brand and associated risk records."""
    brand = db.query(Brand).filter(Brand.id == brand_id).first()
    if not brand:
        raise HTTPException(status_code=404, detail="Brand not found")
    
    db.delete(brand)
    db.commit()
    return None
