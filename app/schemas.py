from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, HttpUrl

# ============================
# Brand Schemas
# ============================
class BrandBase(BaseModel):
    company_name: str
    official_domain: str
    official_email: Optional[str] = None
    industry: Optional[str] = "General Enterprise"
    instagram_handle: Optional[str] = None
    facebook_handle: Optional[str] = None
    twitter_handle: Optional[str] = None
    linkedin_handle: Optional[str] = None
    keywords: Optional[str] = None

class BrandCreate(BrandBase):
    pass

class BrandUpdate(BaseModel):
    company_name: Optional[str] = None
    official_domain: Optional[str] = None
    official_email: Optional[str] = None
    industry: Optional[str] = None
    instagram_handle: Optional[str] = None
    facebook_handle: Optional[str] = None
    twitter_handle: Optional[str] = None
    linkedin_handle: Optional[str] = None
    keywords: Optional[str] = None

class BrandResponse(BrandBase):
    id: int
    created_at: datetime

    class Config:
        from_attributes = True

# ============================
# Lookalike Schemas
# ============================
class LookalikeResponse(BaseModel):
    id: int
    brand_id: int
    domain_name: str
    variation_type: str
    similarity_score: float
    dns_status: str
    ip_address: Optional[str] = None
    risk_level: str
    discovered_at: datetime

    class Config:
        from_attributes = True

class LookalikeGenerateRequest(BaseModel):
    domain: str
    limit: Optional[int] = 30
    check_dns: Optional[bool] = False

# ============================
# Incident Schemas
# ============================
class IncidentBase(BaseModel):
    brand_id: int
    title: str
    threat_url: str
    threat_type: str = "PHISHING_URL"
    severity: str = "HIGH"
    status: str = "OPEN"
    risk_score: int = 75
    evidence_notes: Optional[str] = None
    registrar: Optional[str] = "Unknown Registrar / Host"

class IncidentCreate(IncidentBase):
    pass

class IncidentStatusUpdate(BaseModel):
    status: str
    notes: Optional[str] = None

class IncidentResponse(IncidentBase):
    id: int
    takedown_sent: bool
    takedown_letter: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    brand_name: Optional[str] = None

    class Config:
        from_attributes = True

# ============================
# Scanner Schemas
# ============================
class ScanRequest(BaseModel):
    url: str

class DiagnosticItem(BaseModel):
    category: str
    indicator: str
    risk_impact: int
    status: str   # DANGER, WARNING, SAFE

class ScanResponse(BaseModel):
    target_url: str
    risk_score: int
    risk_level: str
    is_phishing: bool
    verdict: str
    matched_brand: Optional[str] = None
    domain: str
    ip_address: Optional[str] = None
    domain_age_days: Optional[int] = None
    diagnostics: List[DiagnosticItem]
    recommendations: List[str]

# ============================
# Social Impersonation Schemas
# ============================
class ImpersonationResponse(BaseModel):
    id: int
    brand_id: int
    platform: str
    suspicious_handle: str
    profile_url: Optional[str] = None
    similarity_score: float
    bio_text: Optional[str] = None
    follower_count: int
    risk_level: str
    created_at: datetime

    class Config:
        from_attributes = True

# ============================
# Credential Leak Schemas
# ============================
class LeakResponse(BaseModel):
    id: int
    brand_id: int
    email_exposed: str
    breach_source: str
    leak_date: str
    data_types_exposed: str
    severity: str
    discovered_at: datetime

    class Config:
        from_attributes = True

# ============================
# Dashboard & Takedown Schemas
# ============================
class DashboardSummary(BaseModel):
    monitored_brands_count: int
    active_incidents_count: int
    total_threats_detected: int
    resolved_incidents_count: int
    average_risk_score: float
    severity_breakdown: Dict[str, int]
    threat_types_breakdown: Dict[str, int]
    recent_incidents: List[IncidentResponse]
    recent_scans: List[Any]

class TakedownRequest(BaseModel):
    incident_id: int
    sender_name: Optional[str] = "Brand Protection Team"
    sender_email: Optional[str] = "abuse-response@brandshield.security"
    custom_notes: Optional[str] = None

class TakedownLetterResponse(BaseModel):
    incident_id: int
    recipient_email: str
    subject: str
    letter_body: str
    generated_at: str
