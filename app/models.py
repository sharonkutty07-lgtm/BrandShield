import datetime
from sqlalchemy import Column, Integer, String, Float, Boolean, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from .database import Base


class User(Base):
    """Application users for the BrandShield sign-in system."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    full_name = Column(String(150), nullable=False)
    email = Column(String(255), nullable=False, unique=True, index=True)
    password_hash = Column(String(255), nullable=False)
    is_verified = Column(Boolean, default=False)
    otp_code = Column(String(10), nullable=True)
    otp_expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)


class Brand(Base):
    __tablename__ = "brands"

    id = Column(Integer, primary_key=True, index=True)
    company_name = Column(String(150), nullable=False, index=True)
    official_domain = Column(String(255), nullable=False, unique=True, index=True)
    official_email = Column(String(255), nullable=True)
    industry = Column(String(100), default="General Enterprise")
    
    # Social Media Handles
    instagram_handle = Column(String(100), nullable=True)
    facebook_handle = Column(String(100), nullable=True)
    twitter_handle = Column(String(100), nullable=True)
    linkedin_handle = Column(String(100), nullable=True)
    
    # Keywords / Protected Trademarks (comma-separated)
    keywords = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    # Relationships
    lookalikes = relationship("LookalikeDomain", back_populates="brand", cascade="all, delete-orphan")
    incidents = relationship("Incident", back_populates="brand", cascade="all, delete-orphan")
    impersonations = relationship("SocialImpersonation", back_populates="brand", cascade="all, delete-orphan")
    leaks = relationship("CredentialLeak", back_populates="brand", cascade="all, delete-orphan")


class LookalikeDomain(Base):
    __tablename__ = "lookalike_domains"

    id = Column(Integer, primary_key=True, index=True)
    brand_id = Column(Integer, ForeignKey("brands.id"), nullable=False)
    domain_name = Column(String(255), nullable=False, index=True)
    variation_type = Column(String(100), default="Typosquatting") # Homoglyph, TLD Swap, Combosquatting, Typo, Prefix/Suffix
    similarity_score = Column(Float, default=0.0)
    dns_status = Column(String(50), default="UNKNOWN")            # ACTIVE, NXDOMAIN, PARKED
    ip_address = Column(String(100), nullable=True)
    risk_level = Column(String(50), default="MEDIUM")             # CRITICAL, HIGH, MEDIUM, LOW
    discovered_at = Column(DateTime, default=datetime.datetime.utcnow)

    brand = relationship("Brand", back_populates="lookalikes")


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    brand_id = Column(Integer, ForeignKey("brands.id"), nullable=False)
    title = Column(String(255), nullable=False)
    threat_url = Column(String(500), nullable=False)
    threat_type = Column(String(100), default="PHISHING_URL")     # PHISHING_URL, LOOKALIKE_DOMAIN, SOCIAL_IMPERSONATION, DATA_LEAK
    severity = Column(String(50), default="HIGH")                 # CRITICAL, HIGH, MEDIUM, LOW
    status = Column(String(50), default="OPEN")                   # OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE
    risk_score = Column(Integer, default=75)
    evidence_notes = Column(Text, nullable=True)
    registrar = Column(String(150), default="Unknown Registrar / Cloudflare")
    takedown_sent = Column(Boolean, default=False)
    takedown_letter = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    brand = relationship("Brand", back_populates="incidents")


class ScanHistory(Base):
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, index=True)
    target_url = Column(String(500), nullable=False)
    risk_score = Column(Integer, default=0)
    risk_level = Column(String(50), default="SAFE")               # CRITICAL, HIGH, MEDIUM, SAFE
    is_phishing = Column(Boolean, default=False)
    matched_brand_name = Column(String(150), nullable=True)
    diagnostic_details = Column(Text, nullable=True)              # JSON string of triggers
    scanned_at = Column(DateTime, default=datetime.datetime.utcnow)


class SocialImpersonation(Base):
    __tablename__ = "social_impersonations"

    id = Column(Integer, primary_key=True, index=True)
    brand_id = Column(Integer, ForeignKey("brands.id"), nullable=False)
    platform = Column(String(50), default="Instagram")
    suspicious_handle = Column(String(150), nullable=False)
    profile_url = Column(String(500), nullable=True)
    similarity_score = Column(Float, default=0.0)
    bio_text = Column(Text, nullable=True)
    follower_count = Column(Integer, default=0)
    risk_level = Column(String(50), default="HIGH")
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    brand = relationship("Brand", back_populates="impersonations")


class CredentialLeak(Base):
    __tablename__ = "credential_leaks"

    id = Column(Integer, primary_key=True, index=True)
    brand_id = Column(Integer, ForeignKey("brands.id"), nullable=False)
    email_exposed = Column(String(255), nullable=False)
    breach_source = Column(String(150), default="Dark Web Combo List")
    leak_date = Column(String(50), default="2026-Q1")
    data_types_exposed = Column(String(255), default="Password Hash, Username, IP")
    severity = Column(String(50), default="HIGH")
    discovered_at = Column(DateTime, default=datetime.datetime.utcnow)

    brand = relationship("Brand", back_populates="leaks")
