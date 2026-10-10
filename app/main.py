import os
from pathlib import Path

# Load environment variables from .env file
_env_path = Path(__file__).resolve().parent.parent / ".env"
if _env_path.exists():
    try:
        from dotenv import load_dotenv
        load_dotenv(dotenv_path=_env_path, override=True)
    except ImportError:
        with open(_env_path, "r", encoding="utf-8") as _f:
            for _line in _f:
                _line = _line.strip()
                if _line and not _line.startswith("#") and "=" in _line:
                    _k, _v = _line.split("=", 1)
                    _k, _v = _k.strip(), _v.strip().strip('"').strip("'")
                    if _k and _k not in os.environ:
                        os.environ[_k] = _v

import inspect
import hmac
import hashlib
import secrets
from datetime import datetime, timedelta
from urllib.parse import quote
from fastapi import FastAPI, Request, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from starlette.middleware.sessions import SessionMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.orm import Session

from .database import engine, Base, SessionLocal
from .models import User, Brand, LookalikeDomain, Incident, SocialImpersonation, CredentialLeak, ScanHistory
from .core.email_service import generate_otp, send_otp_email
from .api import brands, lookalikes, scan, incidents, impersonation, leaks, dashboard, reports
from .core.typosquatting import generate_lookalikes
from .core.impersonation import scan_social_impersonations
from .core.leak_checker import check_brand_leaks

# Initialize Base Directory Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")

os.makedirs(STATIC_DIR, exist_ok=True)
os.makedirs(TEMPLATES_DIR, exist_ok=True)

# Create database tables
Base.metadata.create_all(bind=engine)

def _ensure_user_columns():
    """Ensure is_verified, otp_code, and otp_expires_at exist in SQLite users table."""
    try:
        with engine.begin() as conn:
            res = conn.execute(text("PRAGMA table_info(users)"))
            cols = [row[1] for row in res.fetchall()]
            if "is_verified" not in cols:
                conn.execute(text("ALTER TABLE users ADD COLUMN is_verified BOOLEAN DEFAULT 0"))
            if "otp_code" not in cols:
                conn.execute(text("ALTER TABLE users ADD COLUMN otp_code VARCHAR(10)"))
            if "otp_expires_at" not in cols:
                conn.execute(text("ALTER TABLE users ADD COLUMN otp_expires_at DATETIME"))
    except Exception as e:
        print(f"[*] Note on table migration: {e}")

_ensure_user_columns()

app = FastAPI(
    title="BrandShield - Digital Risk Protection Platform",
    description="Enterprise brand impersonation detection, look-alike hunter, phishing scanner, and automated takedown system.",
    version="1.0.0"
)

# Enable CORS for open development
app.add_middleware(
    SessionMiddleware,
    secret_key=os.environ.get("BRANDSHIELD_SESSION_SECRET", "local-demo-secret-change-before-deployment"),
    same_site="lax",
    https_only=False,  # Set True when deployed behind HTTPS.
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount Static Files and Templates
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
templates = Jinja2Templates(directory=TEMPLATES_DIR)

# Include API Routers
app.include_router(brands.router)
app.include_router(lookalikes.router)
app.include_router(scan.router)
app.include_router(incidents.router)
app.include_router(impersonation.router)
app.include_router(leaks.router)
app.include_router(dashboard.router)
app.include_router(reports.router)


def _hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 310_000)
    return f"pbkdf2_sha256$310000${salt.hex()}${derived.hex()}"


def _verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, rounds, salt_hex, expected_hex = stored.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(rounds)).hex()
        return hmac.compare_digest(actual, expected_hex)
    except (ValueError, TypeError):
        return False


def seed_demo_data():
    """Seeds realistic brand data, threats, and demo user for seamless evaluation."""
    db: Session = SessionLocal()
    try:
        # Seed default demo user if absent
        if db.query(User).count() == 0:
            demo_user = User(
                full_name="Chief Information Security Officer",
                email="admin@brandshield.io",
                password_hash=_hash_password("admin1234"),
                is_verified=True
            )
            db.add(demo_user)
            db.commit()
            print("[+] Seeded default security analyst user: admin@brandshield.io / admin1234")

        if db.query(Brand).count() == 0:
            print("[+] Initializing BrandShield with initial brand assets...")

            # 1. Seed Brand: ABC Bank
            abc_bank = Brand(
                company_name="ABC Bank",
                official_domain="abcbank.com",
                official_email="security@abcbank.com",
                industry="Banking & Financial Services",
                instagram_handle="abcbank_official",
                facebook_handle="abcbank",
                twitter_handle="abcbank_care",
                linkedin_handle="abc-bank-global",
                keywords="netbanking, login, kyc, secure, loans, credit card, otp"
            )
            db.add(abc_bank)
            db.commit()
            db.refresh(abc_bank)

            # Generate ABC Bank Lookalikes
            abc_lookalikes = generate_lookalikes("abcbank.com", check_dns=False, max_results=20)
            for lk in abc_lookalikes:
                db.add(LookalikeDomain(
                    brand_id=abc_bank.id,
                    domain_name=lk["domain_name"],
                    variation_type=lk["variation_type"],
                    similarity_score=lk["similarity_score"],
                    dns_status=lk["dns_status"],
                    ip_address=lk["ip_address"],
                    risk_level=lk["risk_level"]
                ))

            # Impersonations
            abc_socials = scan_social_impersonations("ABC Bank", {
                "Instagram": "abcbank_official",
                "Twitter / X": "abcbank_care",
                "Facebook": "abcbank"
            })
            for imp in abc_socials:
                db.add(SocialImpersonation(
                    brand_id=abc_bank.id,
                    platform=imp["platform"],
                    suspicious_handle=imp["suspicious_handle"],
                    profile_url=imp["profile_url"],
                    similarity_score=imp["similarity_score"],
                    bio_text=imp["bio_text"],
                    follower_count=imp["follower_count"],
                    risk_level=imp["risk_level"]
                ))

            # Credential Leaks
            abc_leaks = check_brand_leaks("ABC Bank", "abcbank.com")
            for lk in abc_leaks:
                db.add(CredentialLeak(
                    brand_id=abc_bank.id,
                    email_exposed=lk["email_exposed"],
                    breach_source=lk["breach_source"],
                    leak_date=lk["leak_date"],
                    data_types_exposed=lk["data_types_exposed"],
                    severity=lk["severity"]
                ))

            # Sample Incidents for ABC Bank
            inc1 = Incident(
                brand_id=abc_bank.id,
                title="Critical Phishing Site Mimicking ABC NetBanking Portal",
                threat_url="http://abcbank-secure-netbanking.top/login.php",
                threat_type="PHISHING_URL",
                severity="CRITICAL",
                status="OPEN",
                risk_score=96,
                evidence_notes="Live credential harvest portal imitating ABC Bank login screen. Targets customer NetBanking passwords and OTP tokens.",
                registrar="Namecheap / Cloudflare DNS",
                takedown_sent=False
            )
            inc2 = Incident(
                brand_id=abc_bank.id,
                title="Combosquatted Domain Registered: abcbank-kyc-update.xyz",
                threat_url="http://abcbank-kyc-update.xyz",
                threat_type="LOOKALIKE_DOMAIN",
                severity="HIGH",
                status="INVESTIGATING",
                risk_score=88,
                evidence_notes="Active DNS A-Record resolved to Russian bulletproof hosting ASN. SMS spam messages detected redirecting here.",
                registrar="Hostinger International",
                takedown_sent=True,
                takedown_letter="Formal Notice Sent to abuse@hostinger.com"
            )
            db.add_all([inc1, inc2])

            # 2. Seed Brand: Kampus
            kampus = Brand(
                company_name="Kampus",
                official_domain="kampus.vc",
                official_email="contact@kampus.vc",
                industry="Venture Capital & Innovation",
                instagram_handle="kampus_vc",
                facebook_handle="kampusvc",
                twitter_handle="kampus_vc",
                linkedin_handle="kampus-vc",
                keywords="founders, venture, hackathon, investment, pitch"
            )
            db.add(kampus)
            db.commit()
            db.refresh(kampus)

            # Generate Kampus Lookalikes
            k_lookalikes = generate_lookalikes("kampus.vc", check_dns=False, max_results=15)
            for lk in k_lookalikes:
                db.add(LookalikeDomain(
                    brand_id=kampus.id,
                    domain_name=lk["domain_name"],
                    variation_type=lk["variation_type"],
                    similarity_score=lk["similarity_score"],
                    dns_status=lk["dns_status"],
                    ip_address=lk["ip_address"],
                    risk_level=lk["risk_level"]
                ))

            # Kampus Incident
            inc3 = Incident(
                brand_id=kampus.id,
                title="Fake Grant Application Form Spoofing Kampus.vc",
                threat_url="https://kampus-apply-grant.online",
                threat_type="PHISHING_URL",
                severity="HIGH",
                status="OPEN",
                risk_score=82,
                evidence_notes="Phishing form collecting founder identity documents and passport scans under false pretense of Kampus funding.",
                registrar="GoDaddy.com LLC",
                takedown_sent=False
            )
            db.add(inc3)

            # Sample Scan history
            db.add(ScanHistory(
                target_url="http://abcbank-secure-netbanking.top/login.php",
                risk_score=96,
                risk_level="CRITICAL",
                is_phishing=True,
                matched_brand_name="ABC Bank",
                diagnostic_details='[{"category": "Protocol", "indicator": "Unencrypted HTTP", "risk_impact": 20, "status": "DANGER"}]'
            ))
            db.add(ScanHistory(
                target_url="https://google.com",
                risk_score=5,
                risk_level="SAFE",
                is_phishing=False,
                matched_brand_name=None,
                diagnostic_details='[{"category": "Protocol", "indicator": "Valid HTTPS", "risk_impact": 0, "status": "SAFE"}]'
            ))

            db.commit()
            print("[+] Initial brand data seeded successfully.")
    except Exception as e:
        print(f"Error seeding data: {e}")
    finally:
        db.close()

@app.on_event("startup")
def on_startup():
    seed_demo_data()

def _template_response(request: Request, name: str, context: dict | None = None):
    """Support both old and new Starlette Jinja template signatures."""
    context = context or {}
    parameters = inspect.signature(templates.TemplateResponse).parameters
    if "request" in parameters:
        return templates.TemplateResponse(request=request, name=name, context=context)
    return templates.TemplateResponse(name, {"request": request, **context})


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, message: str = ""):
    if request.session.get("user_id"):
        return RedirectResponse(url="/", status_code=303)
    return _template_response(request, "login.html", {"message": message})


@app.post("/login")
def login_submit(request: Request, email: str = Form(""), password: str = Form("")):
    db = SessionLocal()
    try:
        email = (email or "").strip().lower()
        if not email or not password:
            return RedirectResponse(url="/login?message=" + quote("Please enter both email and password."), status_code=303)
        user = db.query(User).filter(User.email == email).first()
        if not user or not _verify_password(password, user.password_hash):
            return RedirectResponse(url="/login?message=" + quote("Email or password is incorrect."), status_code=303)
        
        # Check if user email is verified
        if not user.is_verified:
            otp = generate_otp(6)
            user.otp_code = otp
            user.otp_expires_at = datetime.utcnow() + timedelta(minutes=10)
            db.commit()
            send_otp_email(user.email, otp, user.full_name)
            return RedirectResponse(
                url=f"/verify-otp?email={quote(user.email)}&error=" + quote("Your account is not verified yet. A 6-digit OTP has been sent to your email."),
                status_code=303
            )

        request.session.clear()
        request.session["user_id"] = user.id
        request.session["user_name"] = user.full_name
        request.session["user_email"] = user.email
        request.session["is_verified"] = True
        return RedirectResponse(url="/", status_code=303)
    finally:
        db.close()


@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request, message: str = ""):
    if request.session.get("user_id"):
        return RedirectResponse(url="/", status_code=303)
    return _template_response(request, "register.html", {"message": message})


@app.post("/register")
def register_submit(
    request: Request,
    full_name: str = Form(""),
    email: str = Form(""),
    password: str = Form(""),
    confirm_password: str = Form(""),
):
    full_name = (full_name or "").strip()
    email = (email or "").strip().lower()
    if not full_name or len(full_name) > 150:
        return RedirectResponse(url="/register?message=" + quote("Please enter a valid name."), status_code=303)
    if not email or "@" not in email or len(email) > 255:
        return RedirectResponse(url="/register?message=" + quote("Please enter a valid email address."), status_code=303)
    if not password or len(password) < 8:
        return RedirectResponse(url="/register?message=" + quote("Password must be at least 8 characters."), status_code=303)
    if password != confirm_password:
        return RedirectResponse(url="/register?message=" + quote("Passwords do not match."), status_code=303)
    
    db = SessionLocal()
    try:
        existing_user = db.query(User).filter(User.email == email).first()
        if existing_user:
            if existing_user.is_verified:
                return RedirectResponse(url="/login?message=" + quote("An account with this email already exists and is verified. Please log in."), status_code=303)
            else:
                # User registered before but did not verify OTP
                otp = generate_otp(6)
                existing_user.full_name = full_name
                existing_user.password_hash = _hash_password(password)
                existing_user.otp_code = otp
                existing_user.otp_expires_at = datetime.utcnow() + timedelta(minutes=10)
                db.commit()
                send_otp_email(existing_user.email, otp, existing_user.full_name)
                return RedirectResponse(
                    url=f"/verify-otp?email={quote(existing_user.email)}&message=" + quote("Account pending verification. A fresh verification OTP has been sent."),
                    status_code=303
                )

        # Create new unverified user
        otp = generate_otp(6)
        user = User(
            full_name=full_name,
            email=email,
            password_hash=_hash_password(password),
            is_verified=False,
            otp_code=otp,
            otp_expires_at=datetime.utcnow() + timedelta(minutes=10)
        )
        db.add(user)
        db.commit()
        db.refresh(user)

        send_otp_email(user.email, otp, user.full_name)
        return RedirectResponse(
            url=f"/verify-otp?email={quote(user.email)}",
            status_code=303
        )
    finally:
        db.close()


@app.get("/verify-otp", response_class=HTMLResponse)
def verify_otp_page(request: Request, email: str = "", message: str = "", error: str = ""):
    if request.session.get("user_id"):
        return RedirectResponse(url="/", status_code=303)
    if not email:
        return RedirectResponse(url="/login", status_code=303)

    email = email.strip().lower()
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            return RedirectResponse(url="/register?message=" + quote("Account not found. Please create an account."), status_code=303)
        if user.is_verified:
            return RedirectResponse(url="/login?message=" + quote("Your account is already verified! Please sign in."), status_code=303)

        smtp_configured = bool(os.environ.get("SMTP_USER", "").strip() and os.environ.get("SMTP_PASSWORD", "").strip())
        dev_otp = user.otp_code if not smtp_configured else None

        return _template_response(request, "verify_otp.html", {
            "email": email,
            "dev_otp": dev_otp,
            "success": message,
            "error": error
        })
    finally:
        db.close()


@app.post("/verify-otp")
def verify_otp_submit(request: Request, email: str = Form(""), otp: str = Form("")):
    email = (email or "").strip().lower()
    otp_input = (otp or "").strip()
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            return RedirectResponse(url="/register?message=" + quote("Account not found. Please register."), status_code=303)

        if user.is_verified:
            return RedirectResponse(url="/login?message=" + quote("Account already verified. Please sign in."), status_code=303)

        smtp_configured = bool(os.environ.get("SMTP_USER", "").strip() and os.environ.get("SMTP_PASSWORD", "").strip())
        dev_otp = user.otp_code if not smtp_configured else None

        if not user.otp_code or user.otp_code != otp_input:
            return _template_response(request, "verify_otp.html", {
                "email": email,
                "dev_otp": dev_otp,
                "error": "Invalid verification code. Please check your email or terminal and try again."
            })

        if user.otp_expires_at and user.otp_expires_at < datetime.utcnow():
            return _template_response(request, "verify_otp.html", {
                "email": email,
                "dev_otp": dev_otp,
                "error": "The verification code has expired. Please click Resend OTP below."
            })

        # Mark user verified
        user.is_verified = True
        user.otp_code = None
        user.otp_expires_at = None
        db.commit()

        # Sign the user in with verified status
        request.session.clear()
        request.session["user_id"] = user.id
        request.session["user_name"] = user.full_name
        request.session["user_email"] = user.email
        request.session["is_verified"] = True

        return RedirectResponse(url="/?verified=1", status_code=303)
    finally:
        db.close()


@app.post("/resend-otp")
def resend_otp_submit(request: Request, email: str = Form("")):
    email = (email or "").strip().lower()
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            return RedirectResponse(url="/register?message=" + quote("Account not found. Please create an account."), status_code=303)
        if user.is_verified:
            return RedirectResponse(url="/login?message=" + quote("Account is already verified. Please sign in."), status_code=303)

        new_otp = generate_otp(6)
        user.otp_code = new_otp
        user.otp_expires_at = datetime.utcnow() + timedelta(minutes=10)
        db.commit()

        send_otp_email(user.email, new_otp, user.full_name)
        return RedirectResponse(
            url=f"/verify-otp?email={quote(email)}&message=" + quote("A fresh 6-digit OTP code has been dispatched."),
            status_code=303
        )
    finally:
        db.close()


@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)


@app.get("/api/auth/me")
def auth_me(request: Request):
    if not request.session.get("user_id"):
        return JSONResponse(status_code=401, content={"authenticated": False, "message": "Please log in."})
    return {
        "authenticated": True,
        "user": {
            "id": request.session.get("user_id"),
            "name": request.session.get("user_name"),
            "email": request.session.get("user_email"),
            "is_verified": bool(request.session.get("is_verified", True))
        }
    }


@app.get("/")
def serve_home(request: Request, verified: str = ""):
    """Render the dashboard only after a user has signed in."""
    if not request.session.get("user_id"):
        return RedirectResponse(url="/login", status_code=303)
    return _template_response(request, "index.html", {
        "user_name": request.session.get("user_name", "User"),
        "user_email": request.session.get("user_email", ""),
        "is_verified": request.session.get("is_verified", True),
        "just_verified": verified == "1"
    })


@app.get("/login/demo")
def login_demo(request: Request):
    """Fast-track demo login for hackathon evaluators and judges."""
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == "admin@brandshield.io").first()
        if not user:
            user = User(
                full_name="Chief Information Security Officer",
                email="admin@brandshield.io",
                password_hash=_hash_password("admin1234"),
                is_verified=True
            )
            db.add(user)
            db.commit()
            db.refresh(user)
        request.session.clear()
        request.session["user_id"] = user.id
        request.session["user_name"] = user.full_name
        request.session["user_email"] = user.email
        request.session["is_verified"] = True
        return RedirectResponse(url="/", status_code=303)
    finally:
        db.close()


@app.get("/slides", response_class=HTMLResponse)
@app.get("/pitch-deck", response_class=HTMLResponse)
def serve_pitch_deck(request: Request, slide: int = 1):
    """Render the interactive Hackathon Pitch Deck using 1st image template for Dashboard and 2nd image template for remaining slides."""
    user_name = request.session.get("user_name", "Security Analyst")
    return _template_response(request, "slides.html", {
        "user_name": user_name,
        "is_authenticated": bool(request.session.get("user_id")),
        "initial_slide": slide
    })

