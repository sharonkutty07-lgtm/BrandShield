from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import List, Optional
from ..database import get_db
from ..models import CredentialLeak
from ..schemas import LeakResponse

router = APIRouter(prefix="/api/leaks", tags=["Credential Leak Awareness"])

@router.get("/", response_model=List[LeakResponse])
def list_credential_leaks(brand_id: Optional[int] = None, db: Session = Depends(get_db)):
    """Retrieves leaked credentials and breach exposures associated with the brand domain."""
    query = db.query(CredentialLeak)
    if brand_id:
        query = query.filter(CredentialLeak.brand_id == brand_id)
    return query.order_by(CredentialLeak.discovered_at.desc()).all()
