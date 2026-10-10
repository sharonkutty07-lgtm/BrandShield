from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import List, Optional
from ..database import get_db
from ..models import SocialImpersonation, Brand
from ..schemas import ImpersonationResponse

router = APIRouter(prefix="/api/impersonations", tags=["Social Impersonation Watch"])

@router.get("/", response_model=List[ImpersonationResponse])
def list_impersonations(brand_id: Optional[int] = None, db: Session = Depends(get_db)):
    """Retrieves discovered fake social media accounts and profile impersonators."""
    query = db.query(SocialImpersonation)
    if brand_id:
        query = query.filter(SocialImpersonation.brand_id == brand_id)
    return query.order_by(SocialImpersonation.similarity_score.desc()).all()
