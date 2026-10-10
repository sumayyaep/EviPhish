from fastapi import APIRouter, HTTPException, status
from backend.app.schemas.reputation import ReputationRequest, ReputationResult
from backend.app.analyzer.reputation import EmailReputationChecker
from backend.app.core.config import settings

router = APIRouter(prefix="/reputation", tags=["Reputation"])

checker = EmailReputationChecker(
    provider_name=getattr(settings, "REPUTATION_PROVIDER", "emailrep"),
    api_key=getattr(settings, "EMAILREP_API_KEY", None)
)

@router.post("/check", response_model=ReputationResult)
def check_email_reputation(req: ReputationRequest):
    """Safely validates and checks the reputation of an email address."""
    try:
        return checker.check(req.email, req.consent_given)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred during reputation checking: {str(e)}"
        )
