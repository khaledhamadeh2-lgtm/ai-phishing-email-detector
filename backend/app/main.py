import logging
import secrets

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from .config import settings
from .detector import analyze
from .parser import parse_eml
from .schemas import AnalysisResponse, EmailInput

logging.basicConfig(level=settings.log_level)
logger = logging.getLogger(__name__)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "frame-ancestors 'none'; base-uri 'none'"
        return response


def require_api_key(x_api_key: str = Header(default="")) -> None:
    if settings.api_key and not secrets.compare_digest(x_api_key, settings.api_key):
        raise HTTPException(status_code=401, detail="A valid API key is required.")


app = FastAPI(
    title=settings.app_name,
    description="Explainable hybrid phishing-email risk analysis. Submitted content is processed in memory.",
    version="1.0.0",
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.hosts)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-API-Key"],
)


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": settings.app_name}


@app.post("/api/analyze", response_model=AnalysisResponse, dependencies=[Depends(require_api_key)])
def analyze_email(payload: EmailInput) -> AnalysisResponse:
    return analyze(payload.sender, payload.subject, payload.body, payload.headers)


@app.post("/api/analyze-eml", response_model=AnalysisResponse, dependencies=[Depends(require_api_key)])
async def analyze_eml(
    file: UploadFile = File(...),
    sender_override: str = Form(default=""),
) -> AnalysisResponse:
    if not file.filename or not file.filename.lower().endswith(".eml"):
        raise HTTPException(status_code=415, detail="Only .eml files are accepted.")
    content = await file.read(settings.max_email_bytes + 1)
    if len(content) > settings.max_email_bytes:
        raise HTTPException(status_code=413, detail="The email exceeds the configured size limit.")
    try:
        parsed = parse_eml(content)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        logger.warning("Unable to parse uploaded EML: %s", type(exc).__name__)
        raise HTTPException(status_code=422, detail="The EML file could not be parsed safely.") from exc
    return analyze(sender_override or parsed.sender, parsed.subject, parsed.body, parsed.headers)
