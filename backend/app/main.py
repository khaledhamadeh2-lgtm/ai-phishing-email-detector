import logging

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from .config import settings
from .detector import analyze
from .parser import parse_eml
from .schemas import AnalysisResponse, EmailInput

logging.basicConfig(level=settings.log_level)
logger = logging.getLogger(__name__)

app = FastAPI(
    title=settings.app_name,
    description="Explainable hybrid phishing-email risk analysis. Submitted content is processed in memory.",
    version="1.0.0",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": settings.app_name}


@app.post("/api/analyze", response_model=AnalysisResponse)
def analyze_email(payload: EmailInput) -> AnalysisResponse:
    return analyze(payload.sender, payload.subject, payload.body)


@app.post("/api/analyze-eml", response_model=AnalysisResponse)
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
        sender, subject, body = parse_eml(content)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        logger.warning("Unable to parse uploaded EML: %s", type(exc).__name__)
        raise HTTPException(status_code=422, detail="The EML file could not be parsed safely.") from exc
    return analyze(sender_override or sender, subject, body)
