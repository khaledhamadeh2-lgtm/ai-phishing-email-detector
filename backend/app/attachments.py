import hashlib
import re
import zipfile
from dataclasses import dataclass
from io import BytesIO
from pathlib import PurePath

MAX_ZIP_MEMBERS = 80
MAX_ZIP_MEMBER_BYTES = 2_000_000
EXECUTABLE_EXTENSIONS = {
    ".bat",
    ".cmd",
    ".com",
    ".exe",
    ".hta",
    ".iso",
    ".jar",
    ".js",
    ".jse",
    ".lnk",
    ".msi",
    ".ps1",
    ".scr",
    ".vbe",
    ".vbs",
    ".wsf",
}
MACRO_OFFICE_EXTENSIONS = {".docm", ".dotm", ".xlsm", ".xltm", ".pptm", ".potm", ".ppsm"}
RISKY_DOCUMENT_EXTENSIONS = {".html", ".htm", ".svg", ".xps"}
PDF_DANGEROUS_TOKENS = (
    b"/JavaScript",
    b"/JS",
    b"/OpenAction",
    b"/AA",
    b"/Launch",
    b"/EmbeddedFile",
    b"/RichMedia",
)
ZIP_MACRO_NAMES = ("vbaProject.bin",)
ZIP_EXTERNAL_NAMES = ("externalLinks/", "oleObject", "embeddings/")
URL_PATTERN = re.compile(rb"https?://", re.IGNORECASE)


@dataclass(frozen=True)
class AttachmentRisk:
    filename: str
    content_type: str
    size_bytes: int
    sha256: str
    risk_level: str
    reasons: tuple[str, ...]
    score: int


def _extension(filename: str) -> str:
    return PurePath(filename or "attachment").suffix.lower()


def _looks_like_double_extension(filename: str) -> bool:
    suffixes = [suffix.lower() for suffix in PurePath(filename or "").suffixes]
    return len(suffixes) >= 2 and suffixes[-1] in EXECUTABLE_EXTENSIONS


def _zip_reasons(content: bytes) -> list[str]:
    reasons: list[str] = []
    try:
        with zipfile.ZipFile(BytesIO(content)) as archive:
            members = archive.infolist()
            if len(members) > MAX_ZIP_MEMBERS:
                return ["Archive contains an unusually large number of files."]
            for member in members:
                normalized = member.filename.replace("\\", "/")
                if member.file_size > MAX_ZIP_MEMBER_BYTES:
                    reasons.append("Archive contains a very large embedded file.")
                    break
                if any(name in normalized for name in ZIP_MACRO_NAMES):
                    reasons.append("Office document contains VBA macro code.")
                if any(name in normalized for name in ZIP_EXTERNAL_NAMES):
                    reasons.append("Office/ZIP structure references embedded objects or external links.")
                if PurePath(normalized).suffix.lower() in EXECUTABLE_EXTENSIONS:
                    reasons.append("Archive contains an executable or script file.")
    except zipfile.BadZipFile:
        return []
    return sorted(set(reasons))


def analyze_attachment(filename: str, content_type: str, content: bytes, max_bytes: int) -> AttachmentRisk:
    """Static, no-execution attachment triage.

    This intentionally does not render documents, run macros, follow links, or extract archives to disk.
    It only inspects metadata, magic bytes, bounded ZIP central-directory data, and small byte patterns.
    """
    safe_name = PurePath(filename or "attachment").name[:180]
    truncated = content[:max_bytes]
    size = len(content)
    digest = hashlib.sha256(truncated).hexdigest()
    reasons: list[str] = []
    score = 0
    ext = _extension(safe_name)
    lower_type = (content_type or "application/octet-stream").lower()

    if size > max_bytes:
        reasons.append("Attachment was too large and was only partially inspected.")
        score += 14
    if ext in EXECUTABLE_EXTENSIONS:
        reasons.append("Executable or script attachment type.")
        score += 40
    if ext in MACRO_OFFICE_EXTENSIONS:
        reasons.append("Macro-enabled Office attachment type.")
        score += 35
    if ext in RISKY_DOCUMENT_EXTENSIONS:
        reasons.append("HTML/SVG-style document can hide scripts or credential forms.")
        score += 24
    if _looks_like_double_extension(safe_name):
        reasons.append("Filename uses a misleading double extension.")
        score += 26
    if truncated.startswith(b"MZ"):
        reasons.append("File bytes look like a Windows executable.")
        score += 45
    if truncated.startswith(b"%PDF"):
        found = [
            token.decode("ascii", errors="ignore").lstrip("/")
            for token in PDF_DANGEROUS_TOKENS
            if token in truncated
        ]
        if found:
            reasons.append(f"PDF contains potentially active features: {', '.join(sorted(set(found)))}.")
            score += 28
        if len(URL_PATTERN.findall(truncated)) >= 5:
            reasons.append("PDF contains many embedded links.")
            score += 12
    if "zip" in lower_type or truncated.startswith(b"PK\x03\x04"):
        zip_reasons = _zip_reasons(truncated)
        reasons.extend(zip_reasons)
        score += min(45, 16 * len(zip_reasons))
    if lower_type.startswith("image/"):
        reasons.append("Image content is not executed; QR/OCR analysis is a future enhancement.")

    if not reasons:
        reasons.append("No risky attachment metadata or static byte patterns were found.")

    risk_level = "high" if score >= 40 else "medium" if score >= 18 else "low"
    return AttachmentRisk(
        filename=safe_name,
        content_type=content_type or "application/octet-stream",
        size_bytes=size,
        sha256=digest,
        risk_level=risk_level,
        reasons=tuple(sorted(set(reasons))),
        score=min(score, 60),
    )
