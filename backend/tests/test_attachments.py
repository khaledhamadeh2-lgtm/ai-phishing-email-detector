from io import BytesIO
from zipfile import ZIP_DEFLATED, ZipFile

from app.attachments import analyze_attachment


def test_detects_spoofed_executable_attachment() -> None:
    result = analyze_attachment(
        "invoice.pdf",
        "application/pdf",
        b"MZ" + b"\x00" * 128,
        max_bytes=2_000_000,
    )

    assert result.risk_level == "high"
    assert any("Windows executable" in reason for reason in result.reasons)
    assert any("harmless-looking extension" in reason for reason in result.reasons)


def test_detects_office_macro_inside_zip_structure() -> None:
    buffer = BytesIO()
    with ZipFile(buffer, "w", ZIP_DEFLATED) as archive:
        archive.writestr("word/vbaProject.bin", b"macro bytes")
        archive.writestr("word/_rels/settings.xml.rels", b"externalLinks/")

    result = analyze_attachment(
        "report.docx",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        buffer.getvalue(),
        max_bytes=2_000_000,
    )

    assert result.score >= 32
    assert any("macro" in reason.lower() for reason in result.reasons)


def test_detects_html_credential_form_markers() -> None:
    result = analyze_attachment(
        "secure-message.html",
        "text/html",
        b"<html><form><input name='password'><script></script></form></html>",
        max_bytes=2_000_000,
    )

    assert result.risk_level in {"medium", "high"}
    assert any("form" in reason.lower() for reason in result.reasons)
