from app.detector import analyze


def test_obvious_phishing_is_high_risk() -> None:
    result = analyze(
        "Microsoft Support <security.microsoft@gmail.com>",
        "URGENT: Account suspended",
        "Verify your password immediately at https://198.51.100.10/login!!!!",
    )
    assert result.probability >= 70
    assert result.verdict == "Likely Phishing"
    assert any(factor.id == "brand_freemail" for factor in result.risk_factors)
    assert any(factor.id == "suspicious_url" for factor in result.risk_factors)


def test_normal_internal_message_is_not_high_risk() -> None:
    result = analyze(
        "Maya <maya@example.org>",
        "Updated project notes",
        "Hi team, the meeting notes are in our usual shared workspace. See you Thursday.",
    )
    assert result.probability < 70
    assert result.verdict != "Likely Phishing"


def test_probability_is_bounded() -> None:
    result = analyze("x", "URGENT", "password " * 50)
    assert 1 <= result.probability <= 99


def test_failed_authentication_header_is_high_signal() -> None:
    result = analyze(
        "Billing <billing@example.com>",
        "Invoice",
        "Please review this invoice.",
        {"authentication-results": "mx.example; spf=fail dkim=fail dmarc=fail"},
    )
    assert result.analyzed_headers is True
    assert any(factor.id == "authentication_failure" for factor in result.risk_factors)


def test_reply_to_mismatch_is_detected() -> None:
    result = analyze(
        "Accounts <accounts@example.com>",
        "Question",
        "Please reply.",
        {"reply-to": "collector@other-example.net"},
    )
    assert any(factor.id == "reply_to_mismatch" for factor in result.risk_factors)
