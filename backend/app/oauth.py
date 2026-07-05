import base64
import hashlib
import hmac
import json
import secrets
import urllib.parse
from datetime import UTC, datetime, timedelta

from .config import settings
from .schemas import OAuthConnectResponse
from .storage import RequestContext, create_oauth_state

GMAIL_SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
OUTLOOK_SCOPES = ["offline_access", "https://graph.microsoft.com/Mail.Read", "User.Read"]


def build_connect_response(context: RequestContext, provider: str) -> OAuthConnectResponse:
    provider = provider.lower()
    scopes = _scopes(provider)
    redirect_uri = f"{settings.public_base_url.rstrip('/')}/api/oauth/{provider}/callback"
    state = secrets.token_urlsafe(32)
    create_oauth_state(
        context,
        provider,
        state,
        redirect_uri,
        datetime.now(UTC) + timedelta(seconds=settings.oauth_state_ttl_seconds),
    )
    return OAuthConnectResponse(
        provider=provider,
        authorization_url=_authorization_url(provider, state, redirect_uri, scopes),
        state=state,
        scopes=scopes,
        redirect_uri=redirect_uri,
        privacy_note=(
            "Read-only OAuth is used so the scanner can inspect messages without asking "
            "for mailbox passwords. "
            "The app must not send, delete, move, or mark email read from this integration."
        ),
    )


def encrypted_authorization_code_payload(provider: str, code: str) -> str:
    payload = {
        "provider": provider,
        "authorization_code": code,
        "stored_at": datetime.now(UTC).isoformat(),
        "exchange_status": "pending_server_side_token_exchange",
    }
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    key = hashlib.sha256(settings.oauth_token_encryption_key.encode("utf-8")).digest()
    stream = hashlib.sha256(key + provider.encode("utf-8")).digest()
    encrypted = bytes(byte ^ stream[index % len(stream)] for index, byte in enumerate(raw))
    signature = hmac.new(key, encrypted, hashlib.sha256).digest()
    return _b64(signature + encrypted)


def scopes_for_provider(provider: str) -> list[str]:
    return _scopes(provider.lower())


def _authorization_url(provider: str, state: str, redirect_uri: str, scopes: list[str]) -> str:
    if provider == "gmail":
        client_id = settings.gmail_oauth_client_id or "configure-google-client-id"
        params = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": " ".join(scopes),
            "access_type": "offline",
            "prompt": "consent",
            "state": state,
        }
        return "https://accounts.google.com/o/oauth2/v2/auth?" + urllib.parse.urlencode(params)
    if provider == "outlook":
        client_id = settings.outlook_oauth_client_id or "configure-microsoft-client-id"
        params = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": " ".join(scopes),
            "response_mode": "query",
            "state": state,
        }
        return "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?" + urllib.parse.urlencode(
            params
        )
    raise ValueError("Unsupported OAuth provider.")


def _scopes(provider: str) -> list[str]:
    if provider == "gmail":
        return GMAIL_SCOPES
    if provider == "outlook":
        return OUTLOOK_SCOPES
    raise ValueError("Unsupported OAuth provider.")


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
