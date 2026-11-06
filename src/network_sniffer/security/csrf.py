"""CSRF-Schutz für Formulare: signiertes Double-Submit-Cookie.

Ablauf: Die Seite setzt das Cookie ``ns_csrf`` (``HttpOnly``, ``SameSite=Strict``) und schreibt
denselben Wert in ein verstecktes Formularfeld. Beim Absenden müssen Cookie und Feld übereinstimmen
**und** die Signatur (HMAC-SHA256) gültig sein. Eine fremde Seite kann weder das Cookie lesen noch
ein gültig signiertes Token erzeugen; ``SameSite=Strict`` und die Origin-Prüfung der
``LocalRequestGuardMiddleware`` wirken zusätzlich.

Schlüssel: aus ``NS_SECRET_KEY`` abgeleitet, falls gesetzt (Tokens bleiben über Neustarts gültig),
sonst ein prozesslokaler Zufallsschlüssel (Tokens werden mit einem Neustart ungültig).
"""

import hashlib
import hmac
import secrets

from starlette.requests import Request
from starlette.responses import Response

from network_sniffer.config import Settings

CSRF_COOKIE_NAME = "ns_csrf"
CSRF_FIELD_NAME = "csrf_token"
_NONCE_BYTES = 32
_KEY_CONTEXT = b"network-sniffer/csrf/v1"


class CsrfProtection:
    def __init__(self, key: bytes) -> None:
        self._key = key

    @classmethod
    def from_settings(cls, settings: Settings) -> "CsrfProtection":
        if settings.secret_key is not None:
            secret = settings.secret_key.get_secret_value().encode("utf-8")
            return cls(hmac.new(secret, _KEY_CONTEXT, hashlib.sha256).digest())
        return cls(secrets.token_bytes(32))

    def _signature(self, nonce: str) -> str:
        return hmac.new(self._key, nonce.encode("ascii"), hashlib.sha256).hexdigest()

    def issue(self) -> str:
        nonce = secrets.token_urlsafe(_NONCE_BYTES)
        return f"{nonce}.{self._signature(nonce)}"

    def is_signed(self, token: str | None) -> bool:
        if not token or not token.isascii() or token.count(".") != 1:
            return False
        nonce, signature = token.split(".")
        return hmac.compare_digest(signature, self._signature(nonce))

    def validate(self, cookie_value: str | None, form_value: str | None) -> bool:
        if not cookie_value or not form_value:
            return False
        # Bytes vergleichen: compare_digest wirft bei Nicht-ASCII-str einen TypeError.
        same = hmac.compare_digest(cookie_value.encode("utf-8"), form_value.encode("utf-8"))
        return same and self.is_signed(cookie_value)

    def token_for(self, request: Request) -> str:
        """Vorhandenes gültiges Cookie weiterverwenden (mehrere Tabs), sonst neues Token."""
        current = request.cookies.get(CSRF_COOKIE_NAME)
        return current if current and self.is_signed(current) else self.issue()

    @staticmethod
    def set_cookie(response: Response, request: Request, token: str) -> None:
        response.set_cookie(
            CSRF_COOKIE_NAME,
            token,
            httponly=True,
            samesite="strict",
            secure=request.url.scheme == "https",
            path="/",
        )
