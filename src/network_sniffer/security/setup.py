"""Ersteinrichtung: einmaliges Setup-Token und Setup-Gate (KAN-37).

Lebenszyklus des Setup-Tokens (Security-Empfehlung aus dem Review von KAN-10):
- 256 Bit Zufall (``secrets.token_urlsafe(32)``), nur beim Start erzeugt, solange kein Benutzer
  existiert;
- im Speicher liegt nur der SHA-256-Hash, der Klartext wird genau einmal ins Log geschrieben;
- kurze Gültigkeit (``NS_SETUP_TOKEN_TTL_MINUTES``, Standard 60 min), danach neues Token nur per
  Neustart;
- einmalig: nach Anlage des ersten Benutzers (Setup-Seite, API oder CLI) wird es verworfen.

Das Token ist prozesslokal; die Anwendung läuft deshalb mit genau einem Uvicorn-Worker.
"""

import hashlib
import hmac
import secrets
from collections.abc import Callable
from datetime import datetime, timedelta

from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool
from starlette.responses import JSONResponse, RedirectResponse
from starlette.types import ASGIApp, Receive, Scope, Send
from starlette.websockets import WebSocketClose

from network_sniffer.clock import Clock
from network_sniffer.services.users import users_exist

SETUP_TOKEN_BYTES = 32
SETUP_PATH = "/setup"
SETUP_API_PATH = "/api/setup"
# Pfade, die vor der Ersteinrichtung erreichbar bleiben.
SETUP_EXEMPT_PATHS = frozenset({SETUP_PATH, SETUP_API_PATH, "/api/health"})
SETUP_EXEMPT_PREFIXES = ("/static/",)
_POLICY_VIOLATION = 1008


def _digest(token: str) -> bytes:
    return hashlib.sha256(token.encode("utf-8")).digest()


class SetupTokenManager:
    """Hält das Setup-Token ausschließlich als SHA-256-Hash mit Ablaufzeit."""

    def __init__(self, clock: Clock, ttl: timedelta) -> None:
        self._clock = clock
        self._ttl = ttl
        self._digest: bytes | None = None
        self._expires_at: datetime | None = None

    @property
    def expires_at(self) -> datetime | None:
        return self._expires_at

    @property
    def is_active(self) -> bool:
        return (
            self._digest is not None
            and self._expires_at is not None
            and self._clock.now() < self._expires_at
        )

    def issue(self) -> str:
        """Erzeugt ein neues Token und liefert den Klartext genau einmal zurück."""
        token = secrets.token_urlsafe(SETUP_TOKEN_BYTES)
        self._digest = _digest(token)
        self._expires_at = self._clock.now() + self._ttl
        return token

    def verify(self, token: str | None) -> bool:
        """Prüft in konstanter Zeit; abgelaufene, verworfene oder fehlende Tokens sind ungültig."""
        if not token or not self.is_active or self._digest is None:
            return False
        return hmac.compare_digest(_digest(token), self._digest)

    def invalidate(self) -> None:
        self._digest = None
        self._expires_at = None


class SetupState:
    """Merkt sich, ob die Ersteinrichtung abgeschlossen ist (danach keine DB-Abfrage je Request)."""

    def __init__(self, tokens: SetupTokenManager) -> None:
        self.tokens = tokens
        self._completed = False

    def is_completed(self, session_factory: Callable[[], Session]) -> bool:
        if self._completed:
            return True
        with session_factory() as session:
            if users_exist(session):
                # z. B. per CLI angelegt, während der Server läuft: Token sofort verwerfen.
                self.mark_completed()
        return self._completed

    def mark_completed(self) -> None:
        self._completed = True
        self.tokens.invalidate()


def is_setup_exempt(path: str) -> bool:
    return path in SETUP_EXEMPT_PATHS or path.startswith(SETUP_EXEMPT_PREFIXES)


class SetupGateMiddleware:
    """Solange kein Benutzer existiert: Seiten -> Redirect auf ``/setup``, API -> 503.

    Ausnahmen: ``/setup``, ``/api/setup``, ``/api/health`` und ``/static/``.
    """

    def __init__(self, app: ASGIApp, state: SetupState) -> None:
        self.app = app
        self.state = state

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket") or is_setup_exempt(scope["path"]):
            await self.app(scope, receive, send)
            return
        session_factory = scope["app"].state.session_factory
        # Synchrone DB-Abfrage nicht im Event-Loop (nur bis zur Ersteinrichtung nötig).
        if await run_in_threadpool(self.state.is_completed, session_factory):
            await self.app(scope, receive, send)
            return
        if scope["type"] == "websocket":
            await WebSocketClose(code=_POLICY_VIOLATION)(scope, receive, send)
            return
        if scope["path"].startswith("/api/"):
            response: JSONResponse | RedirectResponse = JSONResponse(
                {"detail": "Ersteinrichtung erforderlich"}, status_code=503
            )
        else:
            response = RedirectResponse(SETUP_PATH, status_code=303)
        await response(scope, receive, send)
