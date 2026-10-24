"""Application Factory."""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import timedelta

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import sessionmaker

from network_sniffer import __version__
from network_sniffer.api import health
from network_sniffer.api import setup as setup_api
from network_sniffer.clock import Clock, SystemClock
from network_sniffer.config import Settings, load_settings
from network_sniffer.security.csrf import CsrfProtection
from network_sniffer.security.passwords import Passwords
from network_sniffer.security.request_guard import LocalRequestGuardMiddleware
from network_sniffer.security.setup import SetupGateMiddleware, SetupState, SetupTokenManager
from network_sniffer.storage.db import create_db_engine, run_migrations
from network_sniffer.web import routes as web_routes
from network_sniffer.web import setup_pages

logger = logging.getLogger(__name__)


def log_setup_token(token: str, tokens: SetupTokenManager) -> None:
    """Einzige bewusste Ausnahme von „keine Secrets im Log“ (KAN-37): das Setup-Token.

    Steht nur im Server-Log bzw. auf der Konsole, nie im Windows-Ereignisprotokoll.
    """
    expires = tokens.expires_at.strftime("%Y-%m-%d %H:%M UTC") if tokens.expires_at else "-"
    logger.warning(
        "SETUP-TOKEN (einmalig, gültig bis %s): %s - noch kein Benutzer vorhanden. Ersten "
        "Admin unter /setup anlegen oder (empfohlen) per "
        "'network-sniffer create-admin --username <name>'.",
        expires,
        token,
    )


def create_app(settings: Settings | None = None, clock: Clock | None = None) -> FastAPI:
    settings = settings or load_settings()
    clock = clock or SystemClock()
    tokens = SetupTokenManager(clock, timedelta(minutes=settings.setup_token_ttl_minutes))
    setup_state = SetupState(tokens)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        engine = create_db_engine(settings)
        run_migrations(engine)
        app.state.engine = engine
        app.state.session_factory = sessionmaker(engine)
        if not setup_state.is_completed(app.state.session_factory):
            log_setup_token(tokens.issue(), tokens)
        try:
            yield
        finally:
            engine.dispose()

    # Keine automatische API-Doku: Swagger lädt Fremd-JS, und Routen werden später rollengeschützt.
    app = FastAPI(
        title="network-sniffer",
        version=__version__,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.settings = settings
    app.state.clock = clock
    app.state.setup = setup_state
    app.state.passwords = Passwords.from_settings(settings)
    app.state.csrf = CsrfProtection.from_settings(settings)
    # Zuletzt hinzugefügte Middleware läuft zuerst -> Host-/Origin-Prüfung vor dem Setup-Gate.
    app.add_middleware(SetupGateMiddleware, state=setup_state)
    app.add_middleware(LocalRequestGuardMiddleware, allowed_hosts=settings.effective_allowed_hosts)
    app.include_router(health.router)
    app.include_router(setup_api.router)
    app.include_router(web_routes.router)
    app.include_router(setup_pages.router)
    app.mount("/static", StaticFiles(directory=web_routes.STATIC_DIR), name="static")
    return app
