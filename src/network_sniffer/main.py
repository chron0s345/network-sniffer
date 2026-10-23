"""Application Factory."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import sessionmaker

from network_sniffer import __version__
from network_sniffer.api import health
from network_sniffer.config import Settings, load_settings
from network_sniffer.security.request_guard import LocalRequestGuardMiddleware
from network_sniffer.storage.db import create_db_engine, run_migrations
from network_sniffer.web import routes as web_routes


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        engine = create_db_engine(settings)
        run_migrations(engine)
        app.state.engine = engine
        app.state.session_factory = sessionmaker(engine)
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
    app.add_middleware(LocalRequestGuardMiddleware, allowed_hosts=settings.effective_allowed_hosts)
    app.include_router(health.router)
    app.include_router(web_routes.router)
    app.mount("/static", StaticFiles(directory=web_routes.STATIC_DIR), name="static")
    return app
