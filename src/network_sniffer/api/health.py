"""Health-Endpunkt (öffentlich, für Smoke-Tests und Betrieb)."""

from typing import Annotated

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from network_sniffer import __version__
from network_sniffer.storage.db import get_session

router = APIRouter(prefix="/api", tags=["health"])


@router.get("/health")
def health(session: Annotated[Session, Depends(get_session)]) -> JSONResponse:
    try:
        session.execute(text("SELECT 1"))
    except SQLAlchemyError:
        return JSONResponse(
            status_code=503,
            content={"status": "error", "version": __version__, "db": "error"},
        )
    return JSONResponse(content={"status": "ok", "version": __version__, "db": "ok"})
