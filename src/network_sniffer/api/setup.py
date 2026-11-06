"""Ersteinrichtung per API: ``POST /api/setup`` legt den ersten Admin an (KAN-37).

Öffentlich (vor der Ersteinrichtung gibt es keine Benutzer); geschützt durch das Setup-Token. Gehört
zur Allowlist des Rechte-Vollständigkeitstests (KAN-39).
"""

import logging

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from network_sniffer.security.passwords import PasswordPolicyError
from network_sniffer.security.setup import SETUP_API_PATH, SetupState
from network_sniffer.services.users import (
    CreatedUser,
    SetupAlreadyCompletedError,
    UsernameError,
    create_initial_admin,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["setup"])


class InvalidSetupTokenError(Exception):
    """Setup-Token fehlt, ist falsch, abgelaufen oder schon verbraucht."""


class SetupRequest(BaseModel):
    # Obergrenzen nur gegen übergroße Eingaben; die fachliche Prüfung folgt in den Services.
    username: str = Field(max_length=256)
    password: str = Field(max_length=4096)
    token: str | None = Field(default=None, max_length=256)


def run_setup(request: Request, username: str, password: str, token: str | None) -> CreatedUser:
    """Gemeinsamer Ablauf für API und Setup-Seite (synchron, im Threadpool aufrufen).

    Reihenfolge: bereits eingerichtet (-> ``SetupAlreadyCompletedError``) vor Token-Prüfung
    (-> ``InvalidSetupTokenError``) vor Eingabeprüfung (``UsernameError``/``PasswordPolicyError``).
    """
    app_state = request.app.state
    state: SetupState = app_state.setup
    if state.is_completed(app_state.session_factory):
        raise SetupAlreadyCompletedError
    if not state.tokens.verify(token):
        logger.warning("Ersteinrichtung abgelehnt: Setup-Token fehlt, ist falsch oder abgelaufen")
        raise InvalidSetupTokenError
    try:
        with app_state.session_factory() as session:
            user = create_initial_admin(
                session,
                username=username,
                password=password,
                passwords=app_state.passwords,
                clock=app_state.clock,
            )
    except SetupAlreadyCompletedError:
        state.mark_completed()
        raise
    state.mark_completed()
    logger.info(
        "Ersteinrichtung abgeschlossen: Admin %r angelegt, Setup-Token verworfen", user.username
    )
    return user


@router.post(SETUP_API_PATH, status_code=201)
def setup(request: Request, body: SetupRequest) -> JSONResponse:
    try:
        user = run_setup(request, body.username, body.password, body.token)
    except SetupAlreadyCompletedError as exc:
        raise HTTPException(status_code=404, detail="Not Found") from exc
    except InvalidSetupTokenError as exc:
        raise HTTPException(
            status_code=403, detail="Setup-Token ist ungültig oder abgelaufen"
        ) from exc
    except (UsernameError, PasswordPolicyError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return JSONResponse(
        status_code=201,
        content={"id": user.id, "username": user.username, "role": user.role.value},
        headers={"Cache-Control": "no-store"},
    )
