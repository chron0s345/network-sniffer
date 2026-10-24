"""Setup-Seite für die Ersteinrichtung (KAN-37).

Nach der Ersteinrichtung leitet ``/setup`` auf ``/login`` um (die Login-Seite liefert KAN-17).
"""

from urllib.parse import parse_qs

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from starlette.concurrency import run_in_threadpool

from network_sniffer import __version__
from network_sniffer.api.setup import InvalidSetupTokenError, run_setup
from network_sniffer.security.csrf import CSRF_COOKIE_NAME, CSRF_FIELD_NAME, CsrfProtection
from network_sniffer.security.passwords import PASSWORD_MIN_LENGTH, PasswordPolicyError
from network_sniffer.security.setup import SETUP_PATH
from network_sniffer.services.users import SetupAlreadyCompletedError, UsernameError
from network_sniffer.web.routes import templates

LOGIN_PATH = "/login"
MAX_FORM_BYTES = 16 * 1024
_MAX_FORM_FIELDS = 20
_FORM_CONTENT_TYPE = "application/x-www-form-urlencoded"
_NO_STORE = {"Cache-Control": "no-store"}

router = APIRouter()


def _render_form(
    request: Request, status_code: int = 200, error: str | None = None, username: str = ""
) -> HTMLResponse:
    csrf: CsrfProtection = request.app.state.csrf
    token = csrf.token_for(request)
    response = templates.TemplateResponse(
        request,
        "setup.html",
        {
            "version": __version__,
            "csrf_field": CSRF_FIELD_NAME,
            "csrf_token": token,
            "error": error,
            "username": username,
            "password_min_length": PASSWORD_MIN_LENGTH,
        },
        status_code=status_code,
        headers=_NO_STORE,
    )
    csrf.set_cookie(response, request, token)
    return response


def _redirect_to_login() -> RedirectResponse:
    return RedirectResponse(LOGIN_PATH, status_code=303)


async def _setup_completed(request: Request) -> bool:
    state = request.app.state.setup
    return await run_in_threadpool(state.is_completed, request.app.state.session_factory)


async def read_urlencoded_form(request: Request) -> dict[str, str]:
    """Liest ein ``application/x-www-form-urlencoded``-Formular mit Größenlimit.

    Bewusst ohne ``python-multipart`` (keine zusätzliche Abhängigkeit für ein einziges Formular).
    """
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != _FORM_CONTENT_TYPE:
        raise HTTPException(status_code=415, detail="Unsupported Media Type")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_FORM_BYTES:
            raise HTTPException(status_code=413, detail="Request Entity Too Large")
    try:
        parsed = parse_qs(
            body.decode("ascii"),
            keep_blank_values=True,
            encoding="utf-8",
            errors="strict",
            max_num_fields=_MAX_FORM_FIELDS,
        )
    except ValueError as exc:  # inkl. UnicodeDecodeError und zu vielen Feldern
        raise HTTPException(status_code=400, detail="Bad Request") from exc
    return {key: values[0] for key, values in parsed.items()}


@router.get(SETUP_PATH, response_class=HTMLResponse)
async def setup_page(request: Request) -> Response:
    if await _setup_completed(request):
        return _redirect_to_login()
    return _render_form(request)


@router.post(SETUP_PATH, response_class=HTMLResponse)
async def submit_setup(request: Request) -> Response:
    if await _setup_completed(request):
        return _redirect_to_login()
    form = await read_urlencoded_form(request)
    username = form.get("username", "")
    csrf: CsrfProtection = request.app.state.csrf
    if not csrf.validate(request.cookies.get(CSRF_COOKIE_NAME), form.get(CSRF_FIELD_NAME)):
        return _render_form(
            request, 403, "Formular abgelaufen - bitte erneut absenden.", username=username
        )
    password = form.get("password", "")
    if password != form.get("password_confirm", ""):
        return _render_form(request, 422, "Passwörter stimmen nicht überein", username=username)
    try:
        user = await run_in_threadpool(
            run_setup, request, username, password, form.get("token") or None
        )
    except SetupAlreadyCompletedError:
        return _redirect_to_login()
    except InvalidSetupTokenError:
        return _render_form(
            request, 403, "Setup-Token ist ungültig oder abgelaufen", username=username
        )
    except (UsernameError, PasswordPolicyError) as exc:
        return _render_form(request, 422, str(exc), username=username)
    return templates.TemplateResponse(
        request,
        "setup_done.html",
        {"version": __version__, "username": user.username, "login_path": LOGIN_PATH},
        headers=_NO_STORE,
    )
