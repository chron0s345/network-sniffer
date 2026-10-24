"""KAN-37: Setup-Seite (Formular mit CSRF-Schutz)."""

import re

import pytest
from conftest import synthetic_password
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from network_sniffer.security.csrf import CSRF_COOKIE_NAME, CSRF_FIELD_NAME
from network_sniffer.storage.models import User
from network_sniffer.web.setup_pages import MAX_FORM_BYTES


@pytest.fixture
def setup_token(client: TestClient, caplog: pytest.LogCaptureFixture) -> str:
    (record,) = [
        r
        for r in caplog.get_records("setup")
        if r.name == "network_sniffer.main" and "SETUP-TOKEN" in r.msg
    ]
    assert isinstance(record.args, tuple)
    return str(record.args[1])


def _csrf_from_page(html: str) -> str:
    match = re.search(rf'name="{CSRF_FIELD_NAME}" value="([^"]+)"', html)
    assert match is not None
    return match.group(1)


def _user_count(client: TestClient) -> int:
    with client.app.state.session_factory() as session:
        return session.scalar(select(func.count()).select_from(User)) or 0


def _form(token: str, csrf: str, password: str | None = None, **overrides: str) -> dict[str, str]:
    password = password or synthetic_password()
    form = {
        "username": "web-admin",
        "password": password,
        "password_confirm": password,
        "token": token,
        CSRF_FIELD_NAME: csrf,
    }
    form.update(overrides)
    return form


def _open_form(client: TestClient) -> str:
    page = client.get("/setup")
    assert page.status_code == 200
    return _csrf_from_page(page.text)


def test_ac1_setup_page_shows_form_with_csrf_cookie(client: TestClient) -> None:
    response = client.get("/setup")

    assert response.status_code == 200
    assert "<h1>Ersteinrichtung</h1>" in response.text
    for field in ("username", "password", "password_confirm", "token"):
        assert f'name="{field}"' in response.text
    assert response.headers["cache-control"] == "no-store"
    cookie = response.headers["set-cookie"]
    assert cookie.startswith(f"{CSRF_COOKIE_NAME}=")
    assert "httponly" in cookie.lower()
    assert "samesite=strict" in cookie.lower()
    assert client.cookies.get(CSRF_COOKIE_NAME) == _csrf_from_page(response.text)


def test_ac1_redirect_from_dashboard_lands_on_setup_page(client: TestClient) -> None:
    response = client.get("/")

    assert response.url.path == "/setup"
    assert "<h1>Ersteinrichtung</h1>" in response.text


def test_ac2_setup_form_creates_admin_and_shows_confirmation(
    client: TestClient, setup_token: str
) -> None:
    csrf = _open_form(client)

    response = client.post("/setup", data=_form(setup_token, csrf))

    assert response.status_code == 200
    assert "Ersteinrichtung abgeschlossen" in response.text
    assert 'href="/login"' in response.text
    with client.app.state.session_factory() as session:
        user = session.scalars(select(User)).one()
    assert (user.username, user.role) == ("web-admin", "admin")
    assert client.app.state.setup.tokens.verify(setup_token) is False


def test_ac3_setup_form_with_wrong_token_answers_403(client: TestClient, setup_token: str) -> None:
    csrf = _open_form(client)

    response = client.post("/setup", data=_form("falsches-token", csrf))

    assert response.status_code == 403
    assert "Setup-Token ist ungültig oder abgelaufen" in response.text
    assert 'value="web-admin"' in response.text  # Benutzername bleibt, Passwort/Token nicht
    assert synthetic_password() not in response.text
    assert _user_count(client) == 0


def test_ac3_setup_form_with_missing_token_answers_403(
    client: TestClient, setup_token: str
) -> None:
    csrf = _open_form(client)

    response = client.post("/setup", data=_form("", csrf))

    assert response.status_code == 403
    assert _user_count(client) == 0


def test_ac4_setup_form_post_after_setup_redirects_to_login(admin_client: TestClient) -> None:
    response = admin_client.post("/setup", data={"username": "x"}, follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    assert _user_count(admin_client) == 1


def test_ac4_second_form_submission_with_same_token_redirects_to_login(
    client: TestClient, setup_token: str
) -> None:
    csrf = _open_form(client)
    assert client.post("/setup", data=_form(setup_token, csrf)).status_code == 200

    again = client.post(
        "/setup", data=_form(setup_token, csrf, username="zweiter"), follow_redirects=False
    )

    assert again.status_code == 303
    assert again.headers["location"] == "/login"
    assert _user_count(client) == 1


def test_ac5_setup_form_rejects_short_password_with_message(
    client: TestClient, setup_token: str
) -> None:
    csrf = _open_form(client)

    response = client.post("/setup", data=_form(setup_token, csrf, password="c" * 11))

    assert response.status_code == 422
    assert "Passwort muss mindestens 12 Zeichen haben" in response.text
    assert _user_count(client) == 0


def test_setup_form_rejects_mismatching_passwords(client: TestClient, setup_token: str) -> None:
    csrf = _open_form(client)

    response = client.post(
        "/setup", data=_form(setup_token, csrf, password_confirm=synthetic_password(20))
    )

    assert response.status_code == 422
    assert "Passwörter stimmen nicht überein" in response.text
    assert _user_count(client) == 0


def test_setup_form_rejects_invalid_username(client: TestClient, setup_token: str) -> None:
    csrf = _open_form(client)

    response = client.post("/setup", data=_form(setup_token, csrf, username="<b>x</b>"))

    assert response.status_code == 422
    assert "Benutzername" in response.text
    assert "<b>x</b>" not in response.text  # Autoescape
    assert _user_count(client) == 0


@pytest.mark.parametrize("csrf_value", ["", "manipuliert.abc"])
def test_csrf_setup_form_without_valid_csrf_token_is_rejected(
    client: TestClient, setup_token: str, csrf_value: str
) -> None:
    _open_form(client)

    response = client.post("/setup", data=_form(setup_token, csrf_value))

    assert response.status_code == 403
    assert "Formular abgelaufen" in response.text
    assert _user_count(client) == 0


def test_csrf_setup_form_without_cookie_is_rejected(client: TestClient, setup_token: str) -> None:
    csrf = _open_form(client)
    client.cookies.clear()

    response = client.post("/setup", data=_form(setup_token, csrf))

    assert response.status_code == 403
    assert _user_count(client) == 0


def test_csrf_forged_matching_cookie_and_field_without_signature_is_rejected(
    client: TestClient, setup_token: str
) -> None:
    forged = "nonce.0000"
    client.cookies.set(CSRF_COOKIE_NAME, forged)

    response = client.post("/setup", data=_form(setup_token, forged))

    assert response.status_code == 403
    assert _user_count(client) == 0


def test_setup_form_requires_urlencoded_body(client: TestClient, setup_token: str) -> None:
    _open_form(client)

    response = client.post("/setup", json={"username": "x"})

    assert response.status_code == 415


def test_setup_form_rejects_oversized_body(client: TestClient, setup_token: str) -> None:
    _open_form(client)

    response = client.post(
        "/setup",
        content=b"username=" + b"a" * (MAX_FORM_BYTES + 1),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )

    assert response.status_code == 413


@pytest.mark.parametrize(
    "body", [b"username=%ff%fe", "username=ä".encode(), b"&".join([b"f=1"] * 50)]
)
def test_setup_form_rejects_malformed_body(
    client: TestClient, setup_token: str, body: bytes
) -> None:
    _open_form(client)

    response = client.post(
        "/setup", content=body, headers={"Content-Type": "application/x-www-form-urlencoded"}
    )

    assert response.status_code == 400
