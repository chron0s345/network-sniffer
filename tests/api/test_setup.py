"""KAN-37: Ersteinrichtung über ``POST /api/setup`` und Setup-Gate."""

import logging
from datetime import UTC, datetime, timedelta

import pytest
import time_machine
from conftest import synthetic_password
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from network_sniffer.security.passwords import PASSWORD_TOO_SHORT_MESSAGE
from network_sniffer.storage.models import Role, User

TOKEN_LOG_MARKER = "SETUP-TOKEN"  # noqa: S105 - Log-Marker, kein Passwort


def _token_from_records(records: list[logging.LogRecord]) -> str:
    """Klartext-Token aus genau einer Logzeile mit dem Marker ``SETUP-TOKEN``."""
    matching = [
        r for r in records if r.name == "network_sniffer.main" and TOKEN_LOG_MARKER in r.msg
    ]
    assert len(matching) == 1
    record = matching[0]
    assert isinstance(record.args, tuple)
    return str(record.args[1])


def _setup_token(caplog: pytest.LogCaptureFixture) -> str:
    """Token aus dem Startlog der Phase ``setup`` (dort startet die Fixture ``client``)."""
    return _token_from_records(caplog.get_records("setup"))


@pytest.fixture
def setup_token(client: TestClient, caplog: pytest.LogCaptureFixture) -> str:
    return _setup_token(caplog)


def _user_count(client: TestClient) -> int:
    with client.app.state.session_factory() as session:
        return session.scalar(select(func.count()).select_from(User)) or 0


def _payload(token: str | None, password: str | None = None, username: str = "erster-admin"):
    body = {"username": username, "password": password or synthetic_password()}
    if token is not None:
        body["token"] = token
    return body


# --- AC1: Token im Log, Redirect auf /setup ---------------------------------------------------


def test_ac1_setup_token_is_logged_once_as_warning_with_at_least_128_bit(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    records = [r for r in caplog.get_records("setup") if TOKEN_LOG_MARKER in r.getMessage()]
    (record,) = [r for r in records if r.name == "network_sniffer.main"]

    assert record.levelname == "WARNING"
    token = _setup_token(caplog)
    # token_urlsafe(32): 32 Byte = 256 Bit -> 43 Zeichen Base64url
    assert len(token) >= 22  # >= 128 Bit
    assert len(token) == 43
    assert "create-admin" in record.getMessage()


@pytest.mark.parametrize("path", ["/", "/findings", "/irgendeine/seite"])
def test_ac1_dashboard_pages_redirect_to_setup_without_users(client: TestClient, path: str) -> None:
    response = client.get(path, follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/setup"


def test_ac1_setup_page_static_files_and_health_stay_reachable(client: TestClient) -> None:
    assert client.get("/setup", follow_redirects=False).status_code == 200
    assert client.get("/static/style.css", follow_redirects=False).status_code == 200
    assert client.get("/api/health", follow_redirects=False).status_code == 200


def test_ac1_other_api_paths_answer_503_until_setup(client: TestClient) -> None:
    response = client.get("/api/findings", follow_redirects=False)

    assert response.status_code == 503
    assert response.json() == {"detail": "Ersteinrichtung erforderlich"}


def test_ac1_no_token_is_logged_when_a_user_exists(
    admin_client: TestClient, settings, caplog: pytest.LogCaptureFixture
) -> None:
    from network_sniffer.main import create_app

    caplog.clear()
    with TestClient(create_app(settings), base_url="http://127.0.0.1:8765") as restarted:
        assert restarted.get("/", follow_redirects=False).status_code == 200
    assert not [r for r in caplog.records if TOKEN_LOG_MARKER in r.getMessage()]


def test_ac1_websocket_is_closed_until_setup(client: TestClient) -> None:
    from starlette.websockets import WebSocketDisconnect

    with pytest.raises(WebSocketDisconnect) as excinfo, client.websocket_connect("/ws"):
        pass
    assert excinfo.value.code == 1008


# --- AC2: Admin anlegen, Token danach ungültig ------------------------------------------------


def test_ac2_setup_with_valid_token_creates_admin_with_argon2id_hash(
    client: TestClient, setup_token: str
) -> None:
    response = client.post("/api/setup", json=_payload(setup_token))

    assert response.status_code == 201
    body = response.json()
    assert body["username"] == "erster-admin"
    assert body["role"] == "admin"
    assert response.headers["cache-control"] == "no-store"
    with client.app.state.session_factory() as session:
        user = session.scalars(select(User)).one()
    assert user.role == Role.ADMIN
    assert user.username_normalized == "erster-admin"
    assert user.password_hash.startswith("$argon2id$")
    assert synthetic_password() not in user.password_hash
    assert user.is_active is True
    assert user.must_change_password is False
    assert client.app.state.passwords.verify(user.password_hash, synthetic_password())


def test_ac2_token_is_invalid_after_successful_setup(client: TestClient, setup_token: str) -> None:
    assert client.post("/api/setup", json=_payload(setup_token)).status_code == 201

    assert client.app.state.setup.tokens.verify(setup_token) is False
    assert client.app.state.setup.tokens.is_active is False
    second = client.post("/api/setup", json=_payload(setup_token, username="zweiter-admin"))
    assert second.status_code == 404
    assert _user_count(client) == 1


def test_ac2_dashboard_is_reachable_after_setup(client: TestClient, setup_token: str) -> None:
    client.post("/api/setup", json=_payload(setup_token))

    assert client.get("/", follow_redirects=False).status_code == 200


# --- AC3: falsches/fehlendes Token -> 403, kein Benutzer --------------------------------------


@pytest.mark.parametrize("token", [None, "", "falsches-token", "x" * 43])
def test_ac3_wrong_or_missing_token_is_rejected_with_403(
    client: TestClient, setup_token: str, token: str | None
) -> None:
    response = client.post("/api/setup", json=_payload(token))

    assert response.status_code == 403
    assert response.json()["detail"] == "Setup-Token ist ungültig oder abgelaufen"
    assert _user_count(client) == 0
    # Ein Fehlversuch verbraucht das echte Token nicht.
    assert client.app.state.setup.tokens.verify(setup_token) is True


def test_ac3_wrong_token_with_short_password_still_answers_403(
    client: TestClient, setup_token: str
) -> None:
    response = client.post("/api/setup", json=_payload("falsch", password="k" * 4))

    assert response.status_code == 403
    assert _user_count(client) == 0


def test_ac3_expired_token_is_rejected_with_403(client: TestClient, setup_token: str) -> None:
    # Security-Empfehlung: kurze Gültigkeit (Standard 60 min).
    with time_machine.travel(datetime.now(UTC) + timedelta(minutes=61), tick=False):
        response = client.post("/api/setup", json=_payload(setup_token))

    assert response.status_code == 403
    assert _user_count(client) == 0


def test_ac3_token_is_valid_shortly_before_expiry(client: TestClient, setup_token: str) -> None:
    with time_machine.travel(datetime.now(UTC) + timedelta(minutes=59), tick=False):
        response = client.post("/api/setup", json=_payload(setup_token))

    assert response.status_code == 201


def test_ac3_token_ttl_is_configurable(settings, caplog: pytest.LogCaptureFixture) -> None:
    from network_sniffer.main import create_app

    short = settings.model_copy(update={"setup_token_ttl_minutes": 5})
    with TestClient(create_app(short), base_url="http://127.0.0.1:8765") as client:
        token = _token_from_records(caplog.records)  # App startet hier in der Phase "call"
        with time_machine.travel(datetime.now(UTC) + timedelta(minutes=6), tick=False):
            assert client.post("/api/setup", json=_payload(token)).status_code == 403


# --- AC4: nach dem Setup 404 bzw. Redirect auf /login ----------------------------------------


def test_ac4_setup_api_answers_404_when_user_exists(admin_client: TestClient) -> None:
    response = admin_client.post("/api/setup", json=_payload("beliebig"))

    assert response.status_code == 404
    assert _user_count(admin_client) == 1


def test_ac4_setup_api_404_takes_precedence_over_token_check(
    client: TestClient, setup_token: str
) -> None:
    assert client.post("/api/setup", json=_payload(setup_token)).status_code == 201

    assert client.post("/api/setup", json=_payload(None)).status_code == 404


def test_ac4_setup_page_redirects_to_login_when_user_exists(admin_client: TestClient) -> None:
    response = admin_client.get("/setup", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_ac4_user_created_by_cli_while_running_invalidates_token(
    client: TestClient, setup_token: str
) -> None:
    # Wie create-admin aus einem zweiten Prozess: Benutzer existiert, Server-Cache weiß es nicht.
    from network_sniffer.services.users import create_initial_admin

    state = client.app.state
    with state.session_factory() as session:
        create_initial_admin(
            session,
            username="cli-admin",
            password=synthetic_password(),
            passwords=state.passwords,
            clock=state.clock,
        )

    assert client.post("/api/setup", json=_payload(setup_token)).status_code == 404
    assert state.setup.tokens.verify(setup_token) is False
    assert _user_count(client) == 1


# --- AC5: Passwort-Richtlinie -----------------------------------------------------------------


def test_ac5_password_with_11_characters_is_rejected_with_message(
    client: TestClient, setup_token: str
) -> None:
    response = client.post("/api/setup", json=_payload(setup_token, password="a" * 11))

    assert response.status_code == 422
    assert response.json()["detail"] == "Passwort muss mindestens 12 Zeichen haben"
    assert response.json()["detail"] == PASSWORD_TOO_SHORT_MESSAGE
    assert _user_count(client) == 0
    # Token bleibt gültig, der Betreiber kann es mit einem gültigen Passwort erneut versuchen.
    assert client.post("/api/setup", json=_payload(setup_token)).status_code == 201


def test_ac5_password_with_exactly_12_characters_is_accepted(
    client: TestClient, setup_token: str
) -> None:
    response = client.post("/api/setup", json=_payload(setup_token, password="b" * 12))

    assert response.status_code == 201


def test_invalid_username_is_rejected_with_422(client: TestClient, setup_token: str) -> None:
    response = client.post("/api/setup", json=_payload(setup_token, username="a b"))

    assert response.status_code == 422
    assert "Benutzername" in response.json()["detail"]
    assert _user_count(client) == 0


def test_oversized_fields_are_rejected(client: TestClient, setup_token: str) -> None:
    response = client.post("/api/setup", json=_payload(setup_token, password="p" * 5000))

    assert response.status_code == 422
    assert _user_count(client) == 0


def test_setup_api_rejects_foreign_origin(client: TestClient, setup_token: str) -> None:
    response = client.post(
        "/api/setup", json=_payload(setup_token), headers={"Origin": "http://evil.example"}
    )

    assert response.status_code == 403
    assert _user_count(client) == 0


def test_ac4_api_maps_already_initialized_during_creation_to_404_and_drops_token(
    client: TestClient, setup_token: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    import network_sniffer.api.setup as setup_module
    from network_sniffer.services.users import SetupAlreadyCompletedError

    # Nur die Abbildung in der API: Der Service meldet "schon eingerichtet" (echter Wettlauf
    # siehe tests/component/test_users_service.py::test_ac4_two_parallel_setups_create_one_admin).
    def raced(*_args: object, **_kwargs: object) -> None:
        raise SetupAlreadyCompletedError

    monkeypatch.setattr(setup_module, "create_initial_admin", raced)

    assert client.post("/api/setup", json=_payload(setup_token)).status_code == 404
    assert client.app.state.setup.tokens.verify(setup_token) is False
