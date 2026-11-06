from pathlib import Path
from typing import Any

import pytest
from conftest import synthetic_password

from network_sniffer import UNKNOWN_VERSION, __main__, get_version


@pytest.fixture
def uvicorn_calls(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    def fake_run(app: object, **kwargs: Any) -> None:
        calls.append({"app": app, **kwargs})

    monkeypatch.setattr(__main__.uvicorn, "run", fake_run)
    return calls


def test_serve_starts_uvicorn_on_configured_loopback_address(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, uvicorn_calls: list[dict[str, Any]]
) -> None:
    monkeypatch.setenv("NS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("NS_PORT", "8777")

    assert __main__.main(["serve"]) == 0

    (call,) = uvicorn_calls
    assert call["host"] == "127.0.0.1"
    assert call["port"] == 8777
    assert call["proxy_headers"] is False
    assert "strip_query" in call["log_config"]["handlers"]["access"]["filters"]


def test_serve_is_default_command(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, uvicorn_calls: list[dict[str, Any]]
) -> None:
    monkeypatch.setenv("NS_DATA_DIR", str(tmp_path))

    assert __main__.main([]) == 0
    assert len(uvicorn_calls) == 1


def test_serve_refuses_non_loopback_without_tls(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    uvicorn_calls: list[dict[str, Any]],
) -> None:
    monkeypatch.setenv("NS_BIND_HOST", "0.0.0.0")

    assert __main__.main(["serve"]) == 2

    assert uvicorn_calls == []
    err = capsys.readouterr().err
    assert "Konfigurationsfehler" in err
    assert "keine Loopback-Adresse" in err


def test_serve_reports_field_errors_with_variable_name(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    uvicorn_calls: list[dict[str, Any]],
) -> None:
    monkeypatch.setenv("NS_PORT", "not-a-port")

    assert __main__.main(["serve"]) == 2

    assert "NS_PORT" in capsys.readouterr().err


def _tls_files(tmp_path: Path) -> tuple[Path, Path]:
    # Inhalt egal: uvicorn ist gemockt, geprüft wird nur Existenz und Weitergabe.
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert.write_text("synthetic-cert", encoding="utf-8")
    key.write_text("synthetic-key", encoding="utf-8")
    return cert, key


def test_serve_passes_tls_files_to_uvicorn(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, uvicorn_calls: list[dict[str, Any]]
) -> None:
    cert, key = _tls_files(tmp_path)
    monkeypatch.setenv("NS_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("NS_BIND_HOST", "0.0.0.0")
    monkeypatch.setenv("NS_TLS_CERT", str(cert))
    monkeypatch.setenv("NS_TLS_KEY", str(key))

    assert __main__.main(["serve"]) == 0

    (call,) = uvicorn_calls
    assert call["host"] == "0.0.0.0"
    assert call["ssl_certfile"] == str(cert)
    assert call["ssl_keyfile"] == str(key)


def test_serve_without_tls_passes_no_ssl_arguments(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, uvicorn_calls: list[dict[str, Any]]
) -> None:
    monkeypatch.setenv("NS_DATA_DIR", str(tmp_path))

    assert __main__.main(["serve"]) == 0

    (call,) = uvicorn_calls
    assert "ssl_certfile" not in call
    assert "ssl_keyfile" not in call


@pytest.mark.parametrize("missing", ["NS_TLS_CERT", "NS_TLS_KEY"])
def test_serve_refuses_missing_tls_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    uvicorn_calls: list[dict[str, Any]],
    missing: str,
) -> None:
    cert, key = _tls_files(tmp_path)
    monkeypatch.setenv("NS_BIND_HOST", "0.0.0.0")
    monkeypatch.setenv("NS_TLS_CERT", str(cert))
    monkeypatch.setenv("NS_TLS_KEY", str(key))
    monkeypatch.setenv(missing, str(tmp_path / "does-not-exist.pem"))

    assert __main__.main(["serve"]) == 2

    assert uvicorn_calls == []
    err = capsys.readouterr().err
    assert "Konfigurationsfehler" in err
    assert f"{missing}: Datei" in err


@pytest.mark.parametrize("only", ["NS_TLS_CERT", "NS_TLS_KEY"])
def test_serve_refuses_only_one_tls_setting_on_loopback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    uvicorn_calls: list[dict[str, Any]],
    only: str,
) -> None:
    cert, _key = _tls_files(tmp_path)
    monkeypatch.setenv(only, str(cert))

    assert __main__.main(["serve"]) == 2

    assert uvicorn_calls == []
    assert "gemeinsam gesetzt" in capsys.readouterr().err


def test_version_flag_prints_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        __main__.main(["--version"])

    assert excinfo.value.code == 0
    assert capsys.readouterr().out.strip() == f"network-sniffer {get_version()}"


def test_unknown_command_is_rejected(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        __main__.main(["bogus"])

    assert excinfo.value.code == 2


def test_get_version_falls_back_without_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    from importlib.metadata import PackageNotFoundError

    import network_sniffer

    def missing(_name: str) -> str:
        raise PackageNotFoundError(_name)

    monkeypatch.setattr(network_sniffer, "version", missing)

    assert network_sniffer.get_version() == UNKNOWN_VERSION


# --- KAN-37: create-admin ---------------------------------------------------------------------


def _cli_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    data_dir = tmp_path / "data"
    monkeypatch.setenv("NS_DATA_DIR", str(data_dir))
    # Argon2 in Tests billig halten.
    monkeypatch.setenv("NS_ARGON2_TIME_COST", "1")
    monkeypatch.setenv("NS_ARGON2_MEMORY_COST_KIB", "8")
    monkeypatch.setenv("NS_ARGON2_PARALLELISM", "1")
    return data_dir


def _users(data_dir: Path) -> list[tuple[str, str, str]]:
    from sqlalchemy import select
    from sqlalchemy.orm import Session

    from network_sniffer.config import Settings
    from network_sniffer.storage.db import create_db_engine
    from network_sniffer.storage.models import User

    engine = create_db_engine(Settings(_env_file=None, data_dir=data_dir))
    try:
        with Session(engine) as session:
            return [
                (u.username, u.role, u.password_hash) for u in session.scalars(select(User)).all()
            ]
    finally:
        engine.dispose()


def _stdin(monkeypatch: pytest.MonkeyPatch, text: str) -> None:
    import io

    monkeypatch.setattr(__main__.sys, "stdin", io.StringIO(text))


def test_ac2_create_admin_with_password_stdin(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    data_dir = _cli_env(monkeypatch, tmp_path)
    password = synthetic_password()
    _stdin(monkeypatch, password + "\r\n")

    code = __main__.main(["create-admin", "--username", "cli-admin", "--password-stdin"])

    assert code == 0
    assert "cli-admin" in capsys.readouterr().out
    ((username, role, password_hash),) = _users(data_dir)
    assert (username, role) == ("cli-admin", "admin")
    assert password_hash.startswith("$argon2id$")


def test_ac2_create_admin_prompts_twice_with_getpass(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    data_dir = _cli_env(monkeypatch, tmp_path)
    prompts: list[str] = []

    def fake_getpass(prompt: str) -> str:
        prompts.append(prompt)
        return synthetic_password()

    monkeypatch.setattr(__main__.getpass, "getpass", fake_getpass)

    assert __main__.main(["create-admin", "--username", "interaktiv"]) == 0
    assert len(prompts) == 2
    assert len(_users(data_dir)) == 1


def test_create_admin_rejects_mismatching_getpass_input(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    data_dir = _cli_env(monkeypatch, tmp_path)
    answers = iter([synthetic_password(), synthetic_password(20)])
    monkeypatch.setattr(__main__.getpass, "getpass", lambda _prompt: next(answers))

    assert __main__.main(["create-admin", "--username", "interaktiv"]) == 1
    assert "stimmen nicht überein" in capsys.readouterr().err
    assert _users(data_dir) == []


def test_ac4_create_admin_fails_when_user_exists(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    data_dir = _cli_env(monkeypatch, tmp_path)
    _stdin(monkeypatch, synthetic_password() + "\n")
    assert __main__.main(["create-admin", "--username", "erster", "--password-stdin"]) == 0

    _stdin(monkeypatch, synthetic_password() + "\n")
    code = __main__.main(["create-admin", "--username", "zweiter", "--password-stdin"])

    assert code != 0
    assert "bereits ein Benutzer" in capsys.readouterr().err
    assert [u[0] for u in _users(data_dir)] == ["erster"]


def test_ac5_create_admin_rejects_short_password(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    data_dir = _cli_env(monkeypatch, tmp_path)
    _stdin(monkeypatch, "a" * 11 + "\n")

    code = __main__.main(["create-admin", "--username", "admin", "--password-stdin"])

    assert code == 1
    assert "Passwort muss mindestens 12 Zeichen haben" in capsys.readouterr().err
    assert _users(data_dir) == []


def test_create_admin_rejects_invalid_username(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    data_dir = _cli_env(monkeypatch, tmp_path)
    _stdin(monkeypatch, synthetic_password() + "\n")

    assert __main__.main(["create-admin", "--username", "a b", "--password-stdin"]) == 1
    assert "Benutzername" in capsys.readouterr().err
    assert _users(data_dir) == []


def test_create_admin_reports_race_with_parallel_setup(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from network_sniffer.services.users import SetupAlreadyCompletedError

    _cli_env(monkeypatch, tmp_path)
    _stdin(monkeypatch, synthetic_password() + "\n")

    def raced(*_args: object, **_kwargs: object) -> None:
        raise SetupAlreadyCompletedError

    monkeypatch.setattr(__main__, "create_initial_admin", raced)

    assert __main__.main(["create-admin", "--username", "admin", "--password-stdin"]) == 1
    assert "bereits ein Benutzer" in capsys.readouterr().err


def test_create_admin_reports_configuration_errors(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("NS_PORT", "not-a-port")

    assert __main__.main(["create-admin", "--username", "admin", "--password-stdin"]) == 2
    assert "NS_PORT" in capsys.readouterr().err


def test_create_admin_does_not_accept_password_argument(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as excinfo:
        __main__.main(["create-admin", "--username", "admin", "--password", "x"])

    assert excinfo.value.code == 2


def test_create_admin_requires_username() -> None:
    with pytest.raises(SystemExit) as excinfo:
        __main__.main(["create-admin"])

    assert excinfo.value.code == 2
