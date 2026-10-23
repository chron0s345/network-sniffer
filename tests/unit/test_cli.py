from pathlib import Path
from typing import Any

import pytest

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
