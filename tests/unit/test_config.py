from pathlib import Path

import pytest
from pydantic import ValidationError

from network_sniffer import config
from network_sniffer.config import Settings, default_data_dir, is_loopback_host, load_settings


def test_defaults_bind_to_loopback_port_8765() -> None:
    settings = Settings(_env_file=None)

    assert settings.bind_host == "127.0.0.1"
    assert settings.port == 8765
    assert settings.secret_key is None
    assert settings.capture_source == "npcap"


def test_default_data_dir_on_windows_uses_programdata(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config.sys, "platform", "win32")
    monkeypatch.setenv("PROGRAMDATA", r"D:\ProgramData")

    assert default_data_dir() == Path(r"D:\ProgramData") / "network-sniffer"


def test_default_data_dir_on_windows_without_programdata(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config.sys, "platform", "win32")
    monkeypatch.delenv("PROGRAMDATA", raising=False)

    assert default_data_dir() == Path(r"C:\ProgramData") / "network-sniffer"


def test_default_data_dir_elsewhere_is_local_data(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config.sys, "platform", "linux")

    assert default_data_dir() == Path("data")


def test_settings_read_ns_prefixed_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("NS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("NS_PORT", "9000")
    monkeypatch.setenv("NS_CAPTURE_SOURCE", "none")

    settings = Settings(_env_file=None)

    assert settings.data_dir == tmp_path
    assert settings.port == 9000
    assert settings.capture_source == "none"


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.10", "example.org", "::"])
def test_non_loopback_bind_host_without_tls_is_refused(host: str) -> None:
    with pytest.raises(ValidationError, match="keine Loopback-Adresse"):
        Settings(_env_file=None, bind_host=host)


def test_non_loopback_bind_host_with_tls_is_allowed(tmp_path: Path) -> None:
    settings = Settings(
        _env_file=None,
        bind_host="0.0.0.0",
        tls_cert=tmp_path / "cert.pem",
        tls_key=tmp_path / "key.pem",
    )

    assert settings.bind_host == "0.0.0.0"


def test_non_loopback_bind_host_with_only_cert_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, bind_host="0.0.0.0", tls_cert=tmp_path / "cert.pem")


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("127.0.0.1", True),
        ("127.1.2.3", True),
        ("localhost", True),
        ("LOCALHOST", True),
        ("::1", True),
        ("[::1]", True),
        ("0.0.0.0", False),
        ("10.0.0.1", False),
        ("evil.example", False),
    ],
)
def test_is_loopback_host(host: str, expected: bool) -> None:
    assert is_loopback_host(host) is expected


def test_default_allowed_hosts_are_loopback_names_with_port() -> None:
    settings = Settings(_env_file=None, port=9001)

    assert settings.effective_allowed_hosts == {"127.0.0.1:9001", "localhost:9001"}


def test_allowed_hosts_include_ipv6_bind_host_in_brackets() -> None:
    settings = Settings(_env_file=None, bind_host="::1")

    assert "[::1]:8765" in settings.effective_allowed_hosts


def test_allowed_hosts_are_configurable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NS_ALLOWED_HOSTS", '["Sniffer.Local:8765", " ", "127.0.0.1:8765"]')

    settings = Settings(_env_file=None)

    assert settings.effective_allowed_hosts == {"sniffer.local:8765", "127.0.0.1:8765"}


def test_secret_key_is_optional_until_kan15() -> None:
    empty, blank = "", " " * 3
    assert Settings(_env_file=None, secret_key=empty).secret_key is None
    assert Settings(_env_file=None, secret_key=blank).secret_key is None


def test_secret_key_too_short_is_refused() -> None:
    with pytest.raises(ValidationError, match="mindestens 32 Zeichen"):
        Settings(_env_file=None, secret_key="x" * 31)


def test_secret_key_with_min_length_is_accepted_and_hidden() -> None:
    synthetic_key = "k" * 32
    settings = Settings(_env_file=None, secret_key=synthetic_key)

    assert settings.secret_key is not None
    assert settings.secret_key.get_secret_value() == synthetic_key
    assert synthetic_key not in repr(settings)


def test_load_settings_reads_dotenv_in_working_directory(tmp_path: Path) -> None:
    data_dir = tmp_path / "from-dotenv"
    Path(".env").write_text(f"NS_DATA_DIR={data_dir.as_posix()}\nNS_PORT=8766\n", encoding="utf-8")

    settings = load_settings()

    assert settings.data_dir == data_dir
    assert settings.port == 8766


def test_load_settings_reads_service_env_file_in_data_dir(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    data_dir = tmp_path / "programdata"
    data_dir.mkdir()
    (data_dir / "network-sniffer.env").write_text("NS_PORT=8799\n", encoding="utf-8")
    monkeypatch.setenv("NS_DATA_DIR", str(data_dir))

    settings = load_settings()

    assert settings.port == 8799
    assert settings.data_dir == data_dir


def test_load_settings_environment_wins_over_service_env_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    data_dir = tmp_path / "programdata"
    data_dir.mkdir()
    (data_dir / "network-sniffer.env").write_text("NS_PORT=8799\n", encoding="utf-8")
    monkeypatch.setenv("NS_DATA_DIR", str(data_dir))
    monkeypatch.setenv("NS_PORT", "8800")

    assert load_settings().port == 8800
