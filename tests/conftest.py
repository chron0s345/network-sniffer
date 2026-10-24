"""Gemeinsame Fixtures: isolierte Settings und TestClient ohne Zugriff auf echte Konfiguration."""

import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from network_sniffer.config import Settings
from network_sniffer.main import create_app

BASE_URL = "http://127.0.0.1:8765"


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Keine NS_-Variablen und keine .env des Entwicklers in Tests."""
    for name in list(os.environ):
        if name.upper().startswith("NS_"):
            monkeypatch.delenv(name, raising=False)
    workdir = tmp_path / "cwd"
    workdir.mkdir()
    monkeypatch.chdir(workdir)


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        _env_file=None,
        data_dir=tmp_path / "data",
        capture_source="none",
        # Argon2 in Tests billig halten (Produktion: RFC-9106-Standardwerte).
        argon2_time_cost=1,
        argon2_memory_cost_kib=8,
        argon2_parallelism=1,
    )


@pytest.fixture
def client(settings: Settings) -> Iterator[TestClient]:
    with TestClient(create_app(settings), base_url=BASE_URL) as test_client:
        yield test_client


def synthetic_password(length: int = 16) -> str:
    """Synthetisches Testpasswort, zur Laufzeit zusammengesetzt (kein Literal im Code)."""
    return ("pw-" + "x1" * length)[:length]


@pytest.fixture
def admin_client(client: TestClient) -> TestClient:
    """TestClient nach abgeschlossener Ersteinrichtung (ein Admin existiert)."""
    from network_sniffer.services.users import create_initial_admin

    state = client.app.state
    with state.session_factory() as session:
        create_initial_admin(
            session,
            username="admin-test",
            password=synthetic_password(),
            passwords=state.passwords,
            clock=state.clock,
        )
    return client
