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
    return Settings(_env_file=None, data_dir=tmp_path / "data", capture_source="none")


@pytest.fixture
def client(settings: Settings) -> Iterator[TestClient]:
    with TestClient(create_app(settings), base_url=BASE_URL) as test_client:
        yield test_client
