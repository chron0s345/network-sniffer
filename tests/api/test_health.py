import tomllib
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError

from network_sniffer import get_version


def test_ac1_health_returns_200_with_status_ok_and_version(client: TestClient) -> None:
    response = client.get("/api/health")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    body = response.json()
    assert body["status"] == "ok"
    assert body["version"] == get_version()
    assert body["db"] == "ok"


def test_ac1_health_version_matches_package_metadata(client: TestClient) -> None:
    # Version kommt aus den Paket-Metadaten (pyproject.toml, gepflegt von release-please).
    pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
    expected = tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]["version"]

    assert client.get("/api/health").json()["version"] == expected


def test_health_reports_503_when_database_unavailable(client: TestClient) -> None:
    class BrokenSession:
        def execute(self, *_args: object, **_kwargs: object) -> None:
            raise OperationalError("SELECT 1", {}, Exception("db down"))

        def __enter__(self) -> "BrokenSession":
            return self

        def __exit__(self, *_exc: object) -> None:
            return None

    client.app.state.session_factory = BrokenSession

    response = client.get("/api/health")

    assert response.status_code == 503
    assert response.json() == {"status": "error", "version": get_version(), "db": "error"}
