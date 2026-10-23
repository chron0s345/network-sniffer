"""Host-Header-Allowlist (DNS-Rebinding) und Origin-Prüfung für zustandsändernde Requests."""

import asyncio

import pytest
from fastapi import FastAPI, WebSocket
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from network_sniffer.config import Settings
from network_sniffer.main import create_app
from network_sniffer.security.request_guard import LocalRequestGuardMiddleware

ALLOWED = ["127.0.0.1:8765", "localhost:8765"]


def _guarded_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(LocalRequestGuardMiddleware, allowed_hosts=ALLOWED)

    @app.get("/thing")
    def read_thing() -> dict[str, str]:
        return {"ok": "read"}

    @app.post("/thing")
    def change_thing() -> dict[str, str]:
        return {"ok": "changed"}

    @app.websocket("/ws")
    async def ws(websocket: WebSocket) -> None:
        await websocket.accept()
        await websocket.send_text("hello")
        await websocket.close()

    return app


@pytest.fixture
def guarded() -> TestClient:
    return TestClient(_guarded_app(), base_url="http://127.0.0.1:8765")


@pytest.mark.parametrize("host", ["127.0.0.1:8765", "localhost:8765", "LocalHost:8765"])
def test_allowed_host_headers_pass(guarded: TestClient, host: str) -> None:
    response = guarded.get("/thing", headers={"host": host})

    assert response.status_code == 200


@pytest.mark.parametrize(
    "host",
    [
        "evil.example:8765",  # DNS-Rebinding: fremder Name zeigt auf 127.0.0.1
        "evil.example",
        "127.0.0.1",  # Port fehlt
        "127.0.0.1:9999",  # falscher Port
        "localhost:8765.evil.example",
    ],
)
def test_foreign_host_headers_are_rejected(guarded: TestClient, host: str) -> None:
    response = guarded.get("/thing", headers={"host": host})

    assert response.status_code == 400
    assert response.text == "Invalid host header"


def test_missing_host_header_is_rejected() -> None:
    sent: list[dict[str, object]] = []

    async def downstream(*_args: object) -> None:  # pragma: no cover - darf nicht aufgerufen werden
        raise AssertionError("Request ohne Host-Header wurde durchgelassen")

    async def receive() -> dict[str, object]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, object]) -> None:
        sent.append(message)

    middleware = LocalRequestGuardMiddleware(downstream, allowed_hosts=ALLOWED)
    scope = {"type": "http", "method": "GET", "path": "/", "headers": []}

    asyncio.run(middleware(scope, receive, send))

    assert sent[0]["status"] == 400


def test_post_without_origin_passes(guarded: TestClient) -> None:
    assert guarded.post("/thing").status_code == 200


@pytest.mark.parametrize("origin", ["http://127.0.0.1:8765", "http://localhost:8765"])
def test_post_with_own_origin_passes(guarded: TestClient, origin: str) -> None:
    assert guarded.post("/thing", headers={"origin": origin}).status_code == 200


@pytest.mark.parametrize("origin", ["http://evil.example", "null", "http://127.0.0.1:9999"])
def test_post_with_foreign_origin_is_rejected(guarded: TestClient, origin: str) -> None:
    response = guarded.post("/thing", headers={"origin": origin})

    assert response.status_code == 403


def test_get_with_foreign_origin_is_not_state_changing_and_passes(guarded: TestClient) -> None:
    assert guarded.get("/thing", headers={"origin": "http://evil.example"}).status_code == 200


def test_websocket_with_allowed_host_and_origin_connects(guarded: TestClient) -> None:
    with guarded.websocket_connect(
        "ws://127.0.0.1:8765/ws", headers={"origin": "http://127.0.0.1:8765"}
    ) as ws:
        assert ws.receive_text() == "hello"


def test_websocket_with_foreign_host_is_closed(guarded: TestClient) -> None:
    with (
        pytest.raises(WebSocketDisconnect) as excinfo,
        guarded.websocket_connect("ws://evil.example:8765/ws"),
    ):
        pass  # pragma: no cover

    assert excinfo.value.code == 1008


def test_websocket_with_foreign_origin_is_closed(guarded: TestClient) -> None:
    with (
        pytest.raises(WebSocketDisconnect) as excinfo,
        guarded.websocket_connect(
            "ws://127.0.0.1:8765/ws", headers={"origin": "http://evil.example"}
        ),
    ):
        pass  # pragma: no cover

    assert excinfo.value.code == 1008


def test_lifespan_scope_passes_through(settings: Settings) -> None:
    # Lifespan-Events laufen ohne Host-Header durch die Middleware (sonst startet die App nicht).
    with TestClient(create_app(settings), base_url="http://127.0.0.1:8765") as client:
        assert client.get("/api/health").status_code == 200


def test_app_rejects_rebinding_host_on_health_and_dashboard(settings: Settings) -> None:
    with TestClient(create_app(settings), base_url="http://evil.example:8765") as client:
        assert client.get("/api/health").status_code == 400
        assert client.get("/").status_code == 400


def test_app_uses_configured_allowed_hosts(settings: Settings) -> None:
    custom = settings.model_copy(update={"allowed_hosts": ["sniffer.local:8765"]})

    with TestClient(create_app(custom), base_url="http://sniffer.local:8765") as client:
        assert client.get("/api/health").status_code == 200
    with TestClient(create_app(custom), base_url="http://127.0.0.1:8765") as client:
        assert client.get("/api/health").status_code == 400
