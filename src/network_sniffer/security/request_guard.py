"""Schutz des lokalen Dashboards vor DNS-Rebinding und Cross-Origin-Schreibzugriffen.

Die Bindung an 127.0.0.1 allein reicht nicht: Eine fremde Website kann ihren Namen auf 127.0.0.1
umbiegen (DNS-Rebinding) und so Requests an das Dashboard schicken. Solche Requests tragen den
fremden Namen im Host-Header und werden hier abgewiesen.
"""

from collections.abc import Iterable

from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp, Receive, Scope, Send
from starlette.websockets import WebSocketClose

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_POLICY_VIOLATION = 1008


def _header(scope: Scope, name: bytes) -> str | None:
    for key, value in scope.get("headers", []):
        if key == name:
            return value.decode("latin-1")
    return None


class LocalRequestGuardMiddleware:
    """Erlaubt nur bekannte Host-Header; zustandsändernde Requests nur ohne oder mit eigenem Origin.

    Der Host-Header wird inklusive Port verglichen (anders als Starlettes TrustedHostMiddleware).
    """

    def __init__(self, app: ASGIApp, allowed_hosts: Iterable[str]) -> None:
        self.app = app
        self.allowed_hosts = frozenset(host.lower() for host in allowed_hosts)
        self.allowed_origins = frozenset(
            f"{scheme}://{host}" for host in self.allowed_hosts for scheme in ("http", "https")
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        host = (_header(scope, b"host") or "").lower()
        if host not in self.allowed_hosts:
            await self._reject(scope, receive, send, 400, "Invalid host header")
            return

        origin = _header(scope, b"origin")
        state_changing = scope["type"] == "websocket" or scope["method"] not in SAFE_METHODS
        if state_changing and origin is not None and origin.lower() not in self.allowed_origins:
            await self._reject(scope, receive, send, 403, "Origin not allowed")
            return

        await self.app(scope, receive, send)

    @staticmethod
    async def _reject(scope: Scope, receive: Receive, send: Send, status: int, text: str) -> None:
        if scope["type"] == "websocket":
            await WebSocketClose(code=_POLICY_VIOLATION)(scope, receive, send)
            return
        await PlainTextResponse(text, status_code=status)(scope, receive, send)
