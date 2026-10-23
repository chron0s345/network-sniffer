"""Dashboard-Seiten."""

import os  # KAN-11 Nachweis: absichtlich ungenutzter Import
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from network_sniffer import __version__

WEB_DIR = Path(__file__).parent
STATIC_DIR = WEB_DIR / "static"

# Starlette erzeugt die Umgebung mit jinja2.select_autoescape(): Autoescape ist für .html/.htm/.xml
# aktiv (Schutz vor XSS). Ein Regressionstest in tests/web/test_index.py sichert das ab.
templates = Jinja2Templates(directory=WEB_DIR / "templates")

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "index.html", {"version": __version__})
