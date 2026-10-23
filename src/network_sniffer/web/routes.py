"""Dashboard-Seiten."""

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from jinja2 import Environment, FileSystemLoader

from network_sniffer import __version__

WEB_DIR = Path(__file__).parent
STATIC_DIR = WEB_DIR / "static"

# Autoescape explizit aktiv (Schutz vor XSS in allen Templates).
templates = Jinja2Templates(
    env=Environment(loader=FileSystemLoader(WEB_DIR / "templates"), autoescape=True)
)

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "index.html", {"version": __version__})
