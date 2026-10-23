import re

from fastapi.testclient import TestClient


def test_ac2_index_page_has_title_network_sniffer(client: TestClient) -> None:
    response = client.get("/")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    match = re.search(r"<title>(.*?)</title>", response.text, re.DOTALL)
    assert match is not None
    assert match.group(1).strip() == "network-sniffer"


def test_ac2_index_page_links_stylesheet_that_is_served(client: TestClient) -> None:
    page = client.get("/").text
    assert "/static/style.css" in page

    css = client.get("/static/style.css")

    assert css.status_code == 200
    assert css.headers["content-type"].startswith("text/css")


def test_templates_autoescape_html_regression() -> None:
    # Regressionstest: Starlette erzeugt die Jinja2-Umgebung mit select_autoescape().
    from network_sniffer.web.routes import templates

    env = templates.env
    assert callable(env.autoescape)
    assert env.autoescape("index.html") is True
    assert env.autoescape("base.html") is True

    rendered = env.get_template("index.html").render(
        version="<script>alert(1)</script>", url_for=lambda *_args, **_kwargs: "/static/style.css"
    )

    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in rendered
    assert "<script>" not in rendered


def test_api_docs_are_disabled(client: TestClient) -> None:
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404
