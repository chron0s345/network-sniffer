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


def test_api_docs_are_disabled(client: TestClient) -> None:
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404
