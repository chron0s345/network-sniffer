import logging
import logging.config

import pytest

from network_sniffer.logging_config import StripQueryStringFilter, build_log_config, strip_query


def _access_record(path: str) -> logging.LogRecord:
    # Gleiche Argumentform wie uvicorn.protocols.http (client, method, path, http_version, status).
    return logging.LogRecord(
        name="uvicorn.access",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg='%s - "%s %s HTTP/%s" %d',
        args=("127.0.0.1:50000", "GET", path, "1.1", 200),
        exc_info=None,
    )


@pytest.mark.parametrize(
    ("path", "expected"),
    [("/api/findings?q=geheim&token=abc", "/api/findings"), ("/", "/"), ("/a?", "/a")],
)
def test_strip_query(path: str, expected: str) -> None:
    assert strip_query(path) == expected


def test_access_log_filter_removes_query_string() -> None:
    record = _access_record("/api/findings?search=synthetic-value")

    assert StripQueryStringFilter().filter(record) is True

    message = record.getMessage()
    assert "synthetic-value" not in message
    assert message == '127.0.0.1:50000 - "GET /api/findings HTTP/1.1" 200'


def test_access_log_filter_ignores_records_without_path_args() -> None:
    record = logging.LogRecord("x", logging.INFO, __file__, 1, "plain %s", ("text",), None)

    assert StripQueryStringFilter().filter(record) is True
    assert record.getMessage() == "plain text"


def test_access_log_filter_ignores_non_string_path() -> None:
    record = logging.LogRecord("x", logging.INFO, __file__, 1, "%s %s %s", (1, 2, 3), None)

    StripQueryStringFilter().filter(record)

    assert record.args == (1, 2, 3)


def test_log_config_attaches_filter_to_access_handler_and_is_valid() -> None:
    config = build_log_config()

    assert "strip_query" in config["handlers"]["access"]["filters"]
    logging.config.dictConfig(config)
    handler = logging.getLogger("uvicorn.access").handlers[0]
    assert any(isinstance(f, StripQueryStringFilter) for f in handler.filters)


def test_log_config_does_not_modify_uvicorn_default() -> None:
    from uvicorn.config import LOGGING_CONFIG

    build_log_config()

    assert "filters" not in LOGGING_CONFIG["handlers"]["access"]
