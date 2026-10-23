"""Logging-Konfiguration für Uvicorn: Access-Log ohne Query-Strings."""

import copy
import logging
from typing import Any

from uvicorn.config import LOGGING_CONFIG

# Position des Pfads in den Argumenten des Uvicorn-Access-Logs:
# (client_addr, method, path_with_query, http_version, status_code)
_PATH_ARG_INDEX = 2


def strip_query(path: str) -> str:
    return path.split("?", 1)[0]


class StripQueryStringFilter(logging.Filter):
    """Entfernt Query-Strings aus Access-Log-Einträgen (können Suchbegriffe/Tokens enthalten)."""

    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if isinstance(args, tuple) and len(args) > _PATH_ARG_INDEX:
            path = args[_PATH_ARG_INDEX]
            if isinstance(path, str):
                record.args = (
                    *args[:_PATH_ARG_INDEX],
                    strip_query(path),
                    *args[_PATH_ARG_INDEX + 1 :],
                )
        return True


def build_log_config() -> dict[str, Any]:
    config = copy.deepcopy(LOGGING_CONFIG)
    config.setdefault("filters", {})["strip_query"] = {
        "()": f"{__name__}.StripQueryStringFilter",
    }
    config["handlers"]["access"].setdefault("filters", []).append("strip_query")
    return config
