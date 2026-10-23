"""Kommandozeile: ``network-sniffer [serve] [--version]``."""

import argparse
import sys
from collections.abc import Sequence

import uvicorn
from pydantic import ValidationError

from network_sniffer import __version__
from network_sniffer.config import ConfigurationError, load_settings
from network_sniffer.logging_config import build_log_config
from network_sniffer.main import create_app


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="network-sniffer",
        description="Defensive Data-Leak-Erkennung im Netzwerkverkehr des eigenen PCs.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("serve", help="Dashboard und API starten (Standard)")
    return parser


def format_validation_error(exc: ValidationError) -> str:
    lines = []
    for error in exc.errors():
        location = ".".join(str(part) for part in error["loc"])
        prefix = f"NS_{location.upper()}: " if location else ""
        lines.append(f"  - {prefix}{error['msg']}")
    return "\n".join(lines)


def _report_configuration_error(details: str) -> int:
    print(f"Konfigurationsfehler, Start abgebrochen:\n{details}", file=sys.stderr)
    return 2


def serve() -> int:
    try:
        settings = load_settings()
        tls_options = settings.tls_options()
    except ValidationError as exc:
        return _report_configuration_error(format_validation_error(exc))
    except ConfigurationError as exc:
        return _report_configuration_error(f"  - {exc}")
    uvicorn.run(
        create_app(settings),
        host=settings.bind_host,
        port=settings.port,
        log_config=build_log_config(),
        proxy_headers=False,
        server_header=False,
        **tls_options,
    )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    build_parser().parse_args(argv)
    # Einziger Befehl ist derzeit "serve" (auch ohne Angabe der Standard).
    return serve()


if __name__ == "__main__":
    sys.exit(main())
