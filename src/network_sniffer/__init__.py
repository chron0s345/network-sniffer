"""network-sniffer – defensive Data-Leak-Erkennung im Netzwerkverkehr des eigenen PCs."""

from importlib.metadata import PackageNotFoundError, version

DISTRIBUTION_NAME = "network-sniffer"
UNKNOWN_VERSION = "0.0.0+unknown"


def get_version() -> str:
    """Liefert die installierte Version aus den Paket-Metadaten (gepflegt von release-please)."""
    try:
        return version(DISTRIBUTION_NAME)
    except PackageNotFoundError:
        return UNKNOWN_VERSION


__version__ = get_version()
