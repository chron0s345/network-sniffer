# PyInstaller-Spezifikation für das Windows-Paket (onedir, ADR 0002).
#
# Aufruf nur über `uv run python packaging/build_windows.py` (setzt Arbeits- und Zielverzeichnis,
# prüft Lizenzen und erzeugt das Zip). Die Globals `Analysis`, `PYZ`, `EXE`, `COLLECT`, `SPECPATH`
# und `workpath` stellt PyInstaller beim Ausführen der Spec bereit.
#
# - Daten: Templates/Static des Dashboards und die Alembic-Migrationen liegen als Dateien unter
#   `_internal/network_sniffer/...`. Der Code findet sie relativ zu `__file__` (`web/routes.py`,
#   `storage/db.py`); `storage/db.alembic_config()` setzt `script_location` programmatisch, eine
#   `alembic.ini` wird im Paket nicht benötigt.
# - Metadaten von `network-sniffer` werden mitkopiert, damit `--version` die Version liefert.
# - Npcap (`wpcap.dll`/`Packet.dll`) wird NIE gebündelt (Npcap-Lizenz, ADR 0003); der Build prüft das.
# - Hidden-Imports für pywin32 (`win32timezone`, `servicemanager`) folgen mit KAN-35.

import json
from pathlib import Path

from PyInstaller.utils.hooks import copy_metadata

PROJECT_ROOT = Path(SPECPATH).resolve().parent  # noqa: F821 - von PyInstaller bereitgestellt
PACKAGE_DIR = PROJECT_ROOT / "src" / "network_sniffer"

datas = [
    (str(PACKAGE_DIR / "web" / "templates"), "network_sniffer/web/templates"),
    (str(PACKAGE_DIR / "web" / "static"), "network_sniffer/web/static"),
    # Alembic lädt env.py und versions/*.py als Dateien (nicht über das Import-System).
    (str(PACKAGE_DIR / "migrations" / "env.py"), "network_sniffer/migrations"),
    (str(PACKAGE_DIR / "migrations" / "script.py.mako"), "network_sniffer/migrations"),
    (str(PACKAGE_DIR / "migrations" / "versions" / "*.py"), "network_sniffer/migrations/versions"),
    *copy_metadata("network-sniffer"),
]

hiddenimports = [
    # Von migrations/env.py bzw. den Migrationsskripten zur Laufzeit importiert.
    "network_sniffer.storage.migration_env",
    "alembic.op",
    "alembic.context",
    "alembic.ddl.sqlite",
    "sqlalchemy.dialects.sqlite",
    # Per Zeichenkette in der Logging-Konfiguration referenziert.
    "network_sniffer.logging_config",
]

# Entwicklungswerkzeuge und nicht benötigte Teile der Standardbibliothek ausschließen. Der Build
# prüft zusätzlich, dass nur Laufzeitabhängigkeiten im Paket landen (build_windows.py).
excludes = [
    "tkinter",
    "_tkinter",
    "test",
    "pytest",
    "_pytest",
    "pytest_cov",
    "coverage",
    "time_machine",
    "httpx",
    # Optionale Syntaxhervorhebung in Mako-Fehlerseiten; nur als Dev-Abhängigkeit (pytest) installiert.
    "pygments",
    "PyInstaller",
    "setuptools",
    "pkg_resources",
    "_distutils_hack",
]

a = Analysis(  # noqa: F821
    [str(PACKAGE_DIR / "__main__.py")],
    pathex=[str(PROJECT_ROOT / "src")],
    datas=datas,
    hiddenimports=hiddenimports,
    excludes=excludes,
    noarchive=False,
)

# Liste der gebündelten Module und Binärdateien für die Prüfungen in build_windows.py.
Path(workpath, "bundle-manifest.json").write_text(  # noqa: F821
    json.dumps(
        {
            "modules": sorted({name for name, _path, _kind in a.pure}),
            "extensions": sorted({name for name, _path, kind in a.binaries if kind == "EXTENSION"}),
            "binaries": sorted({name for name, _path, _kind in a.binaries}),
        },
        indent=2,
    ),
    encoding="utf-8",
)

pyz = PYZ(a.pure)  # noqa: F821

exe = EXE(  # noqa: F821
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="network-sniffer",
    console=True,
    debug=False,
    strip=False,
    upx=False,
)

coll = COLLECT(  # noqa: F821
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="network-sniffer",
)
