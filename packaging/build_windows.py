"""Windows-Paket bauen: PyInstaller (onedir) -> ``dist/network-sniffer-<version>-windows-x64.zip``.

Aufrufe (aus dem Projektverzeichnis):

    uv run python packaging/build_windows.py                   # Paket bauen (nur Windows)
    uv run python packaging/build_windows.py --check-licenses  # nur Lizenzprüfung (alle OS)

Der Build
1. prüft die Lizenzen aller Laufzeit-Distributionen gegen die Allowlist (ADR 0003),
2. ruft PyInstaller mit ``packaging/network-sniffer.spec`` auf,
3. prüft, dass nur Laufzeitabhängigkeiten gebündelt wurden und keine Npcap-DLL im Paket liegt,
4. legt ``LICENSE``, ``README.md`` und ``THIRD-PARTY-LICENSES.txt`` neben das EXE,
5. prüft ``network-sniffer.exe --version``,
6. schreibt das Zip und daneben ``<zip>.sha256`` (Format von ``sha256sum``).

Die Hilfsfunktionen sind plattformunabhängig und werden in ``tests/packaging/`` getestet.
Abhängigkeiten nur aus der Standardbibliothek und ``packaging`` (Dev-Umgebung).
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata as metadata
import json
import re
import shutil
import subprocess  # noqa: S404 - nur feste Argumentlisten, kein Shell-Aufruf
import sys
import time
import tomllib
import zipfile
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PACKAGING_DIR = PROJECT_ROOT / "packaging"
SPEC_FILE = PACKAGING_DIR / "network-sniffer.spec"
RUNTIME_COMPONENTS_LICENSES = PACKAGING_DIR / "licenses" / "python-runtime-components.txt"
BUILD_DIR = PROJECT_ROOT / "build" / "pyinstaller"
PYINSTALLER_DIST_DIR = BUILD_DIR / "dist"
OUTPUT_DIR = PROJECT_ROOT / "dist"

DISTRIBUTION_NAME = "network-sniffer"
APP_DIR_NAME = "network-sniffer"
EXE_NAME = "network-sniffer.exe"
THIRD_PARTY_FILE_NAME = "THIRD-PARTY-LICENSES.txt"
BUNDLE_MANIFEST_NAME = "bundle-manifest.json"

# Npcap darf ohne OEM-Lizenz nicht weitergegeben werden (ADR 0003): diese DLLs nie im Paket.
FORBIDDEN_BINARIES = frozenset({"wpcap.dll", "packet.dll"})

# Lizenz-Allowlist (ADR 0003, KAN-46). MPL-2.0 nur für unverändert gebündelte Komponenten.
ALLOWED_LICENSES = frozenset(
    {
        "MIT",
        "MIT-0",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "Apache-2.0",
        "PSF-2.0",
        "CNRI-Python",
        "MPL-2.0",
        "ISC",
        "Unlicense",
        "0BSD",
    }
)
_ALLOWED_UPPER = {name.upper(): name for name in ALLOWED_LICENSES}

# Copyleft in Laufzeitabhängigkeiten ist ausgeschlossen (ADR 0003).
_COPYLEFT_ID = re.compile(r"^(A|L)?GPL", re.IGNORECASE)
_COPYLEFT_TEXT = re.compile(
    r"\b(A|L)?GPL|GNU (Affero |Lesser |Library )?General Public", re.IGNORECASE
)

# Nur eindeutige Trove-Classifier werden automatisch übersetzt. "BSD License" und
# "Apache Software License" sind mehrdeutig (Version/Klauseln) und brauchen eine Zuordnung unten.
CLASSIFIER_TO_SPDX = {
    "License :: OSI Approved :: MIT License": "MIT",
    "License :: OSI Approved :: MIT No Attribution License (MIT-0)": "MIT-0",
    "License :: OSI Approved :: ISC License (ISCL)": "ISC",
    "License :: OSI Approved :: Python Software Foundation License": "PSF-2.0",
    "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "License :: OSI Approved :: The Unlicense (Unlicense)": "Unlicense",
    "License :: OSI Approved :: Zero-Clause BSD (0BSD)": "0BSD",
}


@dataclass(frozen=True)
class LicenseOverride:
    """Manuelle Zuordnung für Distributionen ohne eindeutigen SPDX-Ausdruck in den Metadaten.

    ``evidence`` ist die erwartete Rohangabe (siehe ``raw_license_summary``). Ändern sich die
    Metadaten, greift die Zuordnung nicht mehr und der Build schlägt fehl -> erneut prüfen.
    """

    expression: str
    evidence: str
    reason: str


# Zuordnungstabelle für unklare Metadaten. Jede Zeile wurde von Hand gegen die mitgelieferte
# Lizenzdatei geprüft; Begründung im Feld ``reason``. Schlüssel: kanonischer Distributionsname.
LICENSE_OVERRIDES: dict[str, LicenseOverride] = {
    # Jinja2 3.1.x: kein License-Expression, nur Classifier "BSD License";
    # LICENSE.txt ist der BSD-3-Clause-Text ("Copyright 2007 Pallets").
    "jinja2": LicenseOverride(
        expression="BSD-3-Clause",
        evidence="Classifier: License :: OSI Approved :: BSD License",
        reason="nur Classifier 'BSD License'; LICENSE.txt ist BSD-3-Clause (Pallets)",
    ),
}

_LICENSE_FILE_PREFIXES = ("LICENSE", "LICENCE", "COPYING", "NOTICE", "AUTHORS")
_VERSION_PATTERN = re.compile(r"^[0-9][0-9A-Za-z.+!_-]*$")


class LicenseCheckError(Exception):
    """Mindestens eine Laufzeit-Distribution verletzt die Lizenz-Allowlist."""

    def __init__(self, problems: list[str]) -> None:
        super().__init__("\n".join(problems))
        self.problems = problems


class BuildError(Exception):
    """Der Paket-Build ist fehlgeschlagen (Ursache in der Nachricht)."""


@dataclass(frozen=True)
class LicenseDecision:
    name: str
    version: str
    expression: str
    source: str


# --------------------------------------------------------------------------------------------
# Version und Dateinamen
# --------------------------------------------------------------------------------------------


def package_file_name(version: str) -> str:
    """``network-sniffer-<version>-windows-x64.zip``; lehnt Versionen mit Pfadzeichen ab."""
    if not _VERSION_PATTERN.fullmatch(version):
        raise ValueError(f"Ungültige Version für den Dateinamen: {version!r}")
    return f"{DISTRIBUTION_NAME}-{version}-windows-x64.zip"


def read_project_version(pyproject: Path) -> str:
    with pyproject.open("rb") as handle:
        return str(tomllib.load(handle)["project"]["version"])


# --------------------------------------------------------------------------------------------
# SPDX-Ausdrücke und Allowlist
# --------------------------------------------------------------------------------------------

_SPDX_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9.+:-]+)")


def _tokenize(expression: str) -> list[str]:
    tokens: list[str] = []
    position = 0
    text = expression.strip()
    while position < len(text):
        match = _SPDX_TOKEN.match(text, position)
        if match is None:
            raise ValueError(f"Ungültiger SPDX-Ausdruck: {expression!r}")
        tokens.append(match.group(1))
        position = match.end()
        while position < len(text) and text[position].isspace():
            position += 1
    if not tokens:
        raise ValueError("Leerer SPDX-Ausdruck")
    return tokens


class _SpdxEvaluator:
    """Rekursiver Abstieg: expr := and ("OR" and)*, and := atom ("AND" atom)*,
    atom := "(" expr ")" | ID ["WITH" ID]. Ergebnis: (erlaubt?, betroffene Lizenzen)."""

    def __init__(self, expression: str) -> None:
        self.expression = expression
        self.tokens = _tokenize(expression)
        self.index = 0

    def evaluate(self) -> tuple[bool, list[str]]:
        result = self._or()
        if self.index != len(self.tokens):
            raise ValueError(f"Ungültiger SPDX-Ausdruck: {self.expression!r}")
        return result

    def _peek(self) -> str | None:
        return self.tokens[self.index] if self.index < len(self.tokens) else None

    def _next(self) -> str:
        token = self._peek()
        if token is None:
            raise ValueError(f"Unvollständiger SPDX-Ausdruck: {self.expression!r}")
        self.index += 1
        return token

    def _or(self) -> tuple[bool, list[str]]:
        allowed, offending = self._and()
        while (self._peek() or "").upper() == "OR":
            self._next()
            right_allowed, right_offending = self._and()
            if allowed or right_allowed:
                allowed, offending = True, []
            else:
                offending = offending + right_offending
        return allowed, offending

    def _and(self) -> tuple[bool, list[str]]:
        allowed, offending = self._atom()
        while (self._peek() or "").upper() == "AND":
            self._next()
            right_allowed, right_offending = self._atom()
            allowed = allowed and right_allowed
            offending = offending + right_offending
        return allowed, offending

    def _atom(self) -> tuple[bool, list[str]]:
        token = self._next()
        # S105: Vergleich mit SPDX-Syntaxzeichen, kein Passwort.
        if token == "(":  # noqa: S105
            result = self._or()
            if self._next() != ")":
                raise ValueError(f"Klammer nicht geschlossen: {self.expression!r}")
            return result
        if token == ")" or token.upper() in {"AND", "OR", "WITH"}:  # noqa: S105
            raise ValueError(f"Ungültiger SPDX-Ausdruck: {self.expression!r}")
        if (self._peek() or "").upper() == "WITH":
            # Ausnahmen (z. B. "GPL-2.0-or-later WITH ...") stehen nicht auf der Allowlist.
            self._next()
            exception = self._next()
            return False, [f"{token} WITH {exception}"]
        if token.upper() in _ALLOWED_UPPER:
            return True, []
        return False, [token]


def evaluate_license_expression(expression: str) -> tuple[bool, list[str]]:
    """Prüft einen SPDX-Ausdruck gegen die Allowlist.

    ``OR`` ist erlaubt, sobald eine Alternative erlaubt ist (Wahlrecht des Empfängers);
    ``AND`` verlangt, dass alle Teile erlaubt sind. Liefert (erlaubt, nicht erlaubte Lizenzen).
    """
    return _SpdxEvaluator(expression).evaluate()


def is_copyleft(identifier: str) -> bool:
    return bool(_COPYLEFT_ID.match(identifier.strip()))


# --------------------------------------------------------------------------------------------
# Lizenz einer Distribution bestimmen
# --------------------------------------------------------------------------------------------


def _license_classifiers(meta: Mapping[str, str] | metadata.PackageMetadata) -> list[str]:
    classifiers = meta.get_all("Classifier") or []  # type: ignore[union-attr]
    return [c.strip() for c in classifiers if c.strip().startswith("License ::")]


def raw_license_summary(meta: metadata.PackageMetadata) -> str:
    """Rohangaben zur Lizenz in stabiler Form (für Fehlermeldungen und ``LicenseOverride``)."""
    parts = []
    expression = (meta.get("License-Expression") or "").strip()
    if expression:
        parts.append(f"License-Expression: {expression}")
    license_field = (meta.get("License") or "").strip()
    if license_field:
        first_line = license_field.splitlines()[0].strip()
        parts.append(f"License: {first_line}")
    parts.extend(f"Classifier: {c}" for c in _license_classifiers(meta))
    return "; ".join(parts) if parts else "keine Lizenzangaben"


def _expression_from_license_field(value: str) -> str | None:
    """``License`` enthält bei manchen Paketen einen SPDX-Ausdruck; Volltexte werden ignoriert."""
    value = value.strip()
    if not value or "\n" in value or len(value) > 100:
        return None
    try:
        evaluate_license_expression(value)
    except ValueError:
        return None
    tokens = [t for t in _tokenize(value) if t not in {"(", ")"}]
    known = all(t.upper() in {"AND", "OR", "WITH"} or t.upper() in _ALLOWED_UPPER for t in tokens)
    return value if known else None


def resolve_license(
    name: str,
    meta: metadata.PackageMetadata,
    overrides: Mapping[str, LicenseOverride] = LICENSE_OVERRIDES,
) -> tuple[str, str]:
    """Bestimmt den SPDX-Ausdruck einer Distribution: (Ausdruck, Quelle).

    Reihenfolge: ``License-Expression`` -> Zuordnungstabelle -> SPDX-Kennung im Feld ``License``
    -> eindeutiger Classifier. Alles andere ist unbekannt und führt zum Fehler.
    """
    expression = (meta.get("License-Expression") or "").strip()
    if expression:
        return expression, "License-Expression"

    raw = raw_license_summary(meta)
    override = overrides.get(canonicalize_name(name))
    if override is not None:
        if override.evidence != raw:
            raise LicenseCheckError(
                [
                    f"{name}: Lizenzangaben haben sich geändert ({raw!r}, erwartet "
                    f"{override.evidence!r}) - Zuordnung in LICENSE_OVERRIDES neu prüfen"
                ]
            )
        return override.expression, f"Zuordnungstabelle: {override.reason}"

    from_field = _expression_from_license_field(meta.get("License") or "")
    if from_field:
        return from_field, "License"

    classifiers = _license_classifiers(meta)
    if len(classifiers) == 1 and classifiers[0] in CLASSIFIER_TO_SPDX:
        return CLASSIFIER_TO_SPDX[classifiers[0]], "Classifier"

    hint = " (Copyleft-Hinweis in den Metadaten)" if _COPYLEFT_TEXT.search(raw) else ""
    raise LicenseCheckError(
        [
            f"{name}: Lizenz unbekannt{hint} - {raw}. Lizenzdatei prüfen und ggf. in "
            "LICENSE_OVERRIDES zuordnen (nur erlaubte Lizenzen, sonst ADR)."
        ]
    )


def check_license(
    dist: metadata.Distribution,
    overrides: Mapping[str, LicenseOverride] = LICENSE_OVERRIDES,
) -> LicenseDecision:
    """Prüft eine Distribution gegen die Allowlist; wirft ``LicenseCheckError`` bei Verstoß."""
    name = dist.metadata["Name"]
    expression, source = resolve_license(name, dist.metadata, overrides)
    try:
        allowed, offending = evaluate_license_expression(expression)
    except ValueError as exc:
        raise LicenseCheckError([f"{name}: {exc}"]) from exc
    if not allowed:
        copyleft = [o for o in offending if is_copyleft(o)]
        kind = "Copyleft-Lizenz nicht erlaubt" if copyleft else "Lizenz nicht auf der Allowlist"
        raise LicenseCheckError(
            [f"{name} {dist.version}: {kind}: {expression} (betroffen: {', '.join(offending)})"]
        )
    return LicenseDecision(name=name, version=dist.version, expression=expression, source=source)


def check_licenses(
    dists: Iterable[metadata.Distribution],
    overrides: Mapping[str, LicenseOverride] = LICENSE_OVERRIDES,
) -> list[LicenseDecision]:
    """Prüft alle Distributionen und sammelt sämtliche Verstöße in einem Fehler."""
    decisions: list[LicenseDecision] = []
    problems: list[str] = []
    for dist in dists:
        try:
            decisions.append(check_license(dist, overrides))
        except LicenseCheckError as exc:
            problems.extend(exc.problems)
    if problems:
        raise LicenseCheckError(problems)
    return decisions


# --------------------------------------------------------------------------------------------
# Laufzeit-Distributionen bestimmen
# --------------------------------------------------------------------------------------------


def runtime_distributions(
    root: str = DISTRIBUTION_NAME,
    find: Callable[[str], metadata.Distribution] = metadata.distribution,
) -> list[metadata.Distribution]:
    """Alle Distributionen, die ``root`` zur Laufzeit (ohne Extras wie ``dev``) benötigt.

    Marker werden für die aktuelle Plattform ausgewertet; ``root`` selbst ist nicht enthalten.
    """
    found: dict[str, metadata.Distribution] = {}
    processed_extras: dict[str, set[str]] = {}
    missing: list[str] = []
    queue: list[tuple[str, frozenset[str]]] = [(root, frozenset())]
    while queue:
        name, extras = queue.pop()
        key = canonicalize_name(name)
        done = processed_extras.setdefault(key, set())
        wanted = {""} | set(extras)
        if key in found and wanted <= done:
            continue
        try:
            dist = found.get(key) or find(name)
        except metadata.PackageNotFoundError:
            missing.append(name)
            continue
        found[key] = dist
        new_extras = wanted - done
        done.update(new_extras)
        for requirement_text in dist.requires or []:
            requirement = Requirement(requirement_text)
            if requirement.marker is not None and not any(
                requirement.marker.evaluate({"extra": extra}) for extra in new_extras
            ):
                continue
            queue.append((requirement.name, frozenset(requirement.extras)))
    if missing:
        raise BuildError(
            "Laufzeitabhängigkeiten nicht installiert: "
            + ", ".join(sorted(set(missing)))
            + " (uv sync --locked --all-extras ausführen)"
        )
    root_key = canonicalize_name(root)
    return sorted(
        (dist for key, dist in found.items() if key != root_key),
        key=lambda d: canonicalize_name(d.metadata["Name"]),
    )


# --------------------------------------------------------------------------------------------
# Inhalt des Pakets prüfen
# --------------------------------------------------------------------------------------------


def find_forbidden_binaries(root: Path) -> list[Path]:
    """Npcap-DLLs (``wpcap.dll``, ``Packet.dll``) irgendwo unterhalb von ``root``."""
    return sorted(
        path
        for path in root.rglob("*")
        if path.is_file() and path.name.lower() in FORBIDDEN_BINARIES
    )


def _is_pyinstaller_runtime_module(top_level: str) -> bool:
    return top_level.startswith(("pyimod", "pyi_", "_pyi_"))


def unexpected_bundled_modules(
    module_names: Iterable[str],
    allowed_distributions: Iterable[str],
    packages_to_distributions: Mapping[str, list[str]],
    first_party: Iterable[str] = ("network_sniffer",),
) -> dict[str, list[str]]:
    """Gebündelte Module, die weder aus der Standardbibliothek, PyInstaller, dem eigenen Paket
    noch aus einer geprüften Laufzeit-Distribution stammen. Ergebnis: Top-Level-Modul ->
    Distributionen (leer = Herkunft unbekannt)."""
    allowed = {canonicalize_name(name) for name in allowed_distributions}
    own = set(first_party)
    unexpected: dict[str, list[str]] = {}
    for module in module_names:
        # Erweiterungsmodule erscheinen als Pfad (z. B. ``markupsafe\_speedups.cp312-win_amd64``).
        top_level = re.split(r"[./\\]", module, maxsplit=1)[0]
        if (
            top_level in sys.stdlib_module_names
            or top_level in own
            or _is_pyinstaller_runtime_module(top_level)
        ):
            continue
        owners = packages_to_distributions.get(top_level, [])
        if not any(canonicalize_name(owner) in allowed for owner in owners):
            unexpected[top_level] = sorted(set(owners))
    return unexpected


# --------------------------------------------------------------------------------------------
# THIRD-PARTY-LICENSES.txt
# --------------------------------------------------------------------------------------------


def license_texts(dist: metadata.Distribution) -> list[tuple[str, str]]:
    """Lizenz-, NOTICE- und AUTHORS-Dateien aus den Metadaten einer Distribution.

    Berücksichtigt ``License-File`` (Metadata 2.4: ``.dist-info/licenses/``, älter: direkt in
    ``.dist-info``) und weitere Dateien mit passendem Namen im ``.dist-info``-Verzeichnis.
    """
    texts: dict[str, str] = {}
    for declared in dist.metadata.get_all("License-File") or []:
        for candidate in (f"licenses/{declared}", declared):
            content = dist.read_text(candidate)
            if content is not None:
                texts[declared] = content
                break
    for file in dist.files or []:
        parts = file.parts
        if not parts or not parts[0].endswith(".dist-info"):
            continue
        relative = "/".join(parts[1:])
        if relative.startswith("licenses/"):
            relative = relative.removeprefix("licenses/")
        if not file.name.upper().startswith(_LICENSE_FILE_PREFIXES) or relative in texts:
            continue
        content = dist.read_text("/".join(parts[1:]))
        if content is not None:
            texts[relative] = content
    return sorted(texts.items())


def find_python_license(base_prefix: Path | None = None) -> Path:
    """Lizenzdatei der laufenden CPython-Installation (Windows: ``LICENSE.txt`` im Präfix)."""
    prefix = Path(base_prefix or sys.base_prefix)
    version = f"python{sys.version_info.major}.{sys.version_info.minor}"
    for candidate in (prefix / "LICENSE.txt", prefix / "lib" / version / "LICENSE.txt"):
        if candidate.is_file():
            return candidate
    raise BuildError(f"Lizenzdatei der Python-Laufzeit nicht gefunden unter {prefix}")


def runtime_component_versions() -> dict[str, str]:
    """Versionen der nativen Bibliotheken der laufenden (und damit gebündelten) Python-Laufzeit."""
    import decimal
    import pyexpat
    import sqlite3
    import ssl
    import zlib

    return {
        "Python": sys.version.split()[0],
        "OpenSSL": ssl.OPENSSL_VERSION,
        "SQLite": sqlite3.sqlite_version,
        "zlib": zlib.ZLIB_RUNTIME_VERSION,
        "Expat": pyexpat.EXPAT_VERSION,
        "mpdecimal": getattr(decimal, "__libmpdec_version__", "unbekannt"),
    }


_RULE = "=" * 78


def _section(title: str, *body: str) -> list[str]:
    return ["", _RULE, title, _RULE, "", *body]


def render_third_party_licenses(
    version: str,
    decisions: list[LicenseDecision],
    texts: Mapping[str, list[tuple[str, str]]],
    python_license: str,
    runtime_components: str,
    component_versions: Mapping[str, str],
    pyinstaller_version: str,
    pyinstaller_license: str,
) -> str:
    """Erzeugt den Inhalt von ``THIRD-PARTY-LICENSES.txt``.

    ``texts`` bildet den Distributionsnamen auf (Dateiname, Inhalt) ab. Fehlt für eine
    Distribution der Lizenztext, schlägt der Build fehl (Copyright-Hinweis ist Pflicht).
    """
    missing = [d.name for d in decisions if not texts.get(d.name)]
    if missing:
        raise BuildError("Keine Lizenzdatei in den Metadaten gefunden für: " + ", ".join(missing))

    lines = [
        f"network-sniffer {version} - Lizenzen gebündelter Drittkomponenten",
        "",
        "network-sniffer selbst steht unter der MIT-Lizenz (Datei LICENSE).",
        "Dieses Paket enthält die unten aufgeführten Komponenten mit ihren Lizenztexten.",
        "Npcap ist NICHT enthalten; es wird vom Betreiber separat installiert und unterliegt der",
        "Npcap-Lizenz (https://npcap.com/oem/redist.html, https://github.com/nmap/npcap/blob/master/LICENSE).",
        "",
        "Übersicht",
        "---------",
    ]
    overview = [(f"{d.name} {d.version}", d.expression) for d in decisions]
    overview.append((f"Python-Laufzeit {component_versions.get('Python', '')}", "PSF-2.0 u. a."))
    overview.append(
        (
            f"PyInstaller {pyinstaller_version}",
            "GPL-2.0-or-later WITH Bootloader-exception, Apache-2.0",
        )
    )
    width = max(len(label) for label, _ in overview) + 2
    lines += [f"{label:<{width}}{expression}" for label, expression in overview]

    for decision in decisions:
        body = [f"Lizenz: {decision.expression} (Quelle: {decision.source})"]
        for file_name, content in texts[decision.name]:
            body += ["", f"--- {file_name} ---", "", content.rstrip()]
        lines += _section(f"{decision.name} {decision.version}", *body)

    versions = [f"  {name}: {value}" for name, value in component_versions.items()]
    lines += _section(
        "Python-Laufzeit (CPython)",
        "Gebündelte Versionen:",
        *versions,
        "",
        "--- LICENSE.txt der Python-Installation ---",
        "",
        python_license.rstrip(),
        "",
        runtime_components.rstrip(),
    )
    lines += _section(
        f"PyInstaller {pyinstaller_version} (Bootloader und Laufzeitmodule)",
        "Das EXE enthält den PyInstaller-Bootloader (GPL-2.0-or-later mit Bootloader-Ausnahme:",
        "die Weitergabe des gebündelten Programms unter beliebiger Lizenz ist erlaubt) sowie",
        "PyInstaller-Laufzeit-Hooks und -Module (Apache-2.0). Laufzeit-Hooks aus",
        "pyinstaller-hooks-contrib stehen unter GPL-2.0-or-later OR Apache-2.0",
        "(gewählt: Apache-2.0).",
        "",
        "--- COPYING.txt ---",
        "",
        pyinstaller_license.rstrip(),
    )
    document = "\n".join(lines) + "\n"
    if "Version 2.0, January 2004" not in document:
        raise BuildError("Vollständiger Text der Apache License 2.0 fehlt (OpenSSL, Apache-Pakete)")
    return document


# --------------------------------------------------------------------------------------------
# Zip und Prüfsumme
# --------------------------------------------------------------------------------------------


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_checksum_file(path: Path) -> Path:
    """Schreibt ``<datei>.sha256`` im Format von ``sha256sum`` (``<hex> *<name>``)."""
    checksum_path = path.with_name(path.name + ".sha256")
    checksum_path.write_text(f"{sha256_of(path)} *{path.name}\n", encoding="ascii", newline="\n")
    return checksum_path


def create_zip(app_dir: Path, zip_path: Path) -> None:
    """Packt ``app_dir`` als Ordner ``network-sniffer/`` in ``zip_path`` (sortierte Einträge)."""
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(p for p in app_dir.rglob("*") if p.is_file()):
            arcname = Path(APP_DIR_NAME) / path.relative_to(app_dir)
            archive.write(path, arcname.as_posix())


# --------------------------------------------------------------------------------------------
# Ablauf
# --------------------------------------------------------------------------------------------


def _print_decisions(decisions: list[LicenseDecision]) -> None:
    for decision in decisions:
        print(
            f"  ok  {decision.name} {decision.version}: {decision.expression} ({decision.source})"
        )


def run_license_check() -> list[LicenseDecision]:
    dists = runtime_distributions()
    decisions = check_licenses(dists)
    print(f"Lizenzprüfung: {len(decisions)} Laufzeit-Distributionen auf der Allowlist")
    _print_decisions(decisions)
    return decisions


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    # Feste Argumentliste ohne Shell; Pfade stammen aus dem Repository bzw. dem Build-Verzeichnis.
    return subprocess.run(command, check=False, capture_output=True, text=True)  # noqa: S603


def run_pyinstaller() -> Path:
    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--log-level=WARN",
        "--distpath",
        str(PYINSTALLER_DIST_DIR),
        "--workpath",
        str(BUILD_DIR / "work"),
        str(SPEC_FILE),
    ]
    print("PyInstaller:", " ".join(command))
    # Ausgabe direkt durchreichen (lange Laufzeit), feste Argumentliste ohne Shell.
    result = subprocess.run(command, check=False)  # noqa: S603
    if result.returncode != 0:
        raise BuildError(f"PyInstaller ist mit Exit-Code {result.returncode} fehlgeschlagen")
    app_dir = PYINSTALLER_DIST_DIR / APP_DIR_NAME
    if not (app_dir / EXE_NAME).is_file():
        raise BuildError(f"{EXE_NAME} fehlt in {app_dir}")
    return app_dir


def verify_bundle(app_dir: Path, decisions: list[LicenseDecision]) -> None:
    forbidden = find_forbidden_binaries(app_dir)
    if forbidden:
        raise BuildError(
            "Npcap-DLLs im Paket gefunden (nicht erlaubt): " + ", ".join(map(str, forbidden))
        )
    # PyInstaller setzt `workpath` der Spec auf <--workpath>/<Name der Spec>.
    manifest_path = BUILD_DIR / "work" / SPEC_FILE.stem / BUNDLE_MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for binary in manifest["binaries"]:
        if Path(binary).name.lower() in FORBIDDEN_BINARIES:
            raise BuildError(f"Npcap-DLL als Binärabhängigkeit eingesammelt: {binary}")
    unexpected = unexpected_bundled_modules(
        [*manifest["modules"], *manifest["extensions"]],
        [d.name for d in decisions],
        metadata.packages_distributions(),
    )
    if unexpected:
        details = ", ".join(
            f"{module} ({', '.join(owners) or 'Herkunft unbekannt'})"
            for module, owners in sorted(unexpected.items())
        )
        raise BuildError(
            "Module außerhalb der geprüften Laufzeitabhängigkeiten gebündelt: " + details
        )


def verify_exe_version(exe: Path, version: str) -> None:
    result = _run([str(exe), "--version"])
    output = result.stdout.strip()
    expected = f"{DISTRIBUTION_NAME} {version}"
    if result.returncode != 0 or output != expected:
        raise BuildError(
            f"{exe.name} --version lieferte {output!r} (Exit-Code {result.returncode}), "
            f"erwartet {expected!r}. stderr: {result.stderr.strip()}"
        )
    print(f"{exe.name} --version: {output}")


def write_package_documents(app_dir: Path, version: str, decisions: list[LicenseDecision]) -> None:
    shutil.copyfile(PROJECT_ROOT / "LICENSE", app_dir / "LICENSE")
    shutil.copyfile(PROJECT_ROOT / "README.md", app_dir / "README.md")
    pyinstaller = metadata.distribution("pyinstaller")
    pyinstaller_license = dict(license_texts(pyinstaller)).get("COPYING.txt")
    if pyinstaller_license is None:
        raise BuildError("COPYING.txt von PyInstaller nicht gefunden")
    document = render_third_party_licenses(
        version=version,
        decisions=decisions,
        texts={d.name: license_texts(metadata.distribution(d.name)) for d in decisions},
        python_license=find_python_license().read_text(encoding="utf-8"),
        runtime_components=RUNTIME_COMPONENTS_LICENSES.read_text(encoding="utf-8"),
        component_versions=runtime_component_versions(),
        pyinstaller_version=pyinstaller.version,
        pyinstaller_license=pyinstaller_license,
    )
    # CRLF, damit die Datei auch im klassischen Windows-Editor lesbar ist.
    (app_dir / THIRD_PARTY_FILE_NAME).write_text(document, encoding="utf-8", newline="\r\n")


def build() -> Path:
    if sys.platform != "win32":
        raise BuildError("Das Windows-Paket kann nur unter Windows gebaut werden")
    started = time.monotonic()
    version = read_project_version(PROJECT_ROOT / "pyproject.toml")
    installed = metadata.version(DISTRIBUTION_NAME)
    if installed != version:
        raise BuildError(
            f"Installierte Version {installed} weicht von pyproject.toml ({version}) ab - "
            "uv sync ausführen"
        )
    zip_path = OUTPUT_DIR / package_file_name(version)
    decisions = run_license_check()
    app_dir = run_pyinstaller()
    verify_bundle(app_dir, decisions)
    write_package_documents(app_dir, version, decisions)
    verify_exe_version(app_dir / EXE_NAME, version)
    create_zip(app_dir, zip_path)
    checksum_path = write_checksum_file(zip_path)
    size_mb = zip_path.stat().st_size / (1024 * 1024)
    print(f"Paket: {zip_path} ({size_mb:.1f} MiB)")
    print(f"Prüfsumme: {checksum_path.read_text(encoding='ascii').strip()}")
    print(f"Dauer: {time.monotonic() - started:.0f} s")
    return zip_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Windows-Paket von network-sniffer bauen")
    parser.add_argument(
        "--check-licenses",
        action="store_true",
        help="nur die Lizenzen der Laufzeitabhängigkeiten gegen die Allowlist prüfen",
    )
    args = parser.parse_args(argv)
    try:
        if args.check_licenses:
            run_license_check()
        else:
            build()
    except LicenseCheckError as exc:
        print("Lizenzprüfung fehlgeschlagen:", file=sys.stderr)
        for problem in exc.problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    except BuildError as exc:
        print(f"Build fehlgeschlagen: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
