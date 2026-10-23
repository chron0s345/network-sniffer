"""Tests der plattformunabhängigen Hilfsfunktionen aus ``packaging/build_windows.py`` (KAN-46).

Das Skript ist kein Paket (``packaging/`` würde sonst die PyPI-Bibliothek ``packaging`` verdecken)
und wird deshalb über seinen Pfad geladen. Distributionen werden als echte ``.dist-info``-
Verzeichnisse in ``tmp_path`` erzeugt (``importlib.metadata.PathDistribution``).
"""

import hashlib
import importlib.util
import sys
import zipfile
from collections.abc import Callable
from importlib.metadata import Distribution, PackageNotFoundError, PathDistribution
from pathlib import Path
from types import ModuleType

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = PROJECT_ROOT / "packaging" / "build_windows.py"
APACHE_MARKER = "Apache License\n                           Version 2.0, January 2004\n"


def _load_build_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("build_windows", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["build_windows"] = module
    spec.loader.exec_module(module)
    return module


bw = _load_build_module()

MakeDist = Callable[..., Distribution]


@pytest.fixture
def make_dist(tmp_path: Path) -> MakeDist:
    """Erzeugt eine installierte Distribution mit den angegebenen Metadaten-Feldern."""

    def factory(
        name: str,
        version: str = "1.0",
        *,
        license_expression: str | None = None,
        license_field: str | None = None,
        classifiers: tuple[str, ...] = (),
        requires: tuple[str, ...] = (),
        license_files: dict[str, str] | None = None,
        legacy_license_files: dict[str, str] | None = None,
        extra_files: dict[str, str] | None = None,
        declare_license_files: bool = True,
    ) -> Distribution:
        dist_info = tmp_path / "site" / f"{name.replace('-', '_')}-{version}.dist-info"
        (dist_info / "licenses").mkdir(parents=True)
        lines = ["Metadata-Version: 2.4", f"Name: {name}", f"Version: {version}"]
        if license_expression:
            lines.append(f"License-Expression: {license_expression}")
        if license_field:
            lines.append(f"License: {license_field}")
        lines += [f"Classifier: {c}" for c in classifiers]
        lines += [f"Requires-Dist: {r}" for r in requires]
        record = []
        for file_name, content in (license_files or {}).items():
            (dist_info / "licenses" / file_name).write_text(content, encoding="utf-8")
            record.append(f"{dist_info.name}/licenses/{file_name},,")
            if declare_license_files:
                lines.append(f"License-File: {file_name}")
        for file_name, content in (legacy_license_files or {}).items():
            (dist_info / file_name).write_text(content, encoding="utf-8")
            record.append(f"{dist_info.name}/{file_name},,")
            if declare_license_files:
                lines.append(f"License-File: {file_name}")
        for file_name, content in (extra_files or {}).items():
            (dist_info / file_name).write_text(content, encoding="utf-8")
            record.append(f"{dist_info.name}/{file_name},,")
        (dist_info / "METADATA").write_text("\n".join(lines) + "\n", encoding="utf-8")
        record.append(f"{dist_info.name}/METADATA,,")
        (dist_info / "RECORD").write_text("\n".join(record) + "\n", encoding="utf-8")
        return PathDistribution(dist_info)

    return factory


# ----------------------------------------------------------------------------------------------
# AC3: Dateiname mit Version
# ----------------------------------------------------------------------------------------------


def test_ac3_package_file_name_contains_version() -> None:
    assert bw.package_file_name("1.2.3") == "network-sniffer-1.2.3-windows-x64.zip"


@pytest.mark.parametrize("version", ["", "../1.0", "1.0/evil", "1.0 beta", "v1.0", "1.0\\x"])
def test_ac3_package_file_name_rejects_unsafe_versions(version: str) -> None:
    with pytest.raises(ValueError, match="Ungültige Version"):
        bw.package_file_name(version)


def test_ac3_read_project_version_from_pyproject(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[project]\nname = "x"\nversion = "2.5.0"\n', encoding="utf-8")

    assert bw.read_project_version(pyproject) == "2.5.0"


def test_ac3_project_version_matches_repository_pyproject() -> None:
    version = bw.read_project_version(PROJECT_ROOT / "pyproject.toml")

    assert bw.package_file_name(version).startswith(f"network-sniffer-{version}-")


# ----------------------------------------------------------------------------------------------
# Lizenz-Allowlist: SPDX-Ausdrücke
# ----------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "expression",
    [
        "MIT",
        "mit",
        "Apache-2.0",
        "Apache-2.0 AND CNRI-Python",
        "(MIT OR Apache-2.0) AND BSD-3-Clause",
        "MIT OR GPL-2.0-only",
        "PSF-2.0",
        "0BSD",
        "Unlicense",
        "MPL-2.0",
        "ISC",
        "MIT-0",
        "BSD-2-Clause",
    ],
)
def test_allowlist_accepts_permissive_expressions(expression: str) -> None:
    assert bw.evaluate_license_expression(expression) == (True, [])


@pytest.mark.parametrize(
    ("expression", "offending"),
    [
        ("GPL-3.0-only", ["GPL-3.0-only"]),
        ("LGPL-2.1-or-later", ["LGPL-2.1-or-later"]),
        ("AGPL-3.0-only", ["AGPL-3.0-only"]),
        ("MIT AND GPL-2.0-only", ["GPL-2.0-only"]),
        (
            "GPL-2.0-or-later WITH Bootloader-exception",
            ["GPL-2.0-or-later WITH Bootloader-exception"],
        ),
        ("LicenseRef-Proprietary", ["LicenseRef-Proprietary"]),
        ("GPL-2.0-only OR LGPL-3.0-only", ["GPL-2.0-only", "LGPL-3.0-only"]),
    ],
)
def test_allowlist_rejects_copyleft_and_unknown_expressions(
    expression: str, offending: list[str]
) -> None:
    assert bw.evaluate_license_expression(expression) == (False, offending)


@pytest.mark.parametrize(
    "expression", ["", "MIT AND", "(MIT", "MIT )", "AND MIT", "MIT WITH", "MIT;"]
)
def test_allowlist_rejects_malformed_expressions(expression: str) -> None:
    with pytest.raises(ValueError):
        bw.evaluate_license_expression(expression)


@pytest.mark.parametrize(
    ("identifier", "expected"),
    [("GPL-2.0-only", True), ("LGPL-3.0", True), ("AGPL-3.0", True), ("MIT", False)],
)
def test_is_copyleft(identifier: str, expected: bool) -> None:
    assert bw.is_copyleft(identifier) is expected


# ----------------------------------------------------------------------------------------------
# Lizenz-Allowlist: Distributionen
# ----------------------------------------------------------------------------------------------


def test_allowlist_gpl_distribution_fails(make_dist: MakeDist) -> None:
    dist = make_dist("copyleft-lib", license_expression="GPL-3.0-or-later")

    with pytest.raises(bw.LicenseCheckError) as excinfo:
        bw.check_license(dist)

    (problem,) = excinfo.value.problems
    assert "copyleft-lib 1.0" in problem
    assert "Copyleft-Lizenz nicht erlaubt" in problem


def test_allowlist_lgpl_classifier_without_expression_fails(make_dist: MakeDist) -> None:
    dist = make_dist(
        "lesser-lib",
        classifiers=("License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)",),
    )

    with pytest.raises(bw.LicenseCheckError, match="Copyleft-Hinweis"):
        bw.check_license(dist)


def test_allowlist_apache_distribution_passes(make_dist: MakeDist) -> None:
    dist = make_dist("apache-lib", "2.0.1", license_expression="Apache-2.0")

    decision = bw.check_license(dist)

    assert decision == bw.LicenseDecision(
        name="apache-lib", version="2.0.1", expression="Apache-2.0", source="License-Expression"
    )


def test_allowlist_missing_metadata_without_mapping_fails(make_dist: MakeDist) -> None:
    dist = make_dist("mystery-lib")

    with pytest.raises(bw.LicenseCheckError, match="mystery-lib: Lizenz unbekannt"):
        bw.check_license(dist)


def test_allowlist_ambiguous_classifier_without_mapping_fails(make_dist: MakeDist) -> None:
    dist = make_dist("bsd-lib", classifiers=("License :: OSI Approved :: BSD License",))

    with pytest.raises(bw.LicenseCheckError, match="LICENSE_OVERRIDES"):
        bw.check_license(dist)


def test_allowlist_unambiguous_classifier_passes(make_dist: MakeDist) -> None:
    dist = make_dist("mit-lib", classifiers=("License :: OSI Approved :: MIT License",))

    assert bw.check_license(dist).expression == "MIT"


def test_allowlist_spdx_in_license_field_passes(make_dist: MakeDist) -> None:
    dist = make_dist("field-lib", license_field="BSD-3-Clause")

    decision = bw.check_license(dist)

    assert (decision.expression, decision.source) == ("BSD-3-Clause", "License")


def test_allowlist_full_text_in_license_field_is_unknown(make_dist: MakeDist) -> None:
    dist = make_dist("text-lib", license_field="Copyright (c) someone, all rights reserved")

    with pytest.raises(bw.LicenseCheckError, match="Lizenz unbekannt"):
        bw.check_license(dist)


def test_allowlist_mapping_resolves_unclear_metadata(make_dist: MakeDist) -> None:
    dist = make_dist("bsd-lib", classifiers=("License :: OSI Approved :: BSD License",))
    overrides = {
        "bsd-lib": bw.LicenseOverride(
            expression="BSD-3-Clause",
            evidence="Classifier: License :: OSI Approved :: BSD License",
            reason="LICENSE geprüft",
        )
    }

    decision = bw.check_license(dist, overrides)

    assert decision.expression == "BSD-3-Clause"
    assert decision.source == "Zuordnungstabelle: LICENSE geprüft"


def test_allowlist_mapping_fails_when_metadata_changed(make_dist: MakeDist) -> None:
    dist = make_dist(
        "bsd-lib", classifiers=("License :: OSI Approved :: GNU General Public License (GPL)",)
    )
    overrides = {
        "bsd-lib": bw.LicenseOverride(
            expression="BSD-3-Clause",
            evidence="Classifier: License :: OSI Approved :: BSD License",
            reason="LICENSE geprüft",
        )
    }

    with pytest.raises(bw.LicenseCheckError, match="Lizenzangaben haben sich geändert"):
        bw.check_license(dist, overrides)


def test_allowlist_mapping_to_forbidden_license_still_fails(make_dist: MakeDist) -> None:
    dist = make_dist("odd-lib", license_field="see LICENSE file for the terms and conditions")
    overrides = {
        "odd-lib": bw.LicenseOverride(
            expression="LGPL-2.1-only",
            evidence="License: see LICENSE file for the terms and conditions",
            reason="LGPL",
        )
    }

    with pytest.raises(bw.LicenseCheckError, match="Copyleft"):
        bw.check_license(dist, overrides)


def test_allowlist_mapping_table_entries_are_allowed_and_documented() -> None:
    for name, override in bw.LICENSE_OVERRIDES.items():
        assert bw.evaluate_license_expression(override.expression)[0], name
        assert override.reason.strip(), name
        assert override.evidence.strip(), name


def test_allowlist_check_licenses_reports_all_problems(make_dist: MakeDist) -> None:
    dists = [
        make_dist("good-lib", license_expression="MIT"),
        make_dist("gpl-lib", license_expression="GPL-2.0-only"),
        make_dist("unknown-lib"),
    ]

    with pytest.raises(bw.LicenseCheckError) as excinfo:
        bw.check_licenses(dists)

    problems = excinfo.value.problems
    assert len(problems) == 2
    assert any("gpl-lib" in p for p in problems)
    assert any("unknown-lib" in p for p in problems)


def test_allowlist_installed_runtime_dependencies_pass() -> None:
    """Frühe Prüfung in jeder CI (auch ubuntu): echte Laufzeitabhängigkeiten aus dem uv.lock."""
    dists = bw.runtime_distributions()

    decisions = bw.check_licenses(dists)

    names = {d.name.lower() for d in decisions}
    assert {"fastapi", "uvicorn", "sqlalchemy", "alembic"} <= names
    assert "network-sniffer" not in names
    assert not names & {"pytest", "ruff", "pyinstaller", "httpx", "coverage"}


# ----------------------------------------------------------------------------------------------
# Laufzeit-Distributionen
# ----------------------------------------------------------------------------------------------


def test_runtime_distributions_follow_requirements_extras_and_markers(make_dist: MakeDist) -> None:
    dists = {
        "app": make_dist(
            "app",
            requires=(
                "lib-a>=1",
                "lib-b[speed]",
                'dev-tool; extra == "dev"',
                'other-os-lib; sys_platform == "no-such-platform"',
            ),
        ),
        "lib-a": make_dist("lib-a", requires=("lib-c",)),
        "lib-b": make_dist(
            "lib-b", requires=('lib-fast; extra == "speed"', 'lib-slow; extra == "slow"')
        ),
        "lib-c": make_dist("lib-c"),
        "lib-fast": make_dist("lib-fast"),
    }

    def find(name: str) -> Distribution:
        try:
            return dists[name]
        except KeyError:
            raise PackageNotFoundError(name) from None

    result = bw.runtime_distributions("app", find)

    assert [d.metadata["Name"] for d in result] == ["lib-a", "lib-b", "lib-c", "lib-fast"]


def test_runtime_distributions_missing_dependency_fails(make_dist: MakeDist) -> None:
    app = make_dist("app", requires=("not-installed",))

    def find(name: str) -> Distribution:
        if name == "app":
            return app
        raise PackageNotFoundError(name)

    with pytest.raises(bw.BuildError, match="not-installed"):
        bw.runtime_distributions("app", find)


# ----------------------------------------------------------------------------------------------
# Paketinhalt: keine Npcap-DLLs, nur geprüfte Module
# ----------------------------------------------------------------------------------------------


def test_npcap_dlls_in_bundle_are_detected(tmp_path: Path) -> None:
    (tmp_path / "_internal" / "sub").mkdir(parents=True)
    (tmp_path / "_internal" / "sub" / "wpcap.dll").write_bytes(b"x")
    (tmp_path / "_internal" / "Packet.DLL").write_bytes(b"x")
    (tmp_path / "_internal" / "libffi-8.dll").write_bytes(b"x")

    found = bw.find_forbidden_binaries(tmp_path)

    assert sorted(p.name for p in found) == ["Packet.DLL", "wpcap.dll"]


def test_bundle_without_npcap_dlls_is_clean(tmp_path: Path) -> None:
    (tmp_path / "_internal").mkdir()
    (tmp_path / "_internal" / "python312.dll").write_bytes(b"x")
    (tmp_path / "wpcap.dll.txt").write_text("kein DLL", encoding="utf-8")

    assert bw.find_forbidden_binaries(tmp_path) == []


def test_unexpected_bundled_modules_are_reported() -> None:
    modules = [
        "json.decoder",
        "network_sniffer.main",
        "pyimod02_importers",
        "_pyi_rth_utils",
        "fastapi.routing",
        "markupsafe\\_speedups.cp312-win_amd64.pyd",
        "pygments.lexer",
        "mystery",
    ]
    owners = {"fastapi": ["fastapi"], "markupsafe": ["MarkupSafe"], "pygments": ["Pygments"]}

    unexpected = bw.unexpected_bundled_modules(modules, ["fastapi", "markupsafe"], owners)

    assert unexpected == {"pygments": ["Pygments"], "mystery": []}


# ----------------------------------------------------------------------------------------------
# THIRD-PARTY-LICENSES.txt
# ----------------------------------------------------------------------------------------------


def test_license_texts_collects_declared_legacy_and_notice_files(make_dist: MakeDist) -> None:
    dist = make_dist(
        "apache-lib",
        license_expression="Apache-2.0",
        license_files={"LICENSE": "Apache text"},
        legacy_license_files={"COPYING.txt": "legacy text"},
        extra_files={"NOTICE": "notice text", "entry_points.txt": "[x]"},
    )

    texts = bw.license_texts(dist)

    assert texts == [
        ("COPYING.txt", "legacy text"),
        ("LICENSE", "Apache text"),
        ("NOTICE", "notice text"),
    ]


def test_license_texts_finds_undeclared_files_in_licenses_dir(make_dist: MakeDist) -> None:
    dist = make_dist(
        "old-lib", license_files={"LICENSE.md": "md text"}, declare_license_files=False
    )

    assert bw.license_texts(dist) == [("LICENSE.md", "md text")]


def _render(**overrides: object) -> str:
    decision = bw.LicenseDecision("apache-lib", "2.0", "Apache-2.0", "License-Expression")
    arguments: dict[str, object] = {
        "version": "1.2.3",
        "decisions": [decision],
        "texts": {"apache-lib": [("LICENSE", APACHE_MARKER + "full apache text")]},
        "python_license": "PSF LICENSE AGREEMENT",
        "runtime_components": "OpenSSL ... libffi ... SQLite",
        "component_versions": {"Python": "3.12.15", "OpenSSL": "OpenSSL 3.5"},
        "pyinstaller_version": "6.22.3",
        "pyinstaller_license": "Bootloader Exception",
    }
    arguments.update(overrides)
    return bw.render_third_party_licenses(**arguments)


def test_third_party_licenses_contain_all_components() -> None:
    document = _render()

    assert document.startswith("network-sniffer 1.2.3 - Lizenzen gebündelter Drittkomponenten")
    assert "apache-lib 2.0" in document
    assert "Lizenz: Apache-2.0 (Quelle: License-Expression)" in document
    assert "full apache text" in document
    assert "PSF LICENSE AGREEMENT" in document
    assert "OpenSSL ... libffi ... SQLite" in document
    assert "OpenSSL: OpenSSL 3.5" in document
    assert "PyInstaller 6.22.3" in document
    assert "Bootloader Exception" in document
    assert "Npcap ist NICHT enthalten" in document


def test_third_party_licenses_require_license_text_per_distribution() -> None:
    with pytest.raises(bw.BuildError, match="apache-lib"):
        _render(texts={"apache-lib": []})


def test_third_party_licenses_require_full_apache_text() -> None:
    with pytest.raises(bw.BuildError, match="Apache License 2.0"):
        _render(texts={"apache-lib": [("LICENSE", "only a short note")]})


def test_repository_runtime_components_file_covers_cpython_libraries() -> None:
    text = bw.RUNTIME_COMPONENTS_LICENSES.read_text(encoding="utf-8")

    for component in ("OpenSSL", "libffi", "SQLite", "zlib", "bzip2", "liblzma", "mpdecimal"):
        assert component in text


def test_find_python_license_in_windows_layout(tmp_path: Path) -> None:
    (tmp_path / "LICENSE.txt").write_text("PSF", encoding="utf-8")

    assert bw.find_python_license(tmp_path) == tmp_path / "LICENSE.txt"


def test_find_python_license_missing_fails(tmp_path: Path) -> None:
    with pytest.raises(bw.BuildError, match="Python-Laufzeit"):
        bw.find_python_license(tmp_path)


def test_runtime_component_versions_report_bundled_libraries() -> None:
    versions = bw.runtime_component_versions()

    assert set(versions) == {"Python", "OpenSSL", "SQLite", "zlib", "Expat", "mpdecimal"}
    assert all(versions.values())


# ----------------------------------------------------------------------------------------------
# Zip und Prüfsumme
# ----------------------------------------------------------------------------------------------


def test_checksum_file_uses_sha256sum_format(tmp_path: Path) -> None:
    package = tmp_path / "network-sniffer-1.2.3-windows-x64.zip"
    package.write_bytes(b"paketinhalt")

    checksum_path = bw.write_checksum_file(package)

    assert checksum_path.name == "network-sniffer-1.2.3-windows-x64.zip.sha256"
    expected = hashlib.sha256(b"paketinhalt").hexdigest()
    assert checksum_path.read_bytes() == f"{expected} *{package.name}\n".encode("ascii")


def test_zip_contains_app_folder_with_documents(tmp_path: Path) -> None:
    app_dir = tmp_path / "app"
    (app_dir / "_internal").mkdir(parents=True)
    for name in ("network-sniffer.exe", "LICENSE", "README.md", "THIRD-PARTY-LICENSES.txt"):
        (app_dir / name).write_text(name, encoding="utf-8")
    (app_dir / "_internal" / "python312.dll").write_text("dll", encoding="utf-8")
    zip_path = tmp_path / "out" / "paket.zip"

    bw.create_zip(app_dir, zip_path)

    with zipfile.ZipFile(zip_path) as archive:
        assert sorted(archive.namelist()) == [
            "network-sniffer/LICENSE",
            "network-sniffer/README.md",
            "network-sniffer/THIRD-PARTY-LICENSES.txt",
            "network-sniffer/_internal/python312.dll",
            "network-sniffer/network-sniffer.exe",
        ]


# ----------------------------------------------------------------------------------------------
# Kommandozeile
# ----------------------------------------------------------------------------------------------


def test_cli_check_licenses_succeeds_for_allowed_dependencies(
    monkeypatch: pytest.MonkeyPatch, make_dist: MakeDist, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        bw, "runtime_distributions", lambda: [make_dist("good-lib", license_expression="MIT")]
    )

    assert bw.main(["--check-licenses"]) == 0

    assert "ok  good-lib 1.0: MIT" in capsys.readouterr().out


def test_cli_check_licenses_fails_for_gpl_dependency(
    monkeypatch: pytest.MonkeyPatch, make_dist: MakeDist, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        bw,
        "runtime_distributions",
        lambda: [make_dist("gpl-lib", license_expression="GPL-3.0-only")],
    )

    assert bw.main(["--check-licenses"]) == 1

    err = capsys.readouterr().err
    assert "Lizenzprüfung fehlgeschlagen" in err
    assert "gpl-lib" in err


def test_cli_build_refuses_non_windows(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(bw.sys, "platform", "linux")

    assert bw.main([]) == 1

    assert "nur unter Windows" in capsys.readouterr().err
