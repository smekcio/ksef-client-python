"""Polityka dystrybucji źródłowej: sdist nie niesie testów, których nie da się uruchomić.

``setuptools`` domyślnie dołącza do sdist pliki ``tests/test*.py``, ale bez
``conftest.py``, ``helpers.py``, katalogu ``tools/`` i specyfikacji takich testów
nie da się uruchomić po rozpakowaniu archiwum (kolekcja kończy się błędami
importu). Ten moduł pilnuje deklaracji z ``MANIFEST.in`` **oraz** kontroli
zawartości zbudowanego archiwum (``tools/check_cli_packaging.py``), którą CI
uruchamia na prawdziwym sdiscie.
"""

from __future__ import annotations

import io
import tarfile
from pathlib import Path

import pytest
from tools.check_cli_packaging import _check_sdist_contents

REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = REPO_ROOT / "MANIFEST.in"

PACKAGE_MODULES = (
    "src/ksef_client/__init__.py",
    "src/ksef_client/models.py",
)
SCHEMAS = (
    "schemat_FA(3)_v1-0E.xsd",
    "ElementarneTypyDanych_v10-0E.xsd",
    "KodyKrajow_v10-0E.xsd",
    "StrukturyDanych_v10-0E.xsd",
)


def _manifest_directives() -> list[str]:
    lines = MANIFEST_PATH.read_text(encoding="utf-8").splitlines()
    return [line.strip() for line in lines if line.strip() and not line.strip().startswith("#")]


def _write_archive(path: Path, names: tuple[str, ...]) -> Path:
    with tarfile.open(path, "w:gz") as archive:
        for name in names:
            payload = b"<x/>" if name.endswith(".xsd") else b""
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    return path


def _valid_sdist_names() -> tuple[str, ...]:
    return (
        "ksef_client-0.18.1/PKG-INFO",
        "ksef_client-0.18.1/pyproject.toml",
        *(f"ksef_client-0.18.1/{module}" for module in PACKAGE_MODULES),
        *(
            f"ksef_client-0.18.1/src/ksef_client/documents/fa3/schemas/{schema}"
            for schema in SCHEMAS
        ),
    )


def test_manifest_prunes_tests_from_the_sdist() -> None:
    assert MANIFEST_PATH.is_file(), (
        "brak MANIFEST.in — sdist wróci do wysyłania niedziałających testów"
    )

    assert "prune tests" in _manifest_directives()


def test_manifest_does_not_include_tests_back() -> None:
    directives = _manifest_directives()

    assert not [
        line
        for line in directives
        if line.endswith(("include tests", "recursive-include tests", "graft tests"))
    ]


def test_sdist_check_accepts_a_complete_archive(tmp_path: Path) -> None:
    _check_sdist_contents(_write_archive(tmp_path / "ok.tar.gz", _valid_sdist_names()))


def test_sdist_check_rejects_packaged_tests(tmp_path: Path) -> None:
    archive = _write_archive(
        tmp_path / "with-tests.tar.gz",
        (*_valid_sdist_names(), "ksef_client-0.18.1/tests/test_api.py"),
    )

    with pytest.raises(AssertionError, match="zawiera testy"):
        _check_sdist_contents(archive)


def test_sdist_check_rejects_missing_schema(tmp_path: Path) -> None:
    names = tuple(
        name for name in _valid_sdist_names() if not name.endswith("KodyKrajow_v10-0E.xsd")
    )
    archive = _write_archive(tmp_path / "no-xsd.tar.gz", names)

    with pytest.raises(AssertionError, match="bez plików XSD"):
        _check_sdist_contents(archive)


def test_sdist_check_rejects_schema_only_archive(tmp_path: Path) -> None:
    """Archiwum z XSD i katalogiem pakietu, ale bez modułów, musi zostać odrzucone.

    Poprzednia wersja kontroli sprawdzała tylko, czy istnieje ścieżka
    `src/ksef_client/...` — taki sdist przechodził (dowód z weryfikacji obalającej).
    """
    archive = _write_archive(
        tmp_path / "schema-only.tar.gz",
        (
            "ksef_client-0.18.1/src/ksef_client/documents/fa3/schemas/schemat_FA(3)_v1-0E.xsd",
            "ksef_client-0.18.1/src/ksef_client/documents/fa3/schemas/KodyKrajow_v10-0E.xsd",
            "ksef_client-0.18.1/src/ksef_client/documents/fa3/schemas/StrukturyDanych_v10-0E.xsd",
            "ksef_client-0.18.1/src/ksef_client/documents/fa3/schemas/ElementarneTypyDanych_v10-0E.xsd",
        ),
    )

    with pytest.raises(AssertionError, match="bez modułów pakietu"):
        _check_sdist_contents(archive)
