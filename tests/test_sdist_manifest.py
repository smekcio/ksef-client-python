"""Polityka dystrybucji źródłowej: sdist nie niesie testów, których nie da się uruchomić.

``setuptools`` domyślnie dołącza do sdist pliki ``tests/test*.py``, ale bez
``conftest.py``, ``helpers.py``, katalogu ``tools/`` i specyfikacji takich testów
nie da się uruchomić po rozpakowaniu archiwum (kolekcja kończy się błędami
importu). Ten test pilnuje samej deklaracji z ``MANIFEST.in``; skutek — zawartość
zbudowanego archiwum — sprawdza ``tools/check_cli_packaging.py``, który w CI
buduje wheel i sdist w świeżym venv.
"""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = REPO_ROOT / "MANIFEST.in"


def _manifest_directives() -> list[str]:
    lines = MANIFEST_PATH.read_text(encoding="utf-8").splitlines()
    return [line.strip() for line in lines if line.strip() and not line.strip().startswith("#")]


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
