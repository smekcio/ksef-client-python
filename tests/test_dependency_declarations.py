"""Spójność zależności: każdy import zewnętrzny musi być zadeklarowany.

`requirements.txt` nie zawierał `typing-extensions`, mimo że `documents/fa3`
importuje je bezwarunkowo (`from typing_extensions import Self`) — instalacja
zgodna z dokumentacją (`pip install -r requirements.txt`) kończyła się
`ModuleNotFoundError` już przy imporcie pakietu.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src"
REQUIREMENTS = REPO / "requirements.txt"
REQUIREMENTS_DEV = REPO / "requirements-dev.txt"
PYPROJECT = REPO / "pyproject.toml"

#: Nazwy dystrybucji != nazwy modułu.
DISTRIBUTION_ALIASES = {
    "pillow": "pil",
    "typing-extensions": "typing_extensions",
    "pytest-cov": "pytest_cov",
    "pytest-mock": "pytest_mock",
}


def _normalize(name: str) -> str:
    return DISTRIBUTION_ALIASES.get(name.lower(), name.lower().replace("-", "_"))


def _requirement_names(path: Path) -> set[str]:
    if not path.exists():
        return set()
    names: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-r", "--")):
            continue
        match = re.match(r"^([A-Za-z0-9._-]+)", line)
        if match:
            names.add(_normalize(match.group(1)))
    return names


def _declared_names(*, include_dev: bool) -> set[str]:
    """Nazwy z `requirements*.txt` oraz z `pyproject.toml`.

    `pyproject.toml` czytamy wyrażeniem regularnym, a nie `tomllib`, bo ten jest
    dostępny dopiero od Pythona 3.11, a pakiet wspiera 3.10.

    ``include_dev=False`` pomija `requirements-dev.txt`: zależność obecna tylko
    tam nie trafi do użytkownika, więc import w `src/` nie może się na niej opierać.
    """
    declared = _requirement_names(REQUIREMENTS)
    if include_dev:
        declared |= _requirement_names(REQUIREMENTS_DEV)
    pyproject = PYPROJECT.read_text(encoding="utf-8")
    for match in re.finditer(r'"([A-Za-z0-9._-]+)(?:\[[^\]]*\])?\s*(?:[<>=!~]|$)"?', pyproject):
        declared.add(_normalize(match.group(1)))
    return declared


def _imported_top_level_modules() -> set[str]:
    modules: set[str] = set()
    for path in SRC.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                modules.add(node.module.split(".")[0])
    return modules


def test_every_external_import_is_declared() -> None:
    stdlib = set(sys.stdlib_module_names)
    external = {
        _normalize(module)
        for module in _imported_top_level_modules()
        if module not in stdlib and module != "ksef_client" and not module.startswith("_")
    }
    declared = _declared_names(include_dev=False)

    missing = sorted(module for module in external if module not in declared)
    assert not missing, (
        "Importy zewnętrzne bez deklaracji w requirements.txt/pyproject.toml: "
        f"{missing}. Na czystym środowisku instalacja z dokumentacji skończy się "
        "ModuleNotFoundError."
    )


def test_typing_extensions_is_a_runtime_requirement() -> None:
    """Konkretna regresja: `documents/fa3` importuje `typing_extensions.Self`."""
    assert _normalize("typing-extensions") in _requirement_names(REQUIREMENTS)
    assert "typing_extensions" in {
        _normalize(module) for module in _imported_top_level_modules()
    }


def test_dev_only_dependency_is_not_enough_for_runtime_imports() -> None:
    """Zależność wyłącznie z `requirements-dev.txt` nie wystarcza dla `src/`.

    Test „całej klasy problemu” nie może przepuszczać importu runtime
    zadeklarowanego tylko w pliku dla deweloperów — użytkownik go nie instaluje.
    """
    runtime = _declared_names(include_dev=False)
    dev_only = _declared_names(include_dev=True) - runtime
    stdlib = set(sys.stdlib_module_names)
    imports = {
        _normalize(module)
        for module in _imported_top_level_modules()
        if module not in stdlib and module != "ksef_client" and not module.startswith("_")
    }

    assert not (imports & dev_only), (
        f"Importy runtime oparte wyłącznie na zależnościach deweloperskich: "
        f"{sorted(imports & dev_only)}"
    )


@pytest.mark.parametrize("path", [REQUIREMENTS, REQUIREMENTS_DEV])
def test_requirements_files_exist(path: Path) -> None:
    assert path.exists(), f"brak {path.name} w repozytorium"
