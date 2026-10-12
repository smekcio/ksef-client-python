"""Regresje pakowania: zależności importowane w runtime muszą być zadeklarowane.

Bug review v0.18.1: ``ksef_client.documents.fa3.domain`` i ``...builders``
importowały ``Self`` z ``typing_extensions`` na poziomie modułu, ale pakiet nie
deklarował tej zależności. Na Pythonie 3.13+ żadna z pozostałych zależności
(``httpx``/``cryptography``/``lxml``) jej nie dostarcza, więc czysty
``pip install ksef-client`` kończył się ``ModuleNotFoundError`` przy imporcie
publicznego API FA(3). CI tego nie widziało, bo ``requirements-dev.txt``
instaluje ``mypy``, który ciągnie ``typing_extensions``.
"""

from __future__ import annotations

import ast
import importlib
import re
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = REPO_ROOT / "src" / "ksef_client"
PYPROJECT_PATH = REPO_ROOT / "pyproject.toml"


def _load_toml_parser() -> Callable[[str], dict[str, Any]] | None:
    """Zwraca parser TOML dostępny w danym interpreterze (bez importu na sztywno).

    ``tomllib`` istnieje dopiero od 3.11, a projekt wspiera 3.10, więc import
    jest rozwiązywany w runtime — inaczej ``mypy`` (target py310) zgłasza brak
    modułu.
    """
    for module_name in ("tomllib", "tomli"):
        try:
            module = importlib.import_module(module_name)
        except ModuleNotFoundError:
            continue
        loads = getattr(module, "loads", None)
        if callable(loads):
            return loads
    return None


_TOML_LOADS = _load_toml_parser()

REQUIRES_TOML_PARSER = pytest.mark.skipif(
    _TOML_LOADS is None, reason="brak parsera TOML (tomllib/tomli)"
)

# Moduły, które importują `typing_extensions` w runtime (nie w TYPE_CHECKING).
RUNTIME_TYPING_EXTENSIONS_IMPORTERS = (
    "src/ksef_client/documents/fa3/domain.py",
    "src/ksef_client/documents/fa3/builders.py",
)

# Importy zdefiniowane w samym projekcie albo w stdlib.
FIRST_PARTY_ROOTS = {"ksef_client", "tests", "tools"}

# Zależności znane jako opcjonalne: wolno je importować tylko w `try/except ImportError`
# albo w funkcji (leniwy import), nie na poziomie modułu bez zabezpieczenia.
OPTIONAL_DEPENDENCIES = {
    "lxml",
    "xmlsec",
    "qrcode",
    "PIL",
    "typer",
    "rich",
    "keyring",
}

REQUIRES_TOML_PARSER = pytest.mark.skipif(
    _TOML_LOADS is None, reason="brak parsera TOML (tomllib/tomli)"
)


def _read_pyproject() -> str:
    return PYPROJECT_PATH.read_text(encoding="utf-8")


def _project() -> dict[str, Any]:
    assert _TOML_LOADS is not None
    return _TOML_LOADS(_read_pyproject())["project"]


def _all_requirement_specs() -> list[str]:
    project = _project()
    specs = list(project.get("dependencies", []))
    for extra_specs in project.get("optional-dependencies", {}).values():
        specs.extend(extra_specs)
    return specs


def _distribution_name(spec: str) -> str:
    requirement = spec.split(";", 1)[0]
    requirement = re.split(r"[<>=!~\[]", requirement, maxsplit=1)[0]
    return requirement.strip().lower().replace("_", "-")


def _declared_names() -> set[str]:
    return {_distribution_name(spec) for spec in _all_requirement_specs()}


def _typing_extensions_specs() -> list[str]:
    return [
        spec for spec in _all_requirement_specs() if _distribution_name(spec) == "typing-extensions"
    ]


def _module_level_third_party_imports(source: str, path: Path) -> set[str]:
    """Importy trzecich pakietów wykonywane przy imporcie modułu.

    Pomija importy wewnątrz funkcji/klas oraz te w ``try/except ImportError``
    (świadomie opcjonalne) i pod ``if TYPE_CHECKING``.
    """
    tree = ast.parse(source, filename=str(path))
    found: set[str] = set()

    def walk(node: ast.AST, *, in_function: bool, guarded: bool, type_checking: bool) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue  # importy wewnątrz funkcji są leniwe - to nie problem
            if isinstance(child, ast.Try):
                is_import_guard = any(
                    isinstance(handler.type, ast.Name) and handler.type.id == "ImportError"
                    for handler in child.handlers
                )
                for grand in child.body:
                    walk(
                        grand,
                        in_function=in_function,
                        guarded=guarded or is_import_guard,
                        type_checking=type_checking,
                    )
                continue
            if isinstance(child, ast.If):
                condition = child.test
                is_type_checking = (
                    isinstance(condition, ast.Name) and condition.id == "TYPE_CHECKING"
                )
                for grand in child.body:
                    walk(
                        grand,
                        in_function=in_function,
                        guarded=guarded,
                        type_checking=type_checking or is_type_checking,
                    )
                continue
            if isinstance(child, ast.Import):
                for alias in child.names:
                    found.add(alias.name.split(".")[0])
                continue
            if isinstance(child, ast.ImportFrom):
                if child.level and child.level > 0:
                    continue  # import względny
                if child.module:
                    found.add(child.module.split(".")[0])
                continue

    walk(tree, in_function=False, guarded=False, type_checking=False)
    return found


def _collect_module_level_imports() -> dict[str, set[str]]:
    imports: dict[str, set[str]] = {}
    for path in sorted(PACKAGE_ROOT.rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        names = _module_level_third_party_imports(source, path)
        filtered = {
            name
            for name in names
            if name not in FIRST_PARTY_ROOTS and name not in sys.stdlib_module_names
        }
        if filtered:
            imports[str(path.relative_to(REPO_ROOT))] = filtered
    return imports


def test_runtime_typing_extensions_importers_exist() -> None:
    """Test pilnuje realnych miejsc importu - jeśli znikną, ten plik można usunąć."""
    for relative in RUNTIME_TYPING_EXTENSIONS_IMPORTERS:
        source = (REPO_ROOT / relative).read_text(encoding="utf-8")
        import_lines = [
            line
            for line in source.splitlines()
            if line.startswith(("import ", "from ")) and "typing_extensions" in line
        ]
        assert import_lines, f"{relative} nie importuje już typing_extensions w runtime"


@REQUIRES_TOML_PARSER
def test_typing_extensions_is_a_declared_dependency() -> None:
    assert "typing-extensions" in _declared_names()


@REQUIRES_TOML_PARSER
def test_typing_extensions_dependency_covers_the_supported_python_range() -> None:
    """Zależność musi obowiązywać wszędzie, gdzie ``Self`` nie ma w ``typing``."""
    specs = _typing_extensions_specs()
    assert specs, "brak wpisu typing_extensions w pyproject.toml"
    marker = " ".join(specs)
    assert "python_version" in marker, specs
    assert "3.11" in marker, specs


@REQUIRES_TOML_PARSER
def test_every_module_level_third_party_import_is_declared() -> None:
    """Każdy pakiet importowany przy imporcie modułu musi być zadeklarowany.

    To jest ogólna regresja tej samej klasy błędu: nieudeklarowana zależność
    działa u autora (bo ma ją z innego pakietu), a u użytkownika kończy się
    ``ModuleNotFoundError``. Zależności opcjonalne (`OPTIONAL_DEPENDENCIES`) są
    dozwolone, ale muszą być importowane leniwie albo pod ``try/except ImportError``
    — ten test sprawdza tylko importy wykonywane bez zabezpieczenia.
    """
    declared = _declared_names()
    # Nazwa modułu != nazwa dystrybucji; mapujemy znane przypadki.
    module_to_distribution = {"pil": "pillow"}
    missing: dict[str, set[str]] = {}
    for relative, names in _collect_module_level_imports().items():
        undeclared: set[str] = set()
        for name in names:
            key = name.lower()
            if key in OPTIONAL_DEPENDENCIES:
                continue
            distribution = module_to_distribution.get(key, key.replace("_", "-"))
            if distribution not in declared:
                undeclared.add(name)
        if undeclared:
            missing[relative] = undeclared
    assert not missing, f"nieudeklarowane importy w runtime: {missing}"
