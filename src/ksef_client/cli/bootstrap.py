from __future__ import annotations

import importlib
import sys
from typing import Any

from .exit_codes import ExitCode

_OPTIONAL_CLI_DEPENDENCIES = ("typer", "rich", "keyring")
_CLI_INSTALL_HINT = 'Install CLI dependencies with: pip install "ksef-client[cli]"'


def _missing_cli_dependencies() -> list[str]:
    missing: list[str] = []
    for dependency in _OPTIONAL_CLI_DEPENDENCIES:
        try:
            importlib.import_module(dependency)
        except Exception:
            missing.append(dependency)
    return missing


def _format_missing_dependencies_message(missing: list[str]) -> str:
    dependencies = ", ".join(missing)
    return (
        "The optional dependencies required by the `ksef` CLI are not installed "
        f"({dependencies}). {_CLI_INSTALL_HINT}"
    )


def _exit_missing_cli_dependencies(missing: list[str]) -> None:
    sys.stderr.write(f"{_format_missing_dependencies_message(missing)}\n")
    raise SystemExit(int(ExitCode.CONFIG_ERROR))


def _load_cli_app_module() -> Any:
    return importlib.import_module("ksef_client.cli.typer_app")


def get_app() -> Any:
    missing = _missing_cli_dependencies()
    if missing:
        raise AttributeError(_format_missing_dependencies_message(missing))
    return _load_cli_app_module().app


def app_entrypoint() -> None:
    missing = _missing_cli_dependencies()
    if missing:
        _exit_missing_cli_dependencies(missing)
    _load_cli_app_module().app_entrypoint()
