from __future__ import annotations

import importlib
from types import SimpleNamespace

import pytest

from ksef_client.cli import bootstrap
from ksef_client.cli.exit_codes import ExitCode


def test_bootstrap_reports_missing_optional_dependencies(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        bootstrap, "_missing_cli_dependencies", lambda: ["typer", "rich", "keyring"]
    )

    with pytest.raises(SystemExit) as exc:
        bootstrap.app_entrypoint()

    assert exc.value.code == int(ExitCode.CONFIG_ERROR)
    stderr = capsys.readouterr().err
    assert 'pip install "ksef-client[cli]"' in stderr
    assert "typer, rich, keyring" in stderr
    assert "ModuleNotFoundError" not in stderr


def test_bootstrap_delegates_to_cli_app_entrypoint(monkeypatch) -> None:
    called = {"value": False}

    def _fake_entrypoint() -> None:
        called["value"] = True

    monkeypatch.setattr(bootstrap, "_missing_cli_dependencies", lambda: [])
    monkeypatch.setattr(
        bootstrap,
        "_load_cli_app_module",
        lambda: SimpleNamespace(app_entrypoint=_fake_entrypoint, app=object()),
    )

    bootstrap.app_entrypoint()

    assert called["value"] is True


def test_get_app_returns_lazy_cli_app(monkeypatch) -> None:
    fake_app = object()
    monkeypatch.setattr(bootstrap, "_missing_cli_dependencies", lambda: [])
    monkeypatch.setattr(
        bootstrap,
        "_load_cli_app_module",
        lambda: SimpleNamespace(app_entrypoint=lambda: None, app=fake_app),
    )

    assert bootstrap.get_app() is fake_app


def test_get_app_raises_attribute_error_when_cli_dependencies_missing(monkeypatch) -> None:
    monkeypatch.setattr(bootstrap, "_missing_cli_dependencies", lambda: ["typer"])

    with pytest.raises(AttributeError) as exc:
        bootstrap.get_app()

    assert 'pip install "ksef-client[cli]"' in str(exc.value)


def test_missing_cli_dependencies_detects_missing_imports(monkeypatch) -> None:
    original_import_module = importlib.import_module

    def _fake_import_module(name: str):
        if name == "rich":
            raise ModuleNotFoundError(name)
        return original_import_module(name)

    monkeypatch.setattr(bootstrap.importlib, "import_module", _fake_import_module)

    missing = bootstrap._missing_cli_dependencies()

    assert missing == ["rich"]


def test_load_cli_app_module_imports_app_module() -> None:
    module = bootstrap._load_cli_app_module()

    assert module.__name__ == "ksef_client.cli.typer_app"
