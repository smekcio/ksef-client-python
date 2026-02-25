from __future__ import annotations

import importlib
import runpy
from pathlib import Path

from ksef_client import KsefClient
from ksef_client.cli.config import loader, paths, profiles
from ksef_client.cli.diagnostics.checks import run_preflight
from ksef_client.cli.diagnostics.report import DiagnosticReport
from ksef_client.cli.output import get_renderer
from ksef_client.cli.sdk.factory import create_client
from ksef_client.cli.types import Envelope, EnvelopeError, EnvelopeMeta

app_module = importlib.import_module("ksef_client.cli.app")


def test_app_version_text_fallback(monkeypatch) -> None:
    monkeypatch.setattr(
        app_module.metadata, "version", lambda name: (_ for _ in ()).throw(RuntimeError("x"))
    )
    assert app_module._version_text() == "0.0.0"


def test_app_entrypoint_calls_app(monkeypatch) -> None:
    called = {"value": False}

    def _fake_app() -> None:
        called["value"] = True

    monkeypatch.setattr(app_module, "app", _fake_app)
    app_module.app_entrypoint()
    assert called["value"] is True


def test_cli_main_module_invokes_entrypoint(monkeypatch) -> None:
    called = {"value": False}

    def _fake_entrypoint() -> None:
        called["value"] = True

    monkeypatch.setattr(app_module, "app_entrypoint", _fake_entrypoint)
    runpy.run_module("ksef_client.cli.__main__", run_name="__main__")
    assert called["value"] is True


def test_config_loader_and_profiles(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(paths, "config_file", lambda: tmp_path / "config.json")
    cfg = loader.load_config()
    loader.save_config(cfg)
    cfg2 = profiles.get_config()
    assert cfg.active_profile == cfg2.active_profile


def test_paths_use_env(monkeypatch, tmp_path: Path) -> None:
    appdata = tmp_path / "appdata"
    localappdata = tmp_path / "localappdata"
    monkeypatch.setenv("APPDATA", str(appdata))
    monkeypatch.setenv("LOCALAPPDATA", str(localappdata))

    assert paths.config_dir() == appdata / paths.APP_DIR_NAME
    assert paths.cache_dir() == localappdata / paths.APP_DIR_NAME
    assert paths.config_file() == appdata / paths.APP_DIR_NAME / "config.json"
    assert paths.cache_file() == localappdata / paths.APP_DIR_NAME / "cache.json"


def test_paths_fallback_to_home(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delenv("APPDATA", raising=False)
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    monkeypatch.setattr(paths.Path, "home", lambda: tmp_path)

    assert paths.config_dir() == tmp_path / ".config" / paths.APP_DIR_NAME
    assert paths.cache_dir() == tmp_path / ".cache" / paths.APP_DIR_NAME


def test_diagnostics_report_and_checks() -> None:
    preflight = run_preflight()
    report = DiagnosticReport(
        status="ok", checks=[{"name": "preflight", "status": preflight["status"]}]
    )
    assert report.status == "ok"
    assert report.checks[0]["status"] in {"PASS", "WARN"}


def test_renderer_selector() -> None:
    from ksef_client.cli.context import CliContext

    human = get_renderer(CliContext(profile="demo", json_output=False, verbose=0, no_color=True))
    json_renderer = get_renderer(
        CliContext(profile="demo", json_output=True, verbose=0, no_color=True)
    )
    assert human.__class__.__name__ == "HumanRenderer"
    assert json_renderer.__class__.__name__ == "JsonRenderer"


def test_factory_create_client() -> None:
    client = create_client("https://api-demo.ksef.mf.gov.pl")
    try:
        assert isinstance(client, KsefClient)
        assert client.lighthouse is not None
    finally:
        client.close()


def test_types_module_is_imported_and_shapes() -> None:
    meta: EnvelopeMeta = {"duration_ms": 1, "timestamp": "now"}
    err: EnvelopeError = {"code": "E", "message": "boom", "hint": "fix"}
    env: Envelope = {
        "ok": False,
        "command": "x",
        "profile": "demo",
        "data": None,
        "errors": [err],
        "meta": meta,
    }
    assert env["errors"][0]["code"] == "E"


def test_cli_package_exports() -> None:
    mod = importlib.import_module("ksef_client.cli")
    assert hasattr(mod, "app")
    assert hasattr(mod, "app_entrypoint")
